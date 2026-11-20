"""A small Sigma-style detection engine for the Tobira audit stream.

Shipping logs is not a security control on its own - somebody has to be told
when something matters. These rules are written against ECS field paths, so the
same logic can be re-expressed in Wazuh, Elastic or Splunk; the drop-in Wazuh
decoder and ruleset under ``siem/wazuh/`` are generated from the same ideas.

Two rule shapes cover everything we need:

``match``
    fire on a single event (for example, a token replayed from another device -
    one occurrence is already an incident);

``threshold``
    fire when N events sharing a key arrive inside a sliding window (for
    example, one user being denied four different applications in a minute,
    which is application enumeration).
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RULES_DIR = Path(__file__).parent / "rules"

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def dotted(doc: dict[str, Any], path: str) -> Any:
    """Look up ``a.b.c`` inside a nested dict."""
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _matches(doc: dict[str, Any], selection: dict[str, Any]) -> bool:
    for path, expected in selection.items():
        actual = dotted(doc, path)
        if isinstance(expected, list):
            if isinstance(actual, list):
                if not set(map(str, actual)) & set(map(str, expected)):
                    return False
            elif actual is None or str(actual) not in {str(e) for e in expected}:
                return False
        elif isinstance(expected, dict) and "contains" in expected:
            if actual is None or str(expected["contains"]) not in str(actual):
                return False
        elif isinstance(actual, list):
            if str(expected) not in {str(a) for a in actual}:
                return False
        elif str(actual) != str(expected):
            return False
    return True


@dataclass(slots=True)
class DetectionRule:
    id: str
    title: str
    severity: str
    selection: dict[str, Any]
    type: str = "match"
    description: str = ""
    group_by: list[str] = field(default_factory=list)
    distinct: str = ""
    threshold: int = 1
    window_seconds: int = 60
    mitre: list[str] = field(default_factory=list)
    response: str = ""

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> DetectionRule:
        return cls(
            id=doc["id"],
            title=doc["title"],
            severity=doc.get("severity", "medium"),
            selection=dict(doc.get("selection", {})),
            type=doc.get("type", "match"),
            description=doc.get("description", ""),
            group_by=list(doc.get("group_by", [])),
            distinct=doc.get("distinct", ""),
            threshold=int(doc.get("threshold", 1)),
            window_seconds=int(doc.get("window_seconds", 60)),
            mitre=list(doc.get("mitre", [])),
            response=doc.get("response", ""),
        )


@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    timestamp: str
    entity: str
    count: int
    evidence: list[dict[str, Any]] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    response: str = ""

    def summary(self) -> str:
        who = f" [{self.entity}]" if self.entity else ""
        return f"{self.severity.upper():<13} {self.rule_id}  {self.title}{who}"


def load_rules(directory: str | Path = RULES_DIR) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    for path in sorted(Path(directory).glob("*.yml")):
        doc = yaml.safe_load(path.read_text()) or {}
        for entry in doc.get("rules", []):
            rules.append(DetectionRule.from_dict(entry))
    return rules


def _parse_ts(value: Any) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return dt.datetime.now(dt.timezone.utc)


class DetectionEngine:
    """Stateful evaluator; safe to feed events one at a time as they happen."""

    def __init__(self, rules: Iterable[DetectionRule] | None = None) -> None:
        self.rules = list(rules) if rules is not None else load_rules()
        self._windows: dict[tuple[str, str], deque[tuple[dt.datetime, dict[str, Any]]]] = (
            defaultdict(deque)
        )
        self._fired: set[tuple[str, str]] = set()
        self.alerts: list[Alert] = []

    # ------------------------------------------------------------ evaluation

    def consume(self, doc: dict[str, Any]) -> list[Alert]:
        produced: list[Alert] = []
        when = _parse_ts(doc.get("@timestamp"))

        for rule in self.rules:
            if not _matches(doc, rule.selection):
                continue

            if rule.type == "match":
                produced.append(
                    Alert(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        timestamp=str(doc.get("@timestamp", "")),
                        entity=self._entity(doc, rule),
                        count=1,
                        evidence=[doc],
                        mitre=rule.mitre,
                        response=rule.response,
                    )
                )
                continue

            key = (rule.id, self._entity(doc, rule))
            window = self._windows[key]
            window.append((when, doc))
            cutoff = when - dt.timedelta(seconds=rule.window_seconds)
            while window and window[0][0] < cutoff:
                window.popleft()

            if rule.distinct:
                values = {str(dotted(d, rule.distinct)) for _, d in window}
                reached = len(values) >= rule.threshold
            else:
                reached = len(window) >= rule.threshold

            if reached and key not in self._fired:
                self._fired.add(key)
                produced.append(
                    Alert(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        timestamp=str(doc.get("@timestamp", "")),
                        entity=key[1],
                        count=len(window),
                        evidence=[d for _, d in window],
                        mitre=rule.mitre,
                        response=rule.response,
                    )
                )

        self.alerts.extend(produced)
        return produced

    def run(self, docs: Iterable[dict[str, Any]]) -> list[Alert]:
        for doc in docs:
            self.consume(doc)
        return self.alerts

    @staticmethod
    def _entity(doc: dict[str, Any], rule: DetectionRule) -> str:
        if not rule.group_by:
            return str(dotted(doc, "user.name") or dotted(doc, "tobira.device_id") or "")
        return "|".join(str(dotted(doc, path) or "-") for path in rule.group_by)

    # --------------------------------------------------------------- reports

    def by_severity(self) -> dict[str, list[Alert]]:
        buckets: dict[str, list[Alert]] = defaultdict(list)
        for alert in self.alerts:
            buckets[alert.severity].append(alert)
        return dict(
            sorted(buckets.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        )

    def report(self) -> str:
        if not self.alerts:
            return "No detections fired."
        lines = [f"{len(self.alerts)} detection(s) fired:", ""]
        for severity, alerts in self.by_severity().items():
            for alert in alerts:
                lines.append(f"  {alert.summary()}")
            _ = severity
        return "\n".join(lines)
