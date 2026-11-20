"""Default-deny policy engine.

Policy is evaluated **per connection**, not once per login. Every time a user's
client asks to reach an application, the broker re-checks identity, group
membership, device posture, MFA and the allowed time window. There is no
implicit network membership to inherit: if no rule matches, the answer is deny.

The engine also decides *visibility*. A user is only told about the application
segments they could actually reach, which removes the enumeration step an
attacker normally performs after landing on a flat VPN subnet.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from .posture import PostureProfile, PostureResult, evaluate

_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


class PolicyError(Exception):
    """Raised when a policy document cannot be loaded."""


@dataclass(slots=True)
class AppSegment:
    """A private application reachable through exactly one App Connector."""

    name: str
    host: str
    port: int
    connector: str
    sensitivity: str = "normal"
    description: str = ""

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> AppSegment:
        try:
            return cls(
                name=doc["name"],
                host=doc["host"],
                port=int(doc["port"]),
                connector=doc["connector"],
                sensitivity=doc.get("sensitivity", "normal"),
                description=doc.get("description", ""),
            )
        except KeyError as exc:
            raise PolicyError(f"app segment missing field {exc}") from exc


@dataclass(slots=True)
class TimeWindow:
    days: set[int] = field(default_factory=lambda: set(range(7)))
    start: dt.time = dt.time(0, 0)
    end: dt.time = dt.time(23, 59, 59)
    tz: str = "UTC"

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> TimeWindow:
        days = {_DAYS[d.lower()[:3]] for d in doc.get("days", list(_DAYS))}
        return cls(
            days=days,
            start=dt.time.fromisoformat(doc.get("from", "00:00")),
            end=dt.time.fromisoformat(doc.get("to", "23:59:59")),
            tz=doc.get("tz", "UTC"),
        )

    def contains(self, moment: dt.datetime) -> bool:
        local = moment.astimezone(ZoneInfo(self.tz))
        if local.weekday() not in self.days:
            return False
        return self.start <= local.time() <= self.end


@dataclass(slots=True)
class Rule:
    name: str
    apps: list[str]
    groups: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    posture: str = ""
    mfa_required: bool = False
    time_window: TimeWindow | None = None
    action: str = "allow"

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> Rule:
        subjects = doc.get("users", {})
        if isinstance(subjects, list):  # shorthand: users: [alice, bob]
            subjects = {"names": subjects}
        window = doc.get("time_window")
        return cls(
            name=doc.get("name", "unnamed"),
            apps=list(doc.get("apps", [])),
            groups=list(subjects.get("groups", [])),
            users=list(subjects.get("names", [])),
            posture=doc.get("posture", ""),
            mfa_required=bool(doc.get("mfa_required", False)),
            time_window=TimeWindow.from_dict(window) if window else None,
            action=doc.get("action", "allow"),
        )

    def matches_subject(self, username: str, groups: Iterable[str]) -> bool:
        if self.users and username in self.users:
            return True
        return bool(self.groups and set(groups) & set(self.groups))

    def matches_app(self, app: str) -> bool:
        return "*" in self.apps or app in self.apps


@dataclass(slots=True)
class Decision:
    allowed: bool
    reason: str
    rule: str = ""
    posture_score: int = 0
    posture_failures: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        return "success" if self.allowed else "failure"


@dataclass(slots=True)
class Subject:
    """Everything known about the requester at decision time."""

    username: str
    groups: list[str]
    mfa: bool
    device_id: str
    posture_attributes: dict[str, Any]


class PolicyEngine:
    def __init__(
        self,
        apps: dict[str, AppSegment],
        rules: list[Rule],
        profiles: dict[str, PostureProfile],
    ) -> None:
        self.apps = apps
        self.rules = rules
        self.profiles = profiles

    # ------------------------------------------------------------------ load

    @classmethod
    def from_files(cls, apps_path: str | Path, policy_path: str | Path) -> PolicyEngine:
        apps_doc = yaml.safe_load(Path(apps_path).read_text()) or {}
        apps = {}
        for entry in apps_doc.get("apps", []):
            segment = AppSegment.from_dict(entry)
            apps[segment.name] = segment

        policy_doc = yaml.safe_load(Path(policy_path).read_text()) or {}
        if policy_doc.get("default", "deny") != "deny":
            raise PolicyError("Tobira only supports default-deny policy")

        profiles = {
            name: PostureProfile.from_dict(name, doc)
            for name, doc in (policy_doc.get("posture_profiles") or {}).items()
        }
        rules = [Rule.from_dict(entry) for entry in policy_doc.get("rules", [])]

        for rule in rules:
            if rule.posture and rule.posture not in profiles:
                raise PolicyError(f"rule {rule.name!r} references unknown posture profile")
            for app in rule.apps:
                if app != "*" and app not in apps:
                    raise PolicyError(f"rule {rule.name!r} references unknown app {app!r}")

        return cls(apps, rules, profiles)

    # -------------------------------------------------------------- decisions

    def evaluate_posture(self, rule: Rule, attributes: dict[str, Any]) -> PostureResult:
        if not rule.posture:
            return PostureResult(passed=True, score=0)
        return evaluate(attributes, self.profiles[rule.posture])

    def decide(
        self, subject: Subject, app_name: str, *, now: dt.datetime | None = None
    ) -> Decision:
        """Authorise one connection attempt. Default is deny."""
        moment = now or dt.datetime.now(dt.timezone.utc)

        if app_name not in self.apps:
            # Deliberately the same shape of answer as "not allowed": an
            # attacker must not be able to tell a real app from a typo.
            return Decision(False, "no_matching_rule")

        candidates = [
            rule
            for rule in self.rules
            if rule.matches_app(app_name) and rule.matches_subject(subject.username, subject.groups)
        ]
        if not candidates:
            return Decision(False, "no_matching_rule")

        # An explicit deny anywhere in the policy wins over any allow.
        for rule in candidates:
            if rule.action == "deny":
                return Decision(False, "explicit_deny", rule=rule.name)

        last: Decision | None = None
        for rule in candidates:
            if rule.mfa_required and not subject.mfa:
                last = Decision(False, "mfa_required", rule=rule.name)
                continue
            if rule.time_window and not rule.time_window.contains(moment):
                last = Decision(False, "outside_time_window", rule=rule.name)
                continue
            result = self.evaluate_posture(rule, subject.posture_attributes)
            if not result.passed:
                last = Decision(
                    False,
                    "posture_failed",
                    rule=rule.name,
                    posture_score=result.score,
                    posture_failures=list(result.failures),
                )
                continue
            return Decision(True, "allowed", rule=rule.name, posture_score=result.score)

        return last or Decision(False, "no_matching_rule")

    def visible_apps(self, subject: Subject, *, now: dt.datetime | None = None) -> list[str]:
        """Apps this subject may currently reach.

        The client is only ever told about these, so there is nothing to
        enumerate.
        """
        return sorted(
            name for name in self.apps if self.decide(subject, name, now=now).allowed
        )
