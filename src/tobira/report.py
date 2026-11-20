"""Renders the attack-suite outcome and the SIEM findings as Markdown."""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .attacks import AttackResult
from .siem import Alert

GROUP_TITLES = {
    "exposure": "Attack surface",
    "identity": "Identity and credentials",
    "device": "Device posture",
    "policy": "Authorisation policy",
    "continuous": "Continuous evaluation",
}


def build_report(
    results: list[AttackResult],
    alerts: list[Alert],
    events: list[dict[str, Any]],
) -> str:
    blocked = sum(1 for r in results if r.blocked)
    total = len(results)
    lines: list[str] = []

    lines += [
        "# Tobira - zero trust access lab: control verification report",
        "",
        f"Generated {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Result",
        "",
        f"- **{blocked}/{total} adversary scenarios blocked**",
        f"- **{len(events)} audit events** written in Elastic Common Schema",
        f"- **{len(alerts)} detections fired** from {len({a.rule_id for a in alerts})} "
        "distinct rules",
        "",
    ]

    if blocked != total:
        failed = [r.name for r in results if not r.blocked]
        lines += ["> **Not all controls held.** Failing scenarios: " + ", ".join(failed), ""]

    lines += ["## Scenarios", ""]
    for group, title in GROUP_TITLES.items():
        subset = [r for r in results if r.group == group]
        if not subset:
            continue
        passed = sum(1 for r in subset if r.blocked)
        lines += [f"### {title} ({passed}/{len(subset)} blocked)", ""]
        lines += ["| Scenario | Attacker goal | Technique | Outcome | Evidence |"]
        lines += ["|---|---|---|---|---|"]
        for r in subset:
            mark = "Blocked" if r.blocked else "**NOT BLOCKED**"
            lines.append(
                f"| `{r.name}` | {r.goal} | {r.technique} | {mark} | {r.evidence} |"
            )
        lines.append("")

    lines += ["## Why each control holds", ""]
    for r in results:
        if r.detail:
            lines += [f"**{r.name}** — {r.detail}", ""]

    lines += ["## Detections", ""]
    if alerts:
        lines += ["| Rule | Severity | Title | Entity | Events |", "|---|---|---|---|---|"]
        for alert in alerts:
            lines.append(
                f"| {alert.rule_id} | {alert.severity} | {alert.title} | "
                f"`{alert.entity or '-'}` | {alert.count} |"
            )
        lines.append("")
    else:
        lines += ["No detections fired.", ""]

    counts = Counter(doc["event"]["action"] for doc in events)
    lines += ["## Audit stream", "", "| Event action | Count |", "|---|---|"]
    for action, count in counts.most_common():
        lines.append(f"| `{action}` | {count} |")
    lines.append("")

    lines += [
        "## Notes",
        "",
        "- Every scenario runs against the live broker in `tobira attack`; nothing "
        "in this table is asserted without being executed.",
        "- `out_of_hours_access_is_denied` is evaluated against the policy engine "
        "with a fixed clock rather than by waiting for 03:00 JST.",
        "- Detection rule identifiers match `siem/wazuh/rules/tobira_rules.xml`, so "
        "a finding here and a finding in a real Wazuh deployment mean the same thing.",
        "",
    ]
    return "\n".join(lines)


def console_summary(results: Iterable[AttackResult], alerts: Iterable[Alert]) -> str:
    results = list(results)
    alerts = list(alerts)
    blocked = sum(1 for r in results if r.blocked)
    bar = "=" * 64
    out = [bar, f" {blocked}/{len(results)} adversary scenarios blocked", bar]
    for alert in alerts:
        out.append(f"  detection  {alert.summary()}")
    return "\n".join(out)
