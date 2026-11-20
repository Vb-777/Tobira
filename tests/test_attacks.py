"""The adversary scenarios, run as tests.

``test_every_scenario_is_blocked`` is the one that matters: if a control
regresses, this fails and names the scenario.
"""

from __future__ import annotations

import pytest

from tobira.attacks import SCENARIOS, run_all
from tobira.lab import Lab
from tobira.siem import DetectionEngine


@pytest.fixture(scope="module")
def anyio_backend() -> str:
    return "asyncio"


async def test_every_scenario_is_blocked(lab: Lab) -> None:
    engine = DetectionEngine()
    lab.emitter.subscribe(engine.consume)

    results = await run_all(lab, verbose=False)

    failed = [r.name for r in results if not r.blocked]
    assert not failed, f"controls did not hold for: {failed}"
    assert len(results) == len(SCENARIOS)


async def test_attacks_are_visible_to_the_siem(lab: Lab) -> None:
    engine = DetectionEngine()
    lab.emitter.subscribe(engine.consume)
    await run_all(lab, verbose=False)

    fired = {alert.rule_id for alert in engine.alerts}
    # The scenarios must light up the high-signal rules, not just be blocked.
    for rule_id in ("TOB-001", "TOB-002", "TOB-003", "TOB-005", "TOB-006", "TOB-008"):
        assert rule_id in fired, f"{rule_id} did not fire"


async def test_scenarios_cover_every_control_group(lab: Lab) -> None:
    results = await run_all(lab, verbose=False)
    groups = {r.group for r in results}
    assert groups == {"exposure", "identity", "device", "policy", "continuous"}
