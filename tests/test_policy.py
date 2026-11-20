from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tobira.lab import DEFAULT_CONFIG_DIR
from tobira.policy import PolicyEngine, PolicyError, Subject
from tobira.posture import DeviceState

TUESDAY_1400_JST = dt.datetime(2026, 11, 24, 5, 0, tzinfo=dt.timezone.utc)
TUESDAY_0300_JST = dt.datetime(2026, 11, 24, 18, 0, tzinfo=dt.timezone.utc)
SUNDAY_1400_JST = dt.datetime(2026, 11, 22, 5, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine.from_files(
        DEFAULT_CONFIG_DIR / "apps.yaml", DEFAULT_CONFIG_DIR / "policy.yaml"
    )


def subject(
    username: str, groups: list[str], *, mfa: bool = True, state: DeviceState | None = None
) -> Subject:
    device = state or DeviceState("device-x", os_patch_age_days=1)
    return Subject(username, groups, mfa, device.device_id, device.attributes())


def test_finance_reaches_payroll_in_hours(engine: PolicyEngine) -> None:
    decision = engine.decide(
        subject("aiko", ["employees", "finance"]), "payroll", now=TUESDAY_1400_JST
    )
    assert decision.allowed
    assert decision.rule == "finance-payroll"


def test_payroll_is_closed_at_night(engine: PolicyEngine) -> None:
    decision = engine.decide(
        subject("aiko", ["employees", "finance"]), "payroll", now=TUESDAY_0300_JST
    )
    assert not decision.allowed
    assert decision.reason == "outside_time_window"


def test_payroll_is_closed_at_weekends(engine: PolicyEngine) -> None:
    decision = engine.decide(
        subject("aiko", ["employees", "finance"]), "payroll", now=SUNDAY_1400_JST
    )
    assert decision.reason == "outside_time_window"


def test_default_deny_for_unmatched_subject(engine: PolicyEngine) -> None:
    decision = engine.decide(subject("ben", ["employees"]), "payroll", now=TUESDAY_1400_JST)
    assert not decision.allowed
    assert decision.reason == "no_matching_rule"


def test_unknown_app_looks_identical_to_a_denial(engine: PolicyEngine) -> None:
    known = engine.decide(subject("ben", ["employees"]), "payroll", now=TUESDAY_1400_JST)
    unknown = engine.decide(subject("ben", ["employees"]), "hr-portal", now=TUESDAY_1400_JST)
    assert known.reason == unknown.reason == "no_matching_rule"


def test_mfa_is_required_for_payroll(engine: PolicyEngine) -> None:
    decision = engine.decide(
        subject("aiko", ["employees", "finance"], mfa=False), "payroll", now=TUESDAY_1400_JST
    )
    assert decision.reason == "mfa_required"


def test_posture_gate_on_critical_app(engine: PolicyEngine) -> None:
    weak = DeviceState("workstation-chen", os_patch_age_days=1, secure_boot=False)
    decision = engine.decide(
        subject("chen", ["employees", "ot-engineers"], state=weak),
        "factory-hmi",
        now=TUESDAY_1400_JST,
    )
    assert decision.reason == "posture_failed"
    assert "secure_boot" in decision.posture_failures


def test_explicit_deny_overrides_allow(engine: PolicyEngine) -> None:
    decision = engine.decide(
        subject("dinesh", ["employees", "contractors", "ot-engineers"]),
        "factory-hmi",
        now=TUESDAY_1400_JST,
    )
    assert not decision.allowed
    assert decision.reason == "explicit_deny"


def test_visible_apps_hide_what_cannot_be_reached(engine: PolicyEngine) -> None:
    ben = engine.visible_apps(subject("ben", ["employees"]), now=TUESDAY_1400_JST)
    assert "payroll" not in ben
    assert "factory-hmi" not in ben
    assert "wiki" in ben


def test_patch_age_changes_the_answer(engine: PolicyEngine) -> None:
    stale = DeviceState("laptop-ben", os_patch_age_days=200)
    decision = engine.decide(
        subject("ben", ["employees"], state=stale), "wiki", now=TUESDAY_1400_JST
    )
    assert decision.reason == "posture_failed"


def test_policy_must_be_default_deny(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("version: 1\ndefault: allow\nrules: []\n")
    with pytest.raises(PolicyError, match="default-deny"):
        PolicyEngine.from_files(DEFAULT_CONFIG_DIR / "apps.yaml", bad)


def test_rule_referencing_unknown_app_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text(
        "version: 1\ndefault: deny\nrules:\n"
        "  - name: oops\n    users: {groups: [employees]}\n    apps: [nonexistent]\n"
    )
    with pytest.raises(PolicyError, match="unknown app"):
        PolicyEngine.from_files(DEFAULT_CONFIG_DIR / "apps.yaml", bad)
