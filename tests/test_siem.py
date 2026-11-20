from __future__ import annotations

import datetime as dt

from tobira.events import Event, EventEmitter, access_event
from tobira.siem import DetectionEngine, load_rules


def _ecs(action: str, *, user: str = "ben", app: str = "", reason: str = "", at: str = "") -> dict:
    doc = access_event(
        action=action,
        outcome="failure",
        user=user,
        app=app,
        reason=reason,
    ).to_ecs()
    if at:
        doc["@timestamp"] = at
    return doc


def test_rules_load_and_are_well_formed() -> None:
    rules = load_rules()
    assert len(rules) >= 10
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in rules:
        assert rule.selection, f"{rule.id} has no selection"
        assert rule.severity in {"informational", "low", "medium", "high", "critical"}


def test_token_replay_fires_on_a_single_event() -> None:
    engine = DetectionEngine()
    alerts = engine.consume(
        _ecs("authentication_failed", user="aiko", reason="token_device_mismatch")
    )
    assert [a.rule_id for a in alerts] == ["TOB-001"]
    assert alerts[0].severity == "critical"


def test_enumeration_needs_distinct_apps() -> None:
    engine = DetectionEngine()
    base = dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc)

    # Same app five times is noisy, but it is not enumeration.
    for i in range(5):
        stamp = (base + dt.timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        engine.consume(_ecs("access_denied", app="payroll", reason="no_matching_rule", at=stamp))
    assert "TOB-003" not in {a.rule_id for a in engine.alerts}

    engine2 = DetectionEngine()
    for i, app in enumerate(["payroll", "factory-hmi", "vpn-admin"]):
        stamp = (base + dt.timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        engine2.consume(_ecs("access_denied", app=app, reason="no_matching_rule", at=stamp))
    assert "TOB-003" in {a.rule_id for a in engine2.alerts}


def test_threshold_rule_respects_its_window() -> None:
    engine = DetectionEngine()
    base = dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc)
    for i, app in enumerate(["a", "b", "c"]):
        # ten minutes apart - outside the 120 second window
        stamp = (base + dt.timedelta(minutes=10 * i)).isoformat().replace("+00:00", "Z")
        engine.consume(_ecs("access_denied", app=app, reason="no_matching_rule", at=stamp))
    assert "TOB-003" not in {a.rule_id for a in engine.alerts}


def test_threshold_rule_fires_once_per_entity() -> None:
    engine = DetectionEngine()
    base = dt.datetime(2026, 11, 20, 12, 0, tzinfo=dt.timezone.utc)
    for i in range(10):
        stamp = (base + dt.timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        engine.consume(_ecs("access_denied", app=f"app{i}", reason="no_matching_rule", at=stamp))
    assert sum(1 for a in engine.alerts if a.rule_id == "TOB-003") == 1


def test_posture_reasons_match_the_prefix_rule() -> None:
    engine = DetectionEngine()
    for reason in ("posture_bad_signature", "posture_nonce_mismatch", "posture_stale"):
        engine.consume(_ecs("authentication_failed", reason=reason))
    assert sum(1 for a in engine.alerts if a.rule_id == "TOB-005") == 3


def test_benign_traffic_produces_no_alerts() -> None:
    engine = DetectionEngine()
    for _ in range(20):
        engine.consume(
            access_event(
                action="access_granted", outcome="success", user="aiko", app="wiki"
            ).to_ecs()
        )
    assert [a for a in engine.alerts if a.severity != "informational"] == []


def test_emitter_fans_out_live(tmp_path) -> None:
    emitter = EventEmitter(tmp_path / "audit.json")
    engine = DetectionEngine()
    emitter.subscribe(engine.consume)
    emitter.emit(
        Event(
            action="authentication_failed",
            outcome="failure",
            reason="token_device_mismatch",
            user="aiko",
        )
    )
    assert any(a.rule_id == "TOB-001" for a in engine.alerts)
    assert (tmp_path / "audit.json").read_text().count("\n") == 1


def test_ecs_document_shape() -> None:
    doc = access_event(
        action="access_granted",
        outcome="success",
        user="aiko",
        groups=["finance"],
        app="payroll",
        app_host="10.0.0.5",
        app_port=8080,
        posture_score=100,
    ).to_ecs()
    assert doc["event"]["module"] == "tobira"
    assert doc["event"]["dataset"] == "tobira.access"
    assert doc["user"]["roles"] == ["finance"]
    assert doc["destination"] == {"address": "10.0.0.5", "port": 8080}
    assert doc["tobira"]["posture_score"] == 100
