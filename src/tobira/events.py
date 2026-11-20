"""SIEM-ready audit events in Elastic Common Schema (ECS).

Every authentication, authorisation and session event is written as one JSON
object per line in ECS 8.x field names, so the same stream can be tailed by
Wazuh, shipped by Filebeat into Elastic, or ingested by Splunk without a custom
parser. Product-specific detail lives under the ``tobira.*`` namespace, which is
where ECS expects vendor fields.

The emitter is deliberately synchronous and append-only: an access decision is
not considered made until it has been recorded.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ECS_VERSION = "8.11.0"


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


@dataclass(slots=True)
class Event:
    action: str
    outcome: str  # success | failure | unknown
    category: list[str] = field(default_factory=lambda: ["network"])
    type: list[str] = field(default_factory=lambda: ["info"])
    severity: int = 3
    reason: str = ""
    user: str = ""
    groups: list[str] = field(default_factory=list)
    device_id: str = ""
    source_ip: str = ""
    source_port: int = 0
    app: str = ""
    app_host: str = ""
    app_port: int = 0
    connector: str = ""
    session_id: str = ""
    stream_id: int = 0
    policy_rule: str = ""
    posture_score: int | None = None
    posture_failures: list[str] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_received: int = 0
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_ecs(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "@timestamp": _utcnow(),
            "ecs": {"version": ECS_VERSION},
            "event": {
                "kind": "event",
                "module": "tobira",
                "dataset": "tobira.access",
                "category": self.category,
                "type": self.type,
                "action": self.action,
                "outcome": self.outcome,
                "severity": self.severity,
            },
            "observer": {"vendor": "Tobira", "product": "zero-trust-broker", "type": "proxy"},
            "message": self.message or f"{self.action} ({self.outcome})",
            "tobira": {},
        }
        if self.reason:
            doc["event"]["reason"] = self.reason
        if self.user:
            doc["user"] = {"name": self.user}
            if self.groups:
                doc["user"]["roles"] = self.groups
        if self.source_ip:
            doc["source"] = {"ip": self.source_ip, "port": self.source_port}
        if self.app_host:
            doc["destination"] = {"address": self.app_host, "port": self.app_port}
        if self.bytes_sent or self.bytes_received:
            doc["network"] = {
                "bytes": self.bytes_sent + self.bytes_received,
                "forwarded_ip": self.app_host,
            }

        tobira: dict[str, Any] = doc["tobira"]
        for key, value in (
            ("app", self.app),
            ("connector", self.connector),
            ("session_id", self.session_id),
            ("policy_rule", self.policy_rule),
            ("device_id", self.device_id),
        ):
            if value:
                tobira[key] = value
        if self.stream_id:
            tobira["stream_id"] = self.stream_id
        if self.posture_score is not None:
            tobira["posture_score"] = self.posture_score
        if self.posture_failures:
            tobira["posture_failures"] = self.posture_failures
        if self.bytes_sent or self.bytes_received:
            tobira["bytes_sent"] = self.bytes_sent
            tobira["bytes_received"] = self.bytes_received
        tobira.update(self.extra)
        if not tobira:
            doc.pop("tobira")
        return doc


class EventEmitter:
    """Writes ECS JSON lines and fans out to in-process subscribers."""

    def __init__(self, path: str | Path | None = None, *, echo: bool = False) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[dict[str, Any]], None]] = []
        self._buffer: list[dict[str, Any]] = []
        self._echo = echo

    def subscribe(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._subscribers.append(callback)

    def emit(self, event: Event) -> dict[str, Any]:
        doc = event.to_ecs()
        line = json.dumps(doc, separators=(",", ":"))
        with self._lock:
            self._buffer.append(doc)
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            if self._echo:
                print(f"[audit] {doc['event']['action']:<24} {doc['event']['outcome']:<8} "
                      f"{doc.get('user', {}).get('name', '-'):<10} "
                      f"{doc.get('tobira', {}).get('app', '-'):<14} "
                      f"{doc['event'].get('reason', '')}", flush=True)
        for callback in list(self._subscribers):
            callback(doc)
        return doc

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()


# ----------------------------------------------------------------- shortcuts

def auth_event(**kwargs: Any) -> Event:
    kwargs.setdefault("category", ["authentication"])
    kwargs.setdefault("type", ["start"])
    return Event(**kwargs)


def access_event(**kwargs: Any) -> Event:
    kwargs.setdefault("category", ["network", "session"])
    kwargs.setdefault("type", ["allowed"] if kwargs.get("outcome") == "success" else ["denied"])
    return Event(**kwargs)
