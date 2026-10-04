"""Tamper-evident, privacy-preserving audit events for secure agents.

The audit layer deliberately stores metadata and fingerprints instead of raw
prompts or tool payloads.  It is usable without a logging framework and keeps
the event format stable enough for append-only JSONL sinks.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, TextIO, cast

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[^\s,;]+"),
    re.compile(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.S
    ),
    re.compile(r"\b(?:ghp|github_pat|sk|xox[baprs])-[-A-Za-z0-9_]{8,}\b"),
)
_MAX_VALUE_LENGTH = 4_096


def redact(value: Any) -> Any:
    """Return a JSON-safe, recursively redacted representation of *value*.

    Keys commonly carrying credentials are replaced entirely. Strings are
    pattern-redacted and truncated to prevent accidental log amplification.
    Unknown objects are represented by their type rather than ``repr`` (which
    can expose secrets through custom implementations).
    """

    sensitive_keys = {
        "authorization",
        "api_key",
        "apikey",
        "secret",
        "password",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
    }
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if str(key).lower().replace("-", "_") in sensitive_keys
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        result = value
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub(
                lambda match: (
                    (match.group(1) if match.lastindex else "") + "[REDACTED]"
                ),
                result,
            )
        return result[:_MAX_VALUE_LENGTH]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def fingerprint(value: Any) -> str:
    """Return a stable one-way identifier for a payload without storing it."""

    canonical = json.dumps(
        redact(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable audit record.  ``details`` must never contain raw secrets."""

    event_type: str
    actor: str
    correlation_id: str
    outcome: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    event_id: str = field(default_factory=lambda: secrets.token_hex(16))
    details: Mapping[str, Any] = field(default_factory=dict)
    prompt_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not self.event_type or not self.actor or not self.correlation_id:
            raise ValueError("event_type, actor, and correlation_id are required")
        if self.outcome not in {"started", "succeeded", "failed", "denied"}:
            raise ValueError("outcome must be started, succeeded, failed, or denied")
        redacted = redact(self.details)
        object.__setattr__(self, "details", MappingProxyType(redacted))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "actor": self.actor,
            "correlation_id": self.correlation_id,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "details": dict(self.details),
            "prompt_fingerprint": self.prompt_fingerprint,
        }

    def __getitem__(self, key: str) -> Any:
        """Provide read-only mapping-style access for sink integrations."""
        return self.to_dict()[key]


class AuditLog:
    """Thread-safe append-only audit sink with optional JSONL export."""

    def __init__(self, *, store_prompts: bool = False) -> None:
        self.store_prompts = store_prompts
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def record(
        self,
        event_type: str,
        *,
        actor: str,
        correlation_id: str,
        outcome: str,
        details: Mapping[str, Any] | None = None,
        prompt: str | None = None,
    ) -> AuditEvent:
        """Record an event; prompts are fingerprinted and never retained by default."""

        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            correlation_id=correlation_id,
            outcome=outcome,
            details=details or {},
            prompt_fingerprint=fingerprint(prompt) if prompt is not None else None,
        )
        with self._lock:
            self._events.append(event)
        return event

    def events(self, correlation_id: str | None = None) -> tuple[AuditEvent, ...]:
        with self._lock:
            events = tuple(self._events)
        return tuple(
            event
            for event in events
            if correlation_id is None or event.correlation_id == correlation_id
        )

    def export_jsonl(self, destination: str | Path | TextIO) -> int:
        """Export a consistent snapshot as JSON Lines; returns event count."""

        events = self.events()
        close = False
        if hasattr(destination, "write"):
            stream = cast(TextIO, destination)
        else:
            stream = Path(destination).open("a", encoding="utf-8")
            close = True
        try:
            for event in events:
                stream.write(
                    json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)
                    + "\n"
                )
        finally:
            if close:
                stream.close()
        return len(events)


def new_correlation_id() -> str:
    """Create an opaque correlation ID suitable for a single agent run."""

    return secrets.token_urlsafe(18)


__all__ = ["AuditEvent", "AuditLog", "fingerprint", "new_correlation_id", "redact"]
