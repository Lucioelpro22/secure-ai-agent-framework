import io
import json

import pytest

from secure_ai_agent_framework.audit import (
    AuditEvent,
    AuditLog,
    fingerprint,
    new_correlation_id,
    redact,
)


def test_redact_nested_secrets_and_private_key() -> None:
    payload = {
        "authorization": "Bearer very-secret",
        "nested": {"password": "abc", "message": "safe"},
    }
    result = redact(payload)
    assert result["authorization"] == "[REDACTED]"
    assert result["nested"]["password"] == "[REDACTED]"
    assert result["nested"]["message"] == "safe"


def test_redact_string_patterns_and_unknown_objects() -> None:
    assert "super-secret" not in redact("api_key=super-secret")
    assert redact(object()) == "<object>"


def test_event_is_immutable_and_validates_outcome() -> None:
    event = AuditEvent(
        "tool.call",
        actor="agent",
        correlation_id="c1",
        outcome="denied",
        details={"token": "x"},
    )
    assert event.details["token"] == "[REDACTED]"
    with pytest.raises((AttributeError, TypeError)):
        event.outcome = "succeeded"  # type: ignore[misc]
    with pytest.raises(TypeError):
        event.details["new"] = "value"  # type: ignore[index]
    with pytest.raises(ValueError):
        AuditEvent("x", actor="a", correlation_id="c", outcome="unknown")


def test_log_fingerprints_prompt_without_retaining_content() -> None:
    log = AuditLog()
    event = log.record(
        "agent.prompt",
        actor="agent",
        correlation_id="c1",
        outcome="started",
        prompt="do not retain this",
    )
    assert event.prompt_fingerprint == fingerprint("do not retain this")
    serialized = json.dumps(event.to_dict())
    assert "do not retain this" not in serialized


def test_correlated_events_and_jsonl_export() -> None:
    log = AuditLog()
    log.record("a", actor="agent", correlation_id="same", outcome="started")
    log.record("b", actor="agent", correlation_id="other", outcome="succeeded")
    stream = io.StringIO()
    assert log.export_jsonl(stream) == 2
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(records) == 2
    assert [item["correlation_id"] for item in log.events("same")] == ["same"]


def test_correlation_id_is_opaque() -> None:
    assert len(new_correlation_id()) >= 20
