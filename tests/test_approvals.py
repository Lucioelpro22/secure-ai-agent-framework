from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from threading import Barrier

import pytest

from secure_ai_agent_framework import ActionRequest, ApprovalAuthority
from secure_ai_agent_framework.approvals import ApprovalError, action_digest
from secure_ai_agent_framework.tools import ToolRequest, ToolRunner, ToolSpec


def request(parameters=None):
    return ActionRequest("agent", "mail.send", "mail/team", "send", parameters or {})


def test_nested_parameters_are_bound_to_approval():
    authority = ApprovalAuthority(b"x" * 32)
    original = request({"to": [{"address": "approved@example.test"}], "body": "hello"})
    token = authority.issue(original)
    for parameters in (
        {"to": [{"address": "different@example.test"}], "body": "hello"},
        {"to": [{"address": "approved@example.test"}], "body": "changed"},
        {"to": [{"address": "approved@example.test"}], "body": "hello", "cc": "extra"},
    ):
        with pytest.raises(ApprovalError, match="exact action"):
            authority.consume(token, request(parameters))
    authority.consume(token, original)


def test_nested_parameter_order_is_canonical():
    first = request({"to": {"name": "test", "address": "a"}, "items": [1, True, None]})
    second = request({"items": [1, True, None], "to": {"address": "a", "name": "test"}})
    assert action_digest(first) == action_digest(second)
    assert action_digest(request({"items": [1, 2]})) != action_digest(
        request({"items": [2, 1]})
    )


def test_snapshot_prevents_mutation_between_approval_and_execution():
    source = {"to": [{"address": "approved@example.test"}]}
    original = request(source)
    authority = ApprovalAuthority(b"x" * 32)
    token = authority.issue(original)
    source["to"][0]["address"] = "different@example.test"
    with pytest.raises(TypeError):
        original.parameters["to"][0]["address"] = "changed"
    authority.consume(token, original)
    runner = ToolRunner((ToolSpec("send", lambda to: to[0]["address"]),))
    assert (
        runner.run(ToolRequest("send", original.parameters)).output
        == "approved@example.test"
    )
    arguments = original.to_arguments()
    arguments["to"][0]["address"] = "mutated copy"
    assert original.to_arguments()["to"][0]["address"] == "approved@example.test"


@pytest.mark.parametrize(
    "invalid",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        object(),
        {1: "ambiguous"},
        {"x"},
        b"bytes",
    ],
)
def test_non_json_parameters_rejected(invalid):
    with pytest.raises(ValueError):
        request({"nested": invalid})


def test_recursive_parameters_rejected():
    recursive = {}
    recursive["self"] = recursive
    with pytest.raises(ValueError, match="non-recursive"):
        request(recursive)


@pytest.mark.parametrize(
    "field", ["subject", "action_digest", "issued_at", "expires_at", "token_id"]
)
def test_all_claims_are_authenticated_and_invalid_tokens_do_not_consume(field):
    authority = ApprovalAuthority(b"x" * 32)
    original = request({"a": 1})
    token = authority.issue(original)
    values = {
        "subject": "other",
        "action_digest": "0" * 64,
        "issued_at": token.issued_at - timedelta(seconds=1),
        "expires_at": token.expires_at + timedelta(seconds=1),
        "token_id": token.token_id[:-1] + ("0" if token.token_id[-1] != "0" else "1"),
    }
    with pytest.raises(ApprovalError):
        authority.consume(replace(token, **{field: values[field]}), original)
    authority.consume(token, original)


@pytest.mark.parametrize(
    "period",
    [
        "naive_issue",
        "naive_expiry",
        "future",
        "zero",
        "negative",
        "too_long",
        "expired",
    ],
)
def test_invalid_validity_periods_fail_closed(period):
    authority = ApprovalAuthority(b"x" * 32)
    original = request()
    token = authority.issue(original)
    now = datetime.now(UTC)
    dates = {
        "naive_issue": {"issued_at": now.replace(tzinfo=None)},
        "naive_expiry": {"expires_at": now.replace(tzinfo=None)},
        "future": {"issued_at": now + timedelta(minutes=1)},
        "zero": {"expires_at": token.issued_at},
        "negative": {"expires_at": token.issued_at - timedelta(seconds=1)},
        "too_long": {"expires_at": token.issued_at + timedelta(hours=2)},
        "expired": {
            "issued_at": now - timedelta(minutes=2),
            "expires_at": now - timedelta(minutes=1),
        },
    }
    with pytest.raises(ApprovalError):
        authority.consume(replace(token, **dates[period]), original)
    authority.consume(token, original)


def test_timezone_normalization_preserves_one_use():
    authority = ApprovalAuthority(b"x" * 32)
    original = request({"unicode": "\u2603"})
    token = authority.issue(original)
    offset = timezone(timedelta(hours=3))
    equivalent = replace(
        token,
        issued_at=token.issued_at.astimezone(offset),
        expires_at=token.expires_at.astimezone(offset),
    )
    authority.consume(equivalent, original)
    with pytest.raises(ApprovalError, match="already"):
        authority.consume(token, original)


@pytest.mark.parametrize(
    "token_id", ["no-separator", ".", "abc.non-ascii-\u2603", "0" * 32 + "." + "x" * 64]
)
def test_malformed_token_denied_without_consuming_valid_token(token_id):
    authority = ApprovalAuthority(b"x" * 32)
    original = request()
    token = authority.issue(original)
    with pytest.raises(ApprovalError):
        authority.consume(replace(token, token_id=token_id), original)
    authority.consume(token, original)


def test_concurrent_consumption_allows_exactly_once():
    authority = ApprovalAuthority(b"x" * 32)
    original = request()
    token = authority.issue(original)
    start = Barrier(8)

    def consume_once(_):
        start.wait()
        try:
            authority.consume(token, original)
        except ApprovalError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as workers:
        assert sum(workers.map(consume_once, range(8))) == 1


@pytest.mark.parametrize(
    "ttl", [timedelta(0), timedelta(seconds=-1), timedelta(hours=1, seconds=1)]
)
def test_invalid_issue_ttl_rejected(ttl):
    with pytest.raises(ValueError, match="TTL"):
        ApprovalAuthority(b"x" * 32).issue(request(), ttl=ttl)


def test_short_key_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        ApprovalAuthority(b"short")


def test_invalid_action_cannot_be_approved():
    authority = ApprovalAuthority(b"x" * 32)
    original = request()
    with pytest.raises(ValueError):
        authority.issue(replace(original, subject="Invalid"))
    token = authority.issue(original)
    with pytest.raises(ApprovalError, match="invalid action"):
        authority.consume(token, replace(original, resource="../unsafe"))


def test_oversized_integer_serialization_denies_without_consuming_token():
    from secure_ai_agent_framework import (
        Capability,
        Decision,
        PolicyEngine,
        PolicyRule,
        RiskLevel,
        Scope,
    )

    authority = ApprovalAuthority(b"x" * 32)
    original = request()
    token = authority.issue(original)
    invalid = replace(original, parameters={"value": 10**5000}, approval_token=token)
    capability = Capability(
        "mail", frozenset({"mail.send"}), (Scope("mail/team"),), RiskLevel.HIGH
    )
    engine = PolicyEngine((PolicyRule(capability),), authority)
    assert engine.evaluate(invalid).decision is Decision.DENY
    with pytest.raises(ValueError, match="serialized"):
        authority.issue(invalid)
    authority.consume(token, original)
