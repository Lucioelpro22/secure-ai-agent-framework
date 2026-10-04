from dataclasses import replace
from datetime import timedelta

from secure_ai_agent_framework import (
    ActionRequest,
    ApprovalAuthority,
    Capability,
    Decision,
    PolicyEngine,
    PolicyRule,
    RiskLevel,
    Scope,
)


def capability(risk=RiskLevel.LOW):
    return Capability(
        "repo",
        frozenset({"github.read", "github.delete"}),
        (Scope("repo/a", frozenset({"read", "delete"})),),
        risk,
    )


def test_no_rule_denies():
    result = PolicyEngine(()).evaluate(
        ActionRequest("agent", "github.read", "repo/a", "read")
    )
    assert result.decision is Decision.DENY


def test_scope_is_hierarchical_but_not_prefix_confusable():
    engine = PolicyEngine((PolicyRule(capability()),))
    assert (
        engine.evaluate(
            ActionRequest("agent", "github.read", "repo/a/sub", "read")
        ).decision
        is Decision.ALLOW
    )
    assert (
        engine.evaluate(
            ActionRequest("agent", "github.read", "repo/ab", "read")
        ).decision
        is Decision.DENY
    )


def test_high_risk_requires_and_accepts_single_use_approval():
    authority = ApprovalAuthority(b"x" * 32)
    request = ActionRequest("agent", "github.delete", "repo/a", "delete")
    engine = PolicyEngine((PolicyRule(capability(RiskLevel.HIGH)),), authority)
    assert engine.evaluate(request).decision is Decision.APPROVAL_REQUIRED
    approved = replace(request, approval_token=authority.issue(request))
    assert engine.evaluate(approved).decision is Decision.ALLOW
    assert engine.evaluate(approved).decision is Decision.DENY


def test_approval_is_bound_to_exact_action():
    authority = ApprovalAuthority(b"x" * 32)
    request = ActionRequest("agent", "github.delete", "repo/a", "delete")
    token = authority.issue(request, ttl=timedelta(minutes=1))
    altered = ActionRequest(
        "agent", "github.delete", "repo/a/other", "delete", approval_token=token
    )
    assert (
        PolicyEngine((PolicyRule(capability(RiskLevel.HIGH)),), authority)
        .evaluate(altered)
        .decision
        is Decision.DENY
    )


def test_malformed_request_denies():
    request = ActionRequest("Agent", "github.read", "repo/a", "read")
    assert (
        PolicyEngine((PolicyRule(capability()),)).evaluate(request).decision
        is Decision.DENY
    )
