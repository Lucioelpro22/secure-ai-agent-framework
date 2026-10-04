"""Fail-closed capability policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from .approvals import ApprovalAuthority, ApprovalError
from .models import ActionRequest, Capability, Decision, PolicyDecision, RiskLevel
from .validator import ActionValidationError, validate_action


@dataclass(frozen=True, slots=True)
class PolicyRule:
    capability: Capability
    requires_approval: bool = False


class PolicyEngine:
    """Evaluate requests against explicit rules; no matching rule means deny."""

    def __init__(
        self, rules: tuple[PolicyRule, ...], approvals: ApprovalAuthority | None = None
    ):
        self._rules = rules
        self._approvals = approvals

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        try:
            validate_action(request)
        except ActionValidationError as exc:
            return PolicyDecision(Decision.DENY, f"invalid action: {exc}")
        for rule in self._rules:
            capability = rule.capability
            if not capability.permits(
                request.action, request.resource, request.operation
            ):
                continue
            approval_required = rule.requires_approval or capability.risk in {
                RiskLevel.HIGH,
                RiskLevel.CRITICAL,
            }
            if not approval_required:
                return PolicyDecision(
                    Decision.ALLOW, "explicit capability matched", capability.name
                )
            if self._approvals is None or request.approval_token is None:
                return PolicyDecision(
                    Decision.APPROVAL_REQUIRED,
                    "human approval required",
                    capability.name,
                )
            try:
                self._approvals.consume(request.approval_token, request)
            except ApprovalError as exc:
                return PolicyDecision(
                    Decision.DENY, f"approval rejected: {exc}", capability.name
                )
            return PolicyDecision(
                Decision.ALLOW,
                "explicit capability and approval matched",
                capability.name,
            )
        return PolicyDecision(Decision.DENY, "no explicit capability matched")
