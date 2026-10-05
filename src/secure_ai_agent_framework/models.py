"""Immutable domain models used by the authorization boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .parameters import freeze_parameters, parameter_values


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Scope:
    """A resource scope. A scope only covers itself and descendants."""

    resource: str
    operations: frozenset[str] = frozenset()

    def covers(self, resource: str, operation: str) -> bool:
        prefix = self.resource.rstrip("/")
        same_resource = resource == prefix or resource.startswith(prefix + "/")
        return same_resource and (not self.operations or operation in self.operations)


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    actions: frozenset[str]
    scopes: tuple[Scope, ...]
    risk: RiskLevel = RiskLevel.LOW

    def permits(self, action: str, resource: str, operation: str) -> bool:
        return action in self.actions and any(
            scope.covers(resource, operation) for scope in self.scopes
        )


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    token_id: str
    subject: str
    action_digest: str
    expires_at: datetime
    issued_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return current >= self.expires_at


@dataclass(frozen=True, slots=True)
class ActionRequest:
    subject: str
    action: str
    resource: str
    operation: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    approval_token: ApprovalToken | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", freeze_parameters(self.parameters))

    def to_arguments(self) -> dict[str, Any]:
        """Copy the exact parameter snapshot for a trusted execution adapter."""
        return {key: parameter_values(value) for key, value in self.parameters.items()}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    reason: str
    capability: str | None = None
