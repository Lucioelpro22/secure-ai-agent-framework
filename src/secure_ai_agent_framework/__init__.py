"""Defensive building blocks for human-approved AI agents."""

from .approvals import ApprovalAuthority, ApprovalError
from .audit import AuditEvent, AuditLog, fingerprint, new_correlation_id, redact
from .models import (
    ActionRequest,
    ApprovalToken,
    Capability,
    Decision,
    PolicyDecision,
    RiskLevel,
    Scope,
)
from .policy import PolicyEngine, PolicyRule
from .tools import (
    ToolError,
    ToolExecutionError,
    ToolPolicy,
    ToolRequest,
    ToolResult,
    ToolRunner,
    ToolSpec,
    ToolTimeoutError,
    UnknownToolError,
)
from .validator import ActionValidationError, validate_action

__all__ = [
    "ActionRequest",
    "ActionValidationError",
    "ApprovalAuthority",
    "ApprovalError",
    "ApprovalToken",
    "AuditEvent",
    "AuditLog",
    "Capability",
    "Decision",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRule",
    "RiskLevel",
    "Scope",
    "ToolError",
    "ToolExecutionError",
    "ToolPolicy",
    "ToolRequest",
    "ToolResult",
    "ToolRunner",
    "ToolSpec",
    "ToolTimeoutError",
    "UnknownToolError",
    "fingerprint",
    "new_correlation_id",
    "redact",
    "validate_action",
]
