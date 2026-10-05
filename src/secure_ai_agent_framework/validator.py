"""Input validation at the tool invocation boundary."""

from __future__ import annotations

import re

from .models import ActionRequest


class ActionValidationError(ValueError):
    """Raised for malformed or unsafe action metadata."""


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


def validate_action(request: ActionRequest) -> None:
    """Reject ambiguous action metadata before policy matching."""
    for label, value in (
        ("subject", request.subject),
        ("action", request.action),
        ("operation", request.operation),
    ):
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ActionValidationError(f"invalid {label}")
    if (
        not isinstance(request.resource, str)
        or not request.resource
        or len(request.resource) > 512
    ):
        raise ActionValidationError("invalid resource")
    if (
        ".." in request.resource
        or "\\" in request.resource
        or "\x00" in request.resource
    ):
        raise ActionValidationError("unsafe resource")
    if len(request.parameters) > 100:
        raise ActionValidationError("too many parameters")
