"""Short-lived, action-bound human approval tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from .models import ActionRequest, ApprovalToken


class ApprovalError(ValueError):
    """Raised when an approval token cannot authorize an exact action."""


def action_digest(request: ActionRequest) -> str:
    """Return a stable digest of the authorization-relevant action."""
    canonical = "\x1f".join(
        (request.subject, request.action, request.resource, request.operation)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalAuthority:
    """Issues and consumes single-use approvals without storing secrets in tokens."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key = signing_key
        self._used: set[str] = set()

    def issue(
        self, request: ActionRequest, *, ttl: timedelta = timedelta(minutes=10)
    ) -> ApprovalToken:
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ValueError(
                "approval TTL must be positive and no longer than one hour"
            )
        now = datetime.now(UTC)
        digest = action_digest(request)
        token_id = secrets.token_urlsafe(24)
        signature = hmac.new(
            self._key, f"{token_id}:{digest}".encode(), hashlib.sha256
        ).hexdigest()
        return ApprovalToken(
            token_id=f"{token_id}.{signature}",
            subject=request.subject,
            action_digest=digest,
            issued_at=now,
            expires_at=now + ttl,
        )

    def consume(self, token: ApprovalToken, request: ActionRequest) -> None:
        """Validate and consume a token; all failures deny authorization."""
        if token.token_id in self._used:
            raise ApprovalError("approval token has already been consumed")
        if token.is_expired():
            raise ApprovalError("approval token has expired")
        if token.subject != request.subject or token.action_digest != action_digest(
            request
        ):
            raise ApprovalError("approval token is not bound to this exact action")
        try:
            token_id, signature = token.token_id.rsplit(".", 1)
        except ValueError as exc:
            raise ApprovalError("malformed approval token") from exc
        expected = hmac.new(
            self._key, f"{token_id}:{token.action_digest}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ApprovalError("invalid approval token signature")
        self._used.add(token.token_id)
