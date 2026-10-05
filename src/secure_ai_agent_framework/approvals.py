"""Short-lived, action-bound human approval tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from threading import Lock

from .models import ActionRequest, ApprovalToken
from .validator import ActionValidationError, validate_action


class ApprovalError(ValueError):
    """Raised when an approval token cannot authorize an exact action."""


def action_digest(request: ActionRequest) -> str:
    """Hash validated metadata and the complete immutable parameter snapshot."""
    validate_action(request)
    try:
        canonical = json.dumps(
            {
                "subject": request.subject,
                "action": request.action,
                "resource": request.resource,
                "operation": request.operation,
                "parameters": request.to_arguments(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ActionValidationError("parameters cannot be serialized as JSON") from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalAuthority:
    """Issue approvals with atomic, process-local single-use enforcement.

    Keep one instance alive for the lifetime of its signing key. Independent
    processes or restarts require an external durable, atomic replay store.
    """

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key = signing_key
        self._used: set[str] = set()
        self._lock = Lock()

    def _signature(
        self,
        token_id: str,
        subject: str,
        digest: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> str:
        claims = json.dumps(
            {
                "version": 1,
                "token_id": token_id,
                "subject": subject,
                "action_digest": digest,
                "issued_at": issued_at.astimezone(UTC).isoformat(
                    timespec="microseconds"
                ),
                "expires_at": expires_at.astimezone(UTC).isoformat(
                    timespec="microseconds"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hmac.new(self._key, claims.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(
        self, request: ActionRequest, *, ttl: timedelta = timedelta(minutes=10)
    ) -> ApprovalToken:
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ValueError(
                "approval TTL must be positive and no longer than one hour"
            )
        now = datetime.now(UTC)
        expires_at = now + ttl
        digest = action_digest(request)
        token_id = secrets.token_urlsafe(24)
        signature = self._signature(token_id, request.subject, digest, now, expires_at)
        return ApprovalToken(
            token_id=f"{token_id}.{signature}",
            subject=request.subject,
            action_digest=digest,
            issued_at=now,
            expires_at=expires_at,
        )

    def consume(self, token: ApprovalToken, request: ActionRequest) -> None:
        """Validate and consume a token; every failure denies authorization."""
        with self._lock:
            self._consume(token, request)

    def _consume(self, token: ApprovalToken, request: ActionRequest) -> None:
        if not isinstance(token.token_id, str):
            raise ApprovalError("malformed approval token")
        if token.token_id in self._used:
            raise ApprovalError("approval token has already been consumed")
        for value in (token.issued_at, token.expires_at):
            if not isinstance(value, datetime) or value.utcoffset() is None:
                raise ApprovalError("approval timestamps must be timezone-aware")
        now = datetime.now(UTC)
        ttl = token.expires_at - token.issued_at
        if ttl <= timedelta(0) or ttl > timedelta(hours=1) or token.issued_at > now:
            raise ApprovalError("invalid approval validity period")
        if token.is_expired(now):
            raise ApprovalError("approval token has expired")
        try:
            digest = action_digest(request)
        except ActionValidationError as exc:
            raise ApprovalError("invalid action") from exc
        if token.subject != request.subject or token.action_digest != digest:
            raise ApprovalError("approval token is not bound to this exact action")
        try:
            token_id, signature = token.token_id.rsplit(".", 1)
        except ValueError as exc:
            raise ApprovalError("malformed approval token") from exc
        if not re.fullmatch(r"[A-Za-z0-9_-]{32}", token_id) or not re.fullmatch(
            r"[0-9a-f]{64}", signature
        ):
            raise ApprovalError("malformed approval token")
        expected = self._signature(
            token_id,
            token.subject,
            token.action_digest,
            token.issued_at,
            token.expires_at,
        )
        if not hmac.compare_digest(signature, expected):
            raise ApprovalError("invalid approval token signature")
        self._used.add(token.token_id)
