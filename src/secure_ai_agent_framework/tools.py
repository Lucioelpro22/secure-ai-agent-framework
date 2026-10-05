"""Fail-closed runner for explicitly allow-listed tools.

The runner intentionally has no shell, network, or dynamic-import support. A
caller must register a trusted Python callable and explicitly opt in to any
capability that callable needs. This is a policy boundary, not a sandbox; run
untrusted code in an operating-system sandbox outside this package.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any

from .parameters import freeze_parameters, parameter_values

ToolCallable = Callable[..., Any]
Validator = Callable[[Mapping[str, Any]], None]


class ToolError(Exception):
    """Base class for safe tool-runner failures."""


class UnknownToolError(ToolError):
    """Raised when a tool is not explicitly registered."""


class ToolExecutionError(ToolError):
    """Raised when a registered tool fails."""


class ToolTimeoutError(ToolError):
    """Raised when a tool exceeds its configured deadline."""


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Execution limits and capability defaults for one runner instance."""

    default_timeout_seconds: float = 5.0
    max_timeout_seconds: float = 30.0
    max_input_bytes: int = 64 * 1024
    max_output_bytes: int = 256 * 1024
    allow_network: bool = False
    allow_subprocess: bool = False

    def __post_init__(self) -> None:
        if self.default_timeout_seconds <= 0 or self.max_timeout_seconds <= 0:
            raise ValueError("timeouts must be positive")
        if self.default_timeout_seconds > self.max_timeout_seconds:
            raise ValueError("default timeout cannot exceed maximum timeout")
        if self.max_input_bytes <= 0 or self.max_output_bytes <= 0:
            raise ValueError("size limits must be positive")


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A trusted callable and its explicit capabilities."""

    name: str
    handler: ToolCallable
    description: str = ""
    validator: Validator | None = None
    network: bool = False
    subprocess: bool = False
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name.strip() != self.name:
            raise ValueError("tool name must be non-empty and trimmed")
        if not callable(self.handler):
            raise TypeError("tool handler must be callable")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("tool timeout must be positive")


@dataclass(frozen=True, slots=True)
class ToolRequest:
    """A single invocation request, normally produced after human approval."""

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    dry_run: bool = False
    timeout_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Structured result that is safe to serialize into an audit event."""

    tool: str
    status: str
    output: Any = None
    simulated: bool = False
    error: str | None = None


class ToolRunner:
    """Execute only registered tools under conservative, fail-closed policy."""

    def __init__(
        self, specs: tuple[ToolSpec, ...] = (), policy: ToolPolicy | None = None
    ) -> None:
        self.policy = policy or ToolPolicy()
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ToolSpec) -> None:
        """Register an allow-listed tool, rejecting duplicates."""
        if spec.name in self._specs:
            raise ValueError(f"tool already registered: {spec.name}")
        if spec.network and not self.policy.allow_network:
            raise ValueError(f"network capability denied by policy: {spec.name}")
        if spec.subprocess and not self.policy.allow_subprocess:
            raise ValueError(f"subprocess capability denied by policy: {spec.name}")
        if (
            spec.timeout_seconds is not None
            and spec.timeout_seconds > self.policy.max_timeout_seconds
        ):
            raise ValueError(f"tool timeout exceeds policy: {spec.name}")
        self._specs[spec.name] = spec

    def names(self) -> tuple[str, ...]:
        """Return the immutable, sorted allowlist."""
        return tuple(sorted(self._specs))

    def run(self, request: ToolRequest) -> ToolResult:
        """Run or simulate a request; all policy failures raise ``ToolError``."""
        spec = self._specs.get(request.tool)
        if spec is None:
            raise UnknownToolError(f"tool is not allow-listed: {request.tool}")
        arguments = self._validate_arguments(spec, request.arguments)
        timeout = (
            request.timeout_seconds
            or spec.timeout_seconds
            or self.policy.default_timeout_seconds
        )
        if timeout <= 0 or timeout > self.policy.max_timeout_seconds:
            raise ToolError("requested timeout is outside policy")
        if request.dry_run:
            return ToolResult(
                tool=spec.name,
                status="simulated",
                output={"tool": spec.name, "arguments": arguments},
                simulated=True,
            )

        # A worker thread gives a deadline to the caller. It is not an OS
        # sandbox: handlers must still be trusted and should be independently
        # cancellable. We fail closed if the deadline is exceeded.
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tool")
        future = pool.submit(spec.handler, **arguments)
        try:
            output = future.result(timeout=timeout)
        except FutureTimeout as exc:
            future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise ToolTimeoutError(f"tool timed out: {spec.name}") from exc
        except ToolError:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        except Exception as exc:
            pool.shutdown(wait=False, cancel_futures=True)
            raise ToolExecutionError(f"tool failed: {spec.name}") from exc
        else:
            pool.shutdown(wait=True, cancel_futures=True)
        self._check_size(output, self.policy.max_output_bytes, "output")
        return ToolResult(tool=spec.name, status="completed", output=output)

    def _validate_arguments(
        self, spec: ToolSpec, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(arguments, Mapping):
            raise ToolError("arguments must be a mapping")
        try:
            normalized = {
                key: parameter_values(value)
                for key, value in freeze_parameters(arguments).items()
            }
        except ValueError as exc:
            raise ToolError("input must contain only finite JSON values") from exc
        self._check_size(normalized, self.policy.max_input_bytes, "input")
        if spec.validator is not None:
            try:
                spec.validator(normalized)
            except Exception as exc:
                raise ToolError(f"invalid arguments for {spec.name}") from exc
        return normalized

    @staticmethod
    def _check_size(value: Any, limit: int, label: str) -> None:
        try:
            size = len(json.dumps(value, ensure_ascii=False, sort_keys=True).encode())
        except (TypeError, ValueError, OverflowError) as exc:
            raise ToolError(f"{label} must be JSON-serializable") from exc
        if size > limit:
            raise ToolError(f"{label} exceeds configured size limit")
