"""Snapshot JSON parameters so callers cannot change an approved action."""

from __future__ import annotations

import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


def freeze_parameters(parameters: Mapping[str, Any]) -> Mapping[str, Any]:
    """Take an immutable copy, rejecting non-JSON and recursive values."""
    if not isinstance(parameters, Mapping):
        raise ValueError("parameters must be a mapping")
    try:
        return MappingProxyType(_freeze_mapping(parameters))
    except RecursionError as exc:
        raise ValueError("parameters must be finite, non-recursive JSON") from exc


def _freeze_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if any(not isinstance(key, str) for key in value):
        raise ValueError("parameter keys must be strings")
    return {key: _freeze(item) for key, item in value.items()}


def _freeze(value: Any) -> Any:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType(_freeze_mapping(value))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise ValueError("parameters must contain only finite JSON values")


def parameter_values(value: Any) -> Any:
    """Return independent JSON containers from a frozen parameter snapshot."""
    if isinstance(value, Mapping):
        return {key: parameter_values(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [parameter_values(item) for item in value]
    return value
