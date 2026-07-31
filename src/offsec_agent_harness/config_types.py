from __future__ import annotations

from typing import Any
import re

_TRUE_STRINGS = {"1", "true", "yes", "y", "on"}
_FALSE_STRINGS = {"0", "false", "no", "n", "off"}
_INT_RE = re.compile(r"^[+-]?\d+$")


def config_bool(value: Any, field: str, *, default: bool | None = None) -> bool:
    """Parse a JSON/config boolean without Python truthiness surprises."""

    if value is None:
        if default is not None:
            return default
        raise ValueError(f"{field} must be a boolean.")
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE_STRINGS:
            return True
        if text in _FALSE_STRINGS:
            return False
    raise ValueError(f"{field} must be a boolean.")


def config_int(
    value: Any,
    field: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse a bounded integer from JSON/config with clean operator errors."""

    if value is None:
        if default is not None:
            parsed = default
        else:
            raise ValueError(f"{field} must be an integer.")
    elif isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, float) and value.is_integer():
        parsed = int(value)
    elif isinstance(value, str) and _INT_RE.match(value.strip()):
        parsed = int(value.strip())
    else:
        raise ValueError(f"{field} must be an integer.")
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field} must be at least {minimum}.")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field} must be at most {maximum}.")
    return parsed


def config_float(value: Any, field: str, *, default: float | None = None, minimum: float | None = None) -> float:
    """Parse a float from JSON/config while rejecting booleans and junk strings."""

    if value is None:
        if default is not None:
            parsed = float(default)
        else:
            raise ValueError(f"{field} must be a number.")
    elif isinstance(value, bool):
        raise ValueError(f"{field} must be a number.")
    else:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field} must be a number.") from None
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field} must be at least {minimum}.")
    return parsed


def config_string(value: Any, field: str, *, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list, tuple, set)) or isinstance(value, bool):
        raise ValueError(f"{field} must be a string.")
    return str(value)


def config_optional_string(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    return config_string(value, field)


def config_string_list(value: Any, field: str, *, default: list[str] | None = None) -> list[str]:
    if value is None:
        return list(default or [])
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be a list of strings.")
    result: list[str] = []
    for idx, item in enumerate(value):
        result.append(config_string(item, f"{field}[{idx}]").strip())
    return [item for item in result if item]


def config_string_list_map(value: Any, field: str) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    result: dict[str, list[str]] = {}
    for key, items in value.items():
        name = config_string(key, f"{field} key").strip()
        if name:
            result[name] = config_string_list(items, f"{field}.{name}")
    return result
