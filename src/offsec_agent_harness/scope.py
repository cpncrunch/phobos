from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    in_scope: bool
    matched_rule: str | None = None
    reason: str = ""


def target_in_scope(target: str, scope_rules: list[str]) -> ScopeMatch:
    """Match a host/IP/URL-ish target against exact host, wildcard, suffix, or CIDR rules."""
    normalized = _normalize_target(target)
    for raw_rule in scope_rules:
        rule = raw_rule.strip()
        if not rule:
            continue
        if _cidr_match(normalized, rule):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched CIDR {raw_rule!r}.")
        if fnmatch(normalized, rule.lower()):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched wildcard/exact rule {raw_rule!r}.")
        if rule.startswith("*.") and normalized.endswith(rule[1:].lower()):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched subdomain rule {raw_rule!r}.")
        if normalized == rule.lower():
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched exact rule {raw_rule!r}.")
    return ScopeMatch(False, None, f"Target {normalized!r} did not match any in-scope target rule.")


def _normalize_target(target: str) -> str:
    value = target.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if ":" in value and not value.startswith("["):
        host, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            value = host
    return value.strip("[]")


def _cidr_match(target: str, rule: str) -> bool:
    try:
        network = ip_network(rule, strict=False)
        return ip_address(target) in network
    except ValueError:
        return False
