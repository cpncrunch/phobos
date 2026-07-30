from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    in_scope: bool
    matched_rule: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class _Endpoint:
    host: str
    port: int | None = None
    valid: bool = True

    def display(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"


def target_in_scope(target: str, scope_rules: list[str]) -> ScopeMatch:
    """Match a host/IP/URL-ish target against exact host, wildcard, suffix, port, or CIDR rules.

    Scope rules are still host-oriented: paths and query strings are ignored so
    secret-like URL parameters never become part of matching reasons. If a rule
    includes an explicit port (for example ``https://app.example.test:8443`` or
    ``*.corp.example:443``), the target must include the same port to match. CIDR
    rules match against the normalized target host/IP and intentionally ignore
    target ports.
    """

    endpoint = _parse_endpoint(target)
    normalized = endpoint.display()
    if not endpoint.host or not endpoint.valid:
        return ScopeMatch(False, None, f"Target {normalized!r} did not parse as a valid host/IP/URL target.")
    for raw_rule in scope_rules:
        rule = raw_rule.strip()
        if not rule:
            continue
        if _cidr_match(endpoint.host, rule):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched CIDR {raw_rule!r}.")

        rule_endpoint = _parse_endpoint(rule)
        if not rule_endpoint.host or not rule_endpoint.valid:
            continue
        if rule_endpoint.port is not None and endpoint.port != rule_endpoint.port:
            continue
        rule_host = rule_endpoint.host
        if fnmatch(endpoint.host, rule_host):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched wildcard/exact rule {raw_rule!r}.")
        if rule_host.startswith("*.") and endpoint.host.endswith(rule_host[1:]):
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched subdomain rule {raw_rule!r}.")
        if endpoint.host == rule_host:
            return ScopeMatch(True, raw_rule, f"Target {normalized!r} matched exact rule {raw_rule!r}.")
    return ScopeMatch(False, None, f"Target {normalized!r} did not match any in-scope target rule.")


def _parse_endpoint(value: str) -> _Endpoint:
    text = value.strip().lower()
    if not text:
        return _Endpoint("")

    if "://" in text or text.startswith("//"):
        parsed = urlsplit(text)
        host = _clean_host(parsed.hostname or "")
        try:
            port = parsed.port
        except ValueError:
            return _Endpoint(host, None, valid=False)
        return _Endpoint(host, port)

    text = _strip_resource_suffix(text)
    if "@" in text:
        text = text.rsplit("@", 1)[1]

    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1 :]
            port = _parse_port(rest[1:]) if rest.startswith(":") else None
            if rest.startswith(":") and rest[1:] and port is None:
                return _Endpoint(_clean_host(host), None, valid=False)
            return _Endpoint(_clean_host(host), port)
        return _Endpoint(_clean_host(text.strip("[]")))

    # Unbracketed IPv6 literals contain multiple colons. Treat them as hosts
    # without ports; bracketed notation is required for an IPv6 host:port pair.
    if text.count(":") > 1:
        return _Endpoint(_clean_host(text))

    if ":" in text:
        host, possible_port = text.rsplit(":", 1)
        port = _parse_port(possible_port)
        if port is not None:
            return _Endpoint(_clean_host(host), port)
        if possible_port.isdigit():
            return _Endpoint(_clean_host(host), None, valid=False)
    return _Endpoint(_clean_host(text))


def _strip_resource_suffix(value: str) -> str:
    end = len(value)
    for sep in ("/", "?", "#"):
        idx = value.find(sep)
        if idx != -1:
            end = min(end, idx)
    return value[:end]


def _parse_port(value: str) -> int | None:
    if not value.isdigit():
        return None
    port = int(value)
    if 0 < port <= 65535:
        return port
    return None


def _clean_host(value: str) -> str:
    return value.strip().strip("[]").rstrip(".")


def _cidr_match(target: str, rule: str) -> bool:
    try:
        network = ip_network(rule, strict=False)
        return ip_address(target) in network
    except ValueError:
        return False
