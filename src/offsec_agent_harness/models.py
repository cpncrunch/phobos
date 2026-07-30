from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
import json
import re


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


@dataclass(slots=True)
class EngagementROE:
    """Rules of engagement for an authorized assessment."""

    name: str
    authorized: bool
    in_scope_targets: list[str]
    allowed_techniques: list[str] = field(default_factory=list)
    prohibited_techniques: list[str] = field(default_factory=lambda: [
        "dos",
        "destructive",
        "persistence",
        "evasion",
        "malware",
    ])
    testing_window: str = "not specified"
    stop_conditions: list[str] = field(default_factory=lambda: [
        "Stop before destructive actions or denial-of-service conditions.",
        "Stop before accessing real customer/personal data unless explicitly authorized.",
        "Stop before persistence, stealth, evasion, or malware-like behavior.",
    ])
    evidence_dir: str = "evidence"
    safety_mode: str = "non_destructive"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementROE":
        return cls(**data)

    @classmethod
    def load(cls, path: str | Path) -> "EngagementROE":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n")


@dataclass(slots=True)
class ActionRequest:
    """A proposed test action or command."""

    target: str
    action_type: str
    purpose: str
    command: str | None = None
    actor: str = "operator"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SafetyDecision:
    status: DecisionStatus
    reasons: list[str] = field(default_factory=list)
    required_confirmations: list[str] = field(default_factory=list)
    safer_alternatives: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    redacted_command: str | None = None

    @property
    def executable(self) -> bool:
        return self.status is DecisionStatus.ALLOW

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


_SECRET_FIELD_PATTERN = (
    r"(?:x[_-]?(?:api[_-]?key|auth[_-]?token|csrf[_-]?token|xsrf[_-]?token)|"
    r"aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|"
    r"client[_-]?secret|clientsecret|private[_-]?key|proxy[_-]?authorization|"
    r"session[_-]?token|id[_-]?token|csrf[_-]?token|xsrf[_-]?token|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|password|passwd|pwd|token|secret)"
)

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM-style private keys may be pasted as evidence/config blocks; collapse the
    # entire block before assignment/header regexes can leave line fragments.
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE | re.DOTALL), "<REDACTED_PRIVATE_KEY>"),
    # Header/assignment formats first so values after auth schemes are not leaked.
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|digest|token)\s+)[^\s'\";,]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?!(?:bearer|basic|digest|token)\s+)[^\s'\";,]+"), r"\1<REDACTED>"),
    (re.compile(r"(?i)\b((?:cookie|set-cookie)\s*:\s*)[^\r\n'\"]+"), r"\1<REDACTED>"),
    (re.compile(rf"(?i)\b(({_SECRET_FIELD_PATTERN})\s*[:=]\s*)(['\"]?)[^\s'\";,]+\3"), r"\1\3<REDACTED>\3"),
    (re.compile(rf"(?i)(['\"]{_SECRET_FIELD_PATTERN}['\"]\s*:\s*['\"])[^'\"]+(['\"])",), r"\1<REDACTED>\2"),
    (re.compile(rf"(?i)(['\"]{_SECRET_FIELD_PATTERN}['\"]\s*:\s*)[^\s'\",}}]+"), r"\1<REDACTED>"),
]


def redact_secrets(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = value
    for pattern, repl in _SECRET_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted
