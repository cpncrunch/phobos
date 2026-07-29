from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import ActionRequest, DecisionStatus, EngagementROE, SafetyDecision, redact_secrets
from .scope import target_in_scope


@dataclass(frozen=True, slots=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]
    reason: str
    safer: str


BLOCK_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "destructive-filesystem",
        re.compile(r"(?i)\b(rm\s+-rf\s+/|mkfs\.|dd\s+if=|format\s+[a-z]:|del\s+/[fq]|shred\b|sdelete\b)"),
        "Command resembles destructive filesystem activity.",
        "Use read-only enumeration or a harmless proof file in a pre-approved test directory.",
    ),
    PatternRule(
        "service-disruption",
        re.compile(r"(?i)\b(reboot|shutdown|systemctl\s+(stop|restart)|service\s+\S+\s+(stop|restart)|killall\b)"),
        "Command could disrupt availability or restart services.",
        "Capture configuration/version evidence or request an approved maintenance window.",
    ),
    PatternRule(
        "persistence-or-backdoor",
        re.compile(r"(?i)\b(persistence|backdoor|implant|autorun|launchagent|schtasks\s+/create|reg\s+add\s+.*\\run\b)"),
        "Persistence/backdoor behavior is outside the safe harness scope.",
        "Document the privilege level and explain persistence risk without installing persistence.",
    ),
    PatternRule(
        "evasion-or-stealth",
        re.compile(r"(?i)\b(edr\s*bypass|av\s*bypass|amsi\s*bypass|disable-defender|set-mppreference\s+.*Disable|rootkit|stealth)"),
        "Evasion/stealth behavior is blocked.",
        "Use client-approved tooling and record detection/disruption considerations instead.",
    ),
    PatternRule(
        "dos-or-resource-exhaustion",
        re.compile(r"(?i)\b(slowloris|hping3|goldeneye|loic|--flood|-T5\b|--rate\s+\d{4,}|ffuf\b.*-t\s*\d{3,}|hydra\b.*-t\s*\d{2,})"),
        "Command resembles denial-of-service, brute force, or high-volume testing.",
        "Use a single-request proof, manual verification, scanner-safe mode, or obtain explicit DoS authorization.",
    ),
    PatternRule(
        "credential-dump-broad",
        re.compile(r"(?i)\b(lsass|ntds\.dit|secretsdump|samdump|mimikatz|procdump\b.*lsass)"),
        "Credential dumping is high-risk and may trigger EDR or collect excessive secrets.",
        "Use the minimum targeted proof permitted by ROE, with redacted evidence and cleanup tracking.",
    ),
)

CONFIRM_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "active-scan",
        re.compile(r"(?i)\b(nmap|masscan|naabu|nikto|nuclei|feroxbuster|gobuster|dirsearch|ffuf|wpscan)\b"),
        "Active scanning can create operational noise or volume.",
        "Prefer low-rate, in-window, in-scope scanning with explicit ROE approval and saved output.",
    ),
    PatternRule(
        "state-changing-http",
        re.compile(r"(?i)\b(curl|http)\b.*(?:-X\s*(POST|PUT|PATCH|DELETE)|--request\s*(POST|PUT|PATCH|DELETE))\b"),
        "HTTP method may change application state.",
        "Use controlled test accounts/objects, capture before/after state, and define cleanup.",
    ),
    PatternRule(
        "password-spray-bruteforce",
        re.compile(r"(?i)\b(password spray|spray|brute\s*force|kerbrute|crackmapexec|netexec\b.*--pass-pol)"),
        "Authentication testing may cause lockouts or high noise.",
        "Confirm lockout policy, rate limits, approved window, and test-user strategy first.",
    ),
)

NON_DESTRUCTIVE_CONFIRM_RULE_NAMES: frozenset[str] = frozenset({
    "state-changing-http",
    "password-spray-bruteforce",
})


class GuardrailEngine:
    """Authorization/scope/safety gate for proposed offsec actions."""

    def evaluate(self, roe: EngagementROE, request: ActionRequest) -> SafetyDecision:
        reasons: list[str] = []
        required: list[str] = []
        alternatives: list[str] = []
        status = DecisionStatus.ALLOW

        redacted_command = redact_secrets(request.command)

        if not roe.authorized:
            return SafetyDecision(
                status=DecisionStatus.BLOCK,
                reasons=["Engagement is not marked authorized."],
                safer_alternatives=["Create or load an ROE file with authorized=true and explicit in-scope targets."],
                stop_conditions=roe.stop_conditions,
                redacted_command=redacted_command,
            )

        scope = target_in_scope(request.target, roe.in_scope_targets)
        reasons.append(scope.reason)
        if not scope.in_scope:
            status = DecisionStatus.BLOCK
            alternatives.append("Choose a target explicitly listed in the ROE in_scope_targets field.")

        text = " ".join(filter(None, [request.action_type, request.purpose, request.command or ""])).strip()
        for rule in BLOCK_RULES:
            if rule.pattern.search(text):
                status = DecisionStatus.BLOCK
                reasons.append(rule.reason)
                alternatives.append(rule.safer)

        if status is not DecisionStatus.BLOCK:
            for rule in _confirm_rules_for_mode(roe.safety_mode):
                if rule.pattern.search(text):
                    status = DecisionStatus.CONFIRM
                    reasons.append(rule.reason)
                    required.append(f"Human/ROE approval required for: {rule.name}")
                    alternatives.append(rule.safer)

        technique_text = _normalize_technique_text(text)
        for technique in roe.prohibited_techniques:
            if technique and re.search(rf"(?i)\b{re.escape(technique)}\b", technique_text):
                status = DecisionStatus.BLOCK
                reasons.append(f"Prohibited technique appears in request: {technique}.")

        if not reasons:
            reasons.append("No guardrail concerns matched.")

        return SafetyDecision(
            status=status,
            reasons=_dedupe(reasons),
            required_confirmations=_dedupe(required),
            safer_alternatives=_dedupe(alternatives),
            stop_conditions=roe.stop_conditions,
            redacted_command=redacted_command,
        )


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _confirm_rules_for_mode(safety_mode: str) -> tuple[PatternRule, ...]:
    """Return confirmation rules for the engagement safety mode.

    The default `non_destructive` mode reflects an experienced tester workflow:
    routine active testing is allowed when in-scope and not destructive, while
    ambiguous state-changing or account-lockout-sensitive actions still require
    an operator decision. `standard` keeps the original conservative behavior.
    """
    normalized = (safety_mode or "non_destructive").strip().lower().replace("-", "_")
    if normalized == "standard":
        return CONFIRM_RULES
    if normalized == "non_destructive":
        return tuple(rule for rule in CONFIRM_RULES if rule.name in NON_DESTRUCTIVE_CONFIRM_RULE_NAMES)
    return CONFIRM_RULES


def _normalize_technique_text(text: str) -> str:
    # Do not let explicit safe-language such as "non-destructive" trip the
    # prohibited technique token "destructive".
    return re.sub(r"(?i)\bnon[-_\s]+destructive\b", "non_destructive", text)
