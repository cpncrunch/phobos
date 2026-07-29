from __future__ import annotations

from dataclasses import dataclass

from .models import ActionRequest, EngagementROE, SafetyDecision
from .scope import target_in_scope


@dataclass(slots=True)
class AgentNote:
    role: str
    summary: str
    details: list[str]


class ScopeROEAgent:
    role = "Scope / ROE agent"

    def review(self, roe: EngagementROE, request: ActionRequest) -> AgentNote:
        match = target_in_scope(request.target, roe.in_scope_targets)
        details = [match.reason]
        details.append(f"Testing window: {roe.testing_window}")
        details.extend(f"Stop condition: {item}" for item in roe.stop_conditions)
        return AgentNote(self.role, "Target is in scope." if match.in_scope else "Target is not in scope.", details)


class SafetyReviewer:
    role = "Safety / disruption reviewer"

    def review(self, decision: SafetyDecision) -> AgentNote:
        if decision.status.value == "allow":
            summary = "No major disruption guardrails matched; proceed dry-run or execute only with operator intent."
        elif decision.status.value == "confirm":
            summary = "Human ROE confirmation is required before execution."
        else:
            summary = "Action is blocked by scope or safety guardrails."
        details = decision.reasons + decision.required_confirmations + [f"Safer alternative: {a}" for a in decision.safer_alternatives]
        return AgentNote(self.role, summary, details)


class ImpactPlanner:
    role = "Impact chain analyst"

    def plan_from_finding(self, roe: EngagementROE, finding: str) -> str:
        stop_conditions = "\n".join(f"- {item}" for item in roe.stop_conditions)
        scope = ", ".join(roe.in_scope_targets)
        return f"""# Safe Impact Validation Plan

## Observed weakness

{finding}

## ROE assumptions

- Engagement: {roe.name}
- Authorized: {roe.authorized}
- In-scope targets: {scope}
- Testing window: {roe.testing_window}

## Minimum safe validation sequence

1. Reproduce the weakness using only in-scope systems and approved accounts.
2. Use controlled test objects or client-approved non-sensitive records.
3. Capture the original request/action and the modified request/action.
4. Capture the response or command output that proves the impact.
5. Run a negative control to show expected authorization or access boundaries.
6. Stop before bulk enumeration, destructive state changes, DoS, persistence, evasion, or accessing real customer/personal data.
7. Record cleanup performed or confirm no cleanup was required.

## Evidence to collect

- Account/role or initial access context.
- Exact affected asset, endpoint, object, host, or privilege relationship.
- Request/response pairs, command output, screenshots, or tool output.
- Negative control evidence.
- Timestamped command/action log.
- Redacted proof suitable for reporting.

## Stop conditions

{stop_conditions}

## Report-safe phrasing skeleton

Under the tested conditions, the assessment confirmed that `[role/access level]` could `[observed unauthorized action]` against `[controlled target/object]`. Testing was limited to controlled/in-scope assets and did not include high-volume activity, denial-of-service conditions, persistence, evasion, or destructive changes.
"""


class ReproductionWriter:
    role = "Reproduction writer"

    def write(self, finding: str) -> str:
        return f"""### Reproduction

1. Authenticate or operate as the tested role/access level.
2. Access the affected in-scope feature, host, endpoint, or object.
3. Perform the minimum action required to reproduce: {finding}
4. Observe and save the response/output demonstrating the issue.
5. Run a negative control where feasible.
6. Stop at proof of impact and avoid destructive or high-volume activity.

Expected result: The system should enforce the intended authorization, trust boundary, or hardening control.

Actual result: The observed behavior demonstrated the weakness described above.

Safety note: Testing should use controlled accounts/objects and remain within the ROE.
"""
