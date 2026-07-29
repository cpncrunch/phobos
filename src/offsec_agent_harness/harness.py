from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .agents import ImpactPlanner, ReproductionWriter, SafetyReviewer, ScopeROEAgent
from .evidence import EvidenceStore
from .guardrails import GuardrailEngine
from .models import ActionRequest, DecisionStatus, EngagementROE, SafetyDecision


@dataclass(slots=True)
class HarnessResult:
    request: ActionRequest
    decision: SafetyDecision
    evidence_path: str
    role_notes: list[dict[str, Any]]
    executed: bool = False
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "decision": self.decision.to_dict(),
            "evidence_path": self.evidence_path,
            "role_notes": self.role_notes,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class OffSecHarness:
    def __init__(self, roe: EngagementROE, guardrails: GuardrailEngine | None = None):
        self.roe = roe
        self.guardrails = guardrails or GuardrailEngine()
        self.store = EvidenceStore(roe)
        self.scope_agent = ScopeROEAgent()
        self.safety_agent = SafetyReviewer()
        self.impact_planner = ImpactPlanner()
        self.repro_writer = ReproductionWriter()

    def assess(self, request: ActionRequest, execute: bool = False, timeout: int = 30) -> HarnessResult:
        decision = self.guardrails.evaluate(self.roe, request)
        evidence_path = self.store.record_decision(request, decision)
        role_notes = [
            asdict(self.scope_agent.review(self.roe, request)),
            asdict(self.safety_agent.review(decision)),
        ]
        result = HarnessResult(request=request, decision=decision, evidence_path=str(evidence_path), role_notes=role_notes)
        if execute:
            if decision.status is not DecisionStatus.ALLOW:
                result.stderr = f"Refused to execute decision status {decision.status.value}."
            elif not request.command:
                result.stderr = "No command supplied for execution."
            else:
                completed = subprocess.run(
                    request.command,
                    shell=True,
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                )
                result.executed = True
                result.exit_code = completed.returncode
                result.stdout = completed.stdout[-4000:]
                result.stderr = completed.stderr[-4000:]
        return result

    def plan(self, finding: str) -> Path:
        body = self.impact_planner.plan_from_finding(self.roe, finding)
        body += "\n" + self.repro_writer.write(finding)
        return self.store.write_plan("safe-impact-validation", body)
