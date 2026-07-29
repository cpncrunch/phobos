from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import re

from .models import ActionRequest, EngagementROE, SafetyDecision


class EvidenceStore:
    def __init__(self, roe: EngagementROE):
        self.roe = roe
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "-", roe.name.strip()).strip("-").lower() or "engagement"
        self.root = Path(roe.evidence_dir) / safe_name
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "plans").mkdir(exist_ok=True)
        self._ensure_markdown_files()

    def record_decision(self, request: ActionRequest, decision: SafetyDecision) -> Path:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "engagement": self.roe.name,
            "request": request.to_dict(),
            "decision": decision.to_dict(),
        }
        path = self.root / "decisions.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self._append_command_log(request, decision)
        return path

    def write_plan(self, title: str, body: str) -> Path:
        safe_title = re.sub(r"[^a-zA-Z0-9_.-]+", "-", title.strip()).strip("-").lower() or "plan"
        path = self.root / "plans" / f"{safe_title}.md"
        path.write_text(body, encoding="utf-8")
        return path

    def _ensure_markdown_files(self) -> None:
        command_log = self.root / "command-log.md"
        if not command_log.exists():
            command_log.write_text(
                "# Command / Action Log\n\n"
                "| Time | Target | Command / Action | Purpose | Expected Result | Actual Result | Side Effects | Evidence Path | Cleanup |\n"
                "|---|---|---|---|---|---|---|---|---|\n",
                encoding="utf-8",
            )
        matrix = self.root / "evidence-matrix.md"
        if not matrix.exists():
            matrix.write_text(
                "# Evidence Matrix\n\n"
                "| Artifact | What It Proves | Affected Asset | Role/Access Used | Confidence | Missing Evidence |\n"
                "|---|---|---|---|---|---|\n",
                encoding="utf-8",
            )

    def _append_command_log(self, request: ActionRequest, decision: SafetyDecision) -> None:
        command = decision.redacted_command or request.action_type
        command = command.replace("|", "\\|").replace("\n", " ")
        purpose = request.purpose.replace("|", "\\|").replace("\n", " ")
        actual = f"Guardrail decision: {decision.status.value}; reasons: {'; '.join(decision.reasons)}"
        actual = actual.replace("|", "\\|").replace("\n", " ")
        row = (
            f"| {datetime.now(timezone.utc).isoformat()} | {request.target} | `{command}` | {purpose} | "
            f"Decision before execution | {actual} | None observed by harness | decisions.jsonl | N/A |\n"
        )
        with (self.root / "command-log.md").open("a", encoding="utf-8") as handle:
            handle.write(row)
