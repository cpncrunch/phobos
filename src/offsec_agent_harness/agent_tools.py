from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
import hashlib
import json
import mimetypes
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
import uuid
import zipfile

from .bloodhound import analyze_bloodhound
from .burp_mcp import BurpMCPClient, HTTPRequestArtifact, write_burp_artifacts
from .cve_advisor import CveAdvisor
from .harness import OffSecHarness
from .model_adapters import BaseModelAdapter, HeuristicAdapter
from .models import ActionRequest, DecisionStatus, EngagementROE, redact_secrets
from .reporting import FindingInput, FindingMarkdownExporter, safe_report_filename
from .agent_store import AgentStore, utc_now
from .agent_crypto import seal_bytes, unseal_bytes


_LIVE_PROCESSES: dict[int, subprocess.Popen] = {}


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolResult:
    status: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OffSecToolRegistry:
    """Tool registry for the standalone Phobos Agent runtime."""

    def __init__(
        self,
        roe: EngagementROE,
        store: AgentStore,
        session_id: str,
        model_adapter: BaseModelAdapter | None = None,
        workspace_dir: str | Path | None = None,
        default_timeout: int = 30,
        blocked_tools: tuple[str, ...] = (),
        confirm_tools: tuple[str, ...] = (),
    ):
        self.roe = roe
        self.harness = OffSecHarness(roe)
        self.store = store
        self.session_id = session_id
        self.model_adapter = model_adapter or HeuristicAdapter()
        self.default_timeout = default_timeout
        self.blocked_tools = {name.strip() for name in blocked_tools if name.strip()}
        self.confirm_tools = {name.strip() for name in confirm_tools if name.strip()}
        self._policy_bypass_tools = {"approve", "deny", "list_approvals", "tool_schemas", "runtime_status", "audit_log"}
        self.workspace_root = Path(workspace_dir) if workspace_dir else self.harness.store.root / "agent" / "workspace"
        if not self.workspace_root.is_absolute():
            self.workspace_root = (self.harness.store.root / self.workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.tools: dict[str, Callable[[dict[str, Any]], ToolResult]] = {}
        self.tool_specs: dict[str, ToolSpec] = {}
        self._register_builtins()

    def register_tool(self, name: str, handler: Callable[[dict[str, Any]], ToolResult], spec: ToolSpec | dict[str, Any] | None = None) -> None:
        self.tools[name] = handler
        if isinstance(spec, ToolSpec):
            self.tool_specs[name] = spec
            return
        if isinstance(spec, dict):
            self.tool_specs[name] = ToolSpec(name=name, description=str(spec.get("description", name)), schema=dict(spec.get("schema", {})))
            return
        self.tool_specs[name] = ToolSpec(name=name, description=name)

    def specs(self) -> list[ToolSpec]:
        return [self.tool_specs[name] for name in sorted(self.tool_specs)]

    def run(self, name: str, args: dict[str, Any]) -> ToolResult:
        if name not in self.tools:
            return ToolResult("error", f"Unknown tool: {name}", {"available": [spec.name for spec in self.specs()]})
        if name in self.blocked_tools and name not in self._policy_bypass_tools:
            result = ToolResult("blocked", f"Tool {name} is blocked by runtime policy.", {"tool": name})
            self.store.audit(self.session_id, "tool_blocked", {"tool": name, "args": _safe_json(args)})
            return result
        if name in self.confirm_tools and name not in self._policy_bypass_tools and not args.get("_policy_approved", False):
            approval_id = self.store.create_approval(self.session_id, name, args, {"status": "confirm", "reason": "Tool requires approval by runtime policy."})
            result = ToolResult("needs_approval", f"Tool {name} requires approval before execution. Approval ID: {approval_id}", {"approval_id": approval_id, "tool": name})
            self.store.audit(self.session_id, "tool_policy_confirm", {"tool": name, "approval_id": approval_id, "args": _safe_json(args)})
            return result
        self.store.audit(self.session_id, "tool_call", {"tool": name, "args": _safe_json(args)})
        try:
            result = self.tools[name](args)
        except Exception as exc:  # defensive tool boundary; details are audit-visible but bounded
            result = ToolResult("error", f"{name} failed: {exc}")
        self.store.audit(self.session_id, "tool_result", {"tool": name, "result": result.to_dict()})
        return result

    def _register_builtins(self) -> None:
        self.register_tool("assess_action", self.assess_action, _spec("assess_action", "Evaluate a proposed action/command against ROE guardrails without executing it.", {
            "target": _string("Target host/IP/URL in the engagement scope."),
            "type": _string("Action type, e.g. host, web, api, service-enumeration."),
            "purpose": _string("Why the action is being performed."),
            "command": _string("Command/action text to assess."),
        }, ["target", "purpose", "command"]))
        self.register_tool("run_command", self.run_command, _spec("run_command", "Run a short shell command through ROE guardrails; confirm-level actions are queued for approval.", {
            "target": _string("In-scope target or local artifact context."),
            "type": _string("Action type."),
            "purpose": _string("Purpose for audit/evidence."),
            "command": _string("Shell command."),
            "execute": {"type": "boolean", "description": "Must be true to execute; false returns dry-run."},
            "timeout": {"type": "integer", "description": "Foreground timeout in seconds."},
        }, ["target", "purpose", "command"]))
        self.register_tool("start_process", self.start_process, _spec("start_process", "Start a guarded background process and capture stdout/stderr logs.", {
            "target": _string("In-scope target or local artifact context."),
            "type": _string("Action type."),
            "purpose": _string("Purpose for audit/evidence."),
            "command": _string("Shell command to run in the background."),
            "execute": {"type": "boolean", "description": "Must be true to start."},
        }, ["target", "purpose", "command"]))
        self.register_tool("poll_process", self.poll_process, _spec("poll_process", "Poll a background process status.", {"id": {"type": "integer"}}, ["id"]))
        self.register_tool("wait_process", self.wait_process, _spec("wait_process", "Wait up to timeout seconds for a background process to complete, then return status and log tails.", {"id": {"type": "integer"}, "timeout": {"type": "integer"}, "limit": {"type": "integer"}}, ["id"]))
        self.register_tool("process_log", self.process_log, _spec("process_log", "Read redacted stdout/stderr tails for a background process.", {"id": {"type": "integer"}, "limit": {"type": "integer"}}, ["id"]))
        self.register_tool("kill_process", self.kill_process, _spec("kill_process", "Terminate a tracked background process.", {"id": {"type": "integer"}}, ["id"]))
        self.register_tool("list_processes", self.list_processes, _spec("list_processes", "List tracked background processes for the current session.", {"limit": {"type": "integer"}}))
        self.register_tool("approve", self.approve, _spec("approve", "Approve and execute/start a pending confirm-level action.", {"id": {"type": "integer"}}, ["id"]))
        self.register_tool("deny", self.deny, _spec("deny", "Deny a pending approval.", {"id": {"type": "integer"}, "reason": _string("Reason for audit log.")}, ["id"]))
        self.register_tool("impact_plan", self.impact_plan, _spec("impact_plan", "Generate a safe impact-validation plan from an observed finding.", {"finding": _string("Observed weakness or finding draft.")}, ["finding"]))
        self.register_tool("burp_tab", self.burp_tab, _spec("burp_tab", "Create/save Burp Repeater request artifacts and optionally call Burp MCP.", {"request_file": _string("Raw HTTP request artifact path."), "target": _string("In-scope target."), "tab_name": _string("Repeater tab/artifact name."), "create": {"type": "boolean"}}))
        self.register_tool("bloodhound_import", self.bloodhound_import, _spec("bloodhound_import", "Offline BloodHound/ADCS graph analysis.", {"input": _string("BloodHound JSON/dir/zip."), "principal": _string("Optional principal to path from.")}))
        self.register_tool("cve_advice", self.cve_advice, _spec("cve_advice", "CVE candidate review with non-invasive validation guidance.", {"component": _string("Product/component name."), "version": _string("Observed version."), "catalog": _string("Local CVE catalog JSON."), "online": {"type": "boolean"}}))
        self.register_tool("export_finding", self.export_finding, _spec("export_finding", "Report-ready finding Markdown exporter.", {"finding_file": _string("Finding JSON path."), "out": _string("Optional output path.")}))
        self.register_tool("remember", self.remember, _spec("remember", "Store local agent memory in SQLite.", {"key": _string("Memory key."), "value": _string("Memory value."), "tags": _string("Optional comma tags.")}, ["key", "value"]))
        self.register_tool("recall", self.recall, _spec("recall", "Search local agent memory.", {"query": _string("Memory search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("search_session", self.search_session, _spec("search_session", "Search current-session messages.", {"query": _string("Message search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("search_all_sessions", self.search_all_sessions, _spec("search_all_sessions", "Search messages across all local Phobos sessions in this DB.", {"query": _string("Message search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("context_snapshot", self.context_snapshot, _spec("context_snapshot", "Return latest compact summary, recent messages, and relevant memory.", {"query": _string("Optional relevance query."), "limit": {"type": "integer"}}))
        self.register_tool("compact_context", self.compact_context, _spec("compact_context", "Summarize recent session messages into durable local context.", {"limit": {"type": "integer"}}))
        self.register_tool("context_compact_node", self.context_compact_node, _spec("context_compact_node", "Create an LCM-style context node from recent messages and optionally roll child nodes into a parent.", {"limit": {"type": "integer"}, "title": _string("Optional node title."), "parent": {"type": "boolean"}}, []))
        self.register_tool("context_describe", self.context_describe, _spec("context_describe", "Describe local LCM-style context nodes without expanding full sources.", {"id": {"type": "integer"}, "limit": {"type": "integer"}}, []))
        self.register_tool("context_expand", self.context_expand, _spec("context_expand", "Expand a local context node and recover its source messages/child summaries.", {"id": {"type": "integer"}, "source_limit": {"type": "integer"}}, ["id"]))
        self.register_tool("context_query", self.context_query, _spec("context_query", "Search memories, session history, and LCM-style context nodes, then synthesize an answer.", {"query": _string("Question or recall query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("reflect_memory", self.reflect_memory, _spec("reflect_memory", "Synthesize an answer from local memories and session/context recall without executing tools.", {"query": _string("Question to answer from memory/context."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("workspace_read", self.workspace_read, _spec("workspace_read", "Read a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "limit": {"type": "integer"}}, ["path"]))
        self.register_tool("workspace_write", self.workspace_write, _spec("workspace_write", "Write or append a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "content": _string("Text content."), "append": {"type": "boolean"}}, ["path", "content"]))
        self.register_tool("workspace_search", self.workspace_search, _spec("workspace_search", "Search text files inside the engagement workspace.", {"query": _string("Substring/regex query."), "glob": _string("Glob like **/*.md."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("workspace_patch", self.workspace_patch, _spec("workspace_patch", "Targeted text replacement inside a workspace file.", {"path": _string("Workspace-relative path."), "old": _string("Text to replace."), "new": _string("Replacement text."), "replace_all": {"type": "boolean"}}, ["path", "old", "new"]))
        self.register_tool("schedule_job", self.schedule_job, _spec("schedule_job", "Create a local scheduled job; run with run_due_jobs or external cron.", {"name": _string("Job name."), "schedule": _string("manual/every 15 m/every 1 h."), "prompt": _string("Agent prompt to run.")}))
        self.register_tool("list_jobs", self.list_jobs, _spec("list_jobs", "List scheduled jobs.", {}))
        self.register_tool("run_due_jobs", self.run_due_jobs, _spec("run_due_jobs", "List due jobs from tool-only context; runtime executes them.", {}))
        self.register_tool("subagent_review", self.subagent_review, _spec("subagent_review", "Run parallel role reviews using the configured model adapter.", {"prompt": _string("Task/finding to review."), "roles": _string("Comma-separated roles."), "context": _string("Optional context.")}))
        self.register_tool("delegate_tasks", self.delegate_tasks, _spec("delegate_tasks", "Run bounded local pseudo-subagent tasks in parallel and persist their artifacts.", {"prompt": _string("Overall task."), "tasks": _string("JSON/list or newline-separated task prompts."), "roles": _string("Comma roles when tasks is omitted.")}, []))
        self.register_tool("list_delegations", self.list_delegations, _spec("list_delegations", "List durable local delegation batches.", {"limit": {"type": "integer"}}, []))
        self.register_tool("auth_status", self.auth_status, _spec("auth_status", "Check model/provider and bridge token environment variables without revealing secret values.", {"include_environment": {"type": "boolean"}}, []))
        self.register_tool("media_import", self.media_import, _spec("media_import", "Copy an operator-supplied local media/artifact file into evidence with hash metadata.", {"path": _string("Source file path."), "kind": _string("image/audio/video/file; inferred when omitted.")}, ["path"]))
        self.register_tool("media_list", self.media_list, _spec("media_list", "List imported media/artifact files for this session.", {"limit": {"type": "integer"}}, []))
        self.register_tool("sealed_export", self.sealed_export, _spec("sealed_export", "Create an authenticated encrypted portable snapshot from a session handoff or pack.", {"passphrase_env": _string("Environment variable containing passphrase."), "out": _string("Optional output .sealed.json path."), "include_pack": {"type": "boolean"}}, ["passphrase_env"]))
        self.register_tool("sealed_import", self.sealed_import, _spec("sealed_import", "Decrypt a sealed session snapshot and import its handoff data; no commands are executed.", {"path": _string("Sealed snapshot path."), "passphrase_env": _string("Environment variable containing passphrase."), "merge_memories": {"type": "boolean"}}, ["path", "passphrase_env"]))
        self.register_tool("list_approvals", self.list_approvals, _spec("list_approvals", "List pending approvals.", {"status": _string("Approval status; default pending.")}))
        self.register_tool("tool_schemas", self.tool_schemas, _spec("tool_schemas", "Return JSON-style schemas for available tools.", {"name": _string("Optional tool name.")}))
        self.register_tool("audit_log", self.audit_log, _spec("audit_log", "List recent redacted audit log entries.", {"limit": {"type": "integer"}}))
        self.register_tool("runtime_status", self.runtime_status, _spec("runtime_status", "Return runtime health, schema, workspace, tool, approval, job, and process counts.", {}))
        self.register_tool("export_pack", self.export_pack, _spec("export_pack", "Create a redacted engagement pack ZIP containing evidence, runtime state, and a manifest.", {"out": _string("Optional ZIP output path; relative paths are written under agent/exports.")}))
        self.register_tool("operator_briefing", self.operator_briefing, _spec("operator_briefing", "Create a Hermes-like operator briefing from context, tasks, approvals, jobs, processes, and recent evidence.", {"query": _string("Optional recall query for relevant memory."), "out": _string("Optional Markdown output path.")}))
        self.register_tool("export_session", self.export_session, _spec("export_session", "Export a redacted portable session handoff JSON bundle.", {"out": _string("Optional JSON output path; relative paths are written under agent/session-exports."), "message_limit": {"type": "integer"}}))
        self.register_tool("import_session", self.import_session, _spec("import_session", "Import memories and context summary from a portable session handoff JSON bundle; no commands are executed.", {"path": _string("Path to exported session JSON."), "merge_memories": {"type": "boolean"}}, ["path"]))
        self.register_tool("list_tasks", self.list_tasks, _spec("list_tasks", "List the current session task board.", {"status": _string("Filter by pending/in_progress/completed/cancelled/all."), "limit": {"type": "integer"}}))
        self.register_tool("add_task", self.add_task, _spec("add_task", "Add an item to the current session task board.", {"content": _string("Task description."), "status": _string("pending/in_progress/completed/cancelled; default pending.")}, ["content"]))
        self.register_tool("update_task", self.update_task, _spec("update_task", "Update a task board item by id.", {"id": {"type": "integer"}, "content": _string("Optional replacement content."), "status": _string("pending/in_progress/completed/cancelled.")}, ["id"]))

    def assess_action(self, args: dict[str, Any]) -> ToolResult:
        request = _request_from_args(args)
        result = self.harness.assess(request, execute=False)
        status = result.decision.status.value
        return ToolResult(status, f"Guardrail decision: {status}", result.to_dict(), {"decision_log": result.evidence_path})

    def run_command(self, args: dict[str, Any]) -> ToolResult:
        request = _request_from_args(args)
        timeout = int(args.get("timeout", self.default_timeout))
        decision = self.harness.guardrails.evaluate(self.roe, request)
        evidence_path = self.harness.store.record_decision(request, decision)
        if decision.status is DecisionStatus.BLOCK:
            return ToolResult("blocked", "Command blocked by guardrails.", {"decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        if decision.status is DecisionStatus.CONFIRM and not args.get("_approved", False):
            approval_id = self.store.create_approval(self.session_id, "run_command", args, decision.to_dict())
            return ToolResult("needs_approval", f"Command requires approval before execution. Approval ID: {approval_id}", {"approval_id": approval_id, "decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        if not args.get("execute", False):
            return ToolResult("dry_run", "Command allowed but not executed; pass execute=true to run.", {"decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        return self._execute_allowed_command(request, timeout=timeout, approval_id=args.get("_approval_id"))

    def start_process(self, args: dict[str, Any], approval_id: int | None = None) -> ToolResult:
        request = _request_from_args(args)
        decision = self.harness.guardrails.evaluate(self.roe, request)
        evidence_path = self.harness.store.record_decision(request, decision)
        if decision.status is DecisionStatus.BLOCK:
            return ToolResult("blocked", "Background process blocked by guardrails.", {"decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        if decision.status is DecisionStatus.CONFIRM and not args.get("_approved", False):
            queued_id = self.store.create_approval(self.session_id, "start_process", args, decision.to_dict())
            return ToolResult("needs_approval", f"Background process requires approval before start. Approval ID: {queued_id}", {"approval_id": queued_id, "decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        if not args.get("execute", False):
            return ToolResult("dry_run", "Background process allowed but not started; pass execute=true to start.", {"decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        if not request.command:
            return ToolResult("error", "No command supplied.")
        run_key = uuid.uuid4().hex[:10]
        out_dir = self.harness.store.root / "agent" / "processes"
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = out_dir / f"process-{run_key}.stdout.log"
        stderr_path = out_dir / f"process-{run_key}.stderr.log"
        rc_path = out_dir / f"process-{run_key}.rc"
        process_id = self.store.create_process(
            self.session_id,
            redact_secrets(request.command),
            request.target,
            request.action_type,
            request.purpose,
            str(stdout_path),
            str(stderr_path),
            str(rc_path),
            decision.to_dict(),
            approval_id=approval_id,
        )
        wrapper = f"{request.command}\nstatus=$?\nprintf '%s\\n' \"$status\" > {shlex.quote(str(rc_path))}\nexit \"$status\""
        stdout_handle = stdout_path.open("ab")
        stderr_handle = stderr_path.open("ab")
        try:
            proc = subprocess.Popen(["bash", "-lc", wrapper], stdout=stdout_handle, stderr=stderr_handle, start_new_session=True)
        finally:
            stdout_handle.close()
            stderr_handle.close()
        self.store.update_process(process_id, pid=proc.pid, status="running")
        _LIVE_PROCESSES[process_id] = proc
        return ToolResult("started", f"Background process {process_id} started with pid {proc.pid}.", {"process_id": process_id, "pid": proc.pid, "decision": decision.to_dict()}, {"stdout": str(stdout_path), "stderr": str(stderr_path), "return_code": str(rc_path), "decision_log": str(evidence_path)})

    def poll_process(self, args: dict[str, Any]) -> ToolResult:
        process = self._refresh_process(int(args.get("id") or args.get("process_id")))
        if not process:
            return ToolResult("error", "Process not found.")
        return ToolResult(process["status"], f"Process {process['id']} is {process['status']}.", {"process": process})

    def wait_process(self, args: dict[str, Any]) -> ToolResult:
        process_id = int(args.get("id") or args.get("process_id"))
        deadline = time.monotonic() + max(0, int(args.get("timeout", 30)))
        process = self._refresh_process(process_id)
        while process and process.get("status") in {"running", "starting"} and time.monotonic() < deadline:
            time.sleep(0.05)
            process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", "Process not found.")
        log = self.process_log({"id": process_id, "limit": int(args.get("limit", 4000))})
        return ToolResult(process["status"], f"Process {process_id} wait ended with status {process['status']}.", {"process": process, "stdout": log.data.get("stdout", ""), "stderr": log.data.get("stderr", "")})

    def process_log(self, args: dict[str, Any]) -> ToolResult:
        process = self._refresh_process(int(args.get("id") or args.get("process_id")))
        if not process:
            return ToolResult("error", "Process not found.")
        limit = int(args.get("limit", 4000))
        stdout = redact_secrets(_tail(Path(process["stdout_path"]), limit))
        stderr = redact_secrets(_tail(Path(process["stderr_path"]), limit))
        return ToolResult("ok", f"Process {process['id']} log tails.", {"process": process, "stdout": stdout, "stderr": stderr})

    def kill_process(self, args: dict[str, Any]) -> ToolResult:
        process = self._refresh_process(int(args.get("id") or args.get("process_id")))
        if not process:
            return ToolResult("error", "Process not found.")
        pid = process.get("pid")
        if process.get("status") not in {"running", "starting"} or not pid:
            return ToolResult("ok", f"Process {process['id']} is already {process.get('status')}.", {"process": process})
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        self.store.update_process(int(process["id"]), status="killed", ended_at=utc_now())
        process = self.store.get_process(int(process["id"])) or process
        return ToolResult("killed", f"Process {process['id']} terminated.", {"process": process})

    def list_processes(self, args: dict[str, Any]) -> ToolResult:
        rows = [self._refresh_process(int(row["id"])) or row for row in self.store.list_processes(self.session_id, limit=int(args.get("limit", 20)))]
        return ToolResult("ok", f"Found {len(rows)} processes.", {"processes": rows})

    def approve(self, args: dict[str, Any]) -> ToolResult:
        approval_id = int(args.get("id") or args.get("approval_id"))
        approval = self.store.get_approval(approval_id)
        if not approval:
            return ToolResult("error", f"Approval {approval_id} not found.")
        if approval["status"] != "pending":
            return ToolResult("error", f"Approval {approval_id} is already {approval['status']}.", approval)
        if approval["tool_name"] == "run_command":
            approved_args = dict(approval["args"])
            approved_args["_approved"] = True
            approved_args["_approval_id"] = approval_id
            request = _request_from_args(approved_args)
            decision = self.harness.guardrails.evaluate(self.roe, request)
            if decision.status is DecisionStatus.BLOCK:
                self.store.resolve_approval(approval_id, "blocked_on_recheck", args.get("by", "operator"), {"decision": decision.to_dict()})
                return ToolResult("blocked", "Approval was blocked on re-check; command was not executed.", {"decision": decision.to_dict()})
            result = self.run_command(approved_args)
            self.store.resolve_approval(approval_id, "approved_executed", args.get("by", "operator"), result.to_dict())
            return result
        if approval["tool_name"] == "start_process":
            approved_args = dict(approval["args"])
            approved_args["_approved"] = True
            approved_args["_approval_id"] = approval_id
            decision = self.harness.guardrails.evaluate(self.roe, _request_from_args(approved_args))
            if decision.status is DecisionStatus.BLOCK:
                self.store.resolve_approval(approval_id, "blocked_on_recheck", args.get("by", "operator"), {"decision": decision.to_dict()})
                return ToolResult("blocked", "Approval was blocked on re-check; process was not started.", {"decision": decision.to_dict()})
            result = self.start_process(approved_args, approval_id=approval_id)
            self.store.resolve_approval(approval_id, "approved_started", args.get("by", "operator"), result.to_dict())
            return result
        if approval["tool_name"] in self.tools:
            approved_args = dict(approval["args"])
            approved_args["_policy_approved"] = True
            result = self.run(approval["tool_name"], approved_args)
            self.store.resolve_approval(approval_id, "approved_executed", args.get("by", "operator"), result.to_dict())
            return result
        self.store.resolve_approval(approval_id, "approved", args.get("by", "operator"), {"note": "Approved non-command tool."})
        return ToolResult("approved", f"Approval {approval_id} approved.")

    def deny(self, args: dict[str, Any]) -> ToolResult:
        approval_id = int(args.get("id") or args.get("approval_id"))
        approval = self.store.get_approval(approval_id)
        if not approval:
            return ToolResult("error", f"Approval {approval_id} not found.")
        self.store.resolve_approval(approval_id, "denied", args.get("by", "operator"), {"reason": args.get("reason", "")})
        return ToolResult("denied", f"Approval {approval_id} denied.")

    def impact_plan(self, args: dict[str, Any]) -> ToolResult:
        path = self.harness.plan(str(args.get("finding", "")))
        return ToolResult("ok", f"Plan written: {path}", {"plan_path": str(path)}, {"plan": str(path)})

    def burp_tab(self, args: dict[str, Any]) -> ToolResult:
        request_file = args.get("request_file")
        if not request_file:
            return ToolResult("error", "request_file is required.")
        target = str(args.get("target", ""))
        tab_name = str(args.get("tab_name", "burp-tab"))
        http_request = HTTPRequestArtifact.load(request_file)
        guard_request = ActionRequest(
            target=target,
            action_type="web",
            purpose=f"Create Burp Repeater tab {tab_name!r} for saved {http_request.method} {http_request.path}; no target request is sent by the harness.",
            command=f"burp-mcp create_repeater_tab {tab_name}",
        )
        decision = self.harness.guardrails.evaluate(self.roe, guard_request)
        self.harness.store.record_decision(guard_request, decision)
        mcp_result: dict[str, Any] = {"skipped": "dry-run; create=true not supplied"}
        status = "ok"
        if decision.status is DecisionStatus.BLOCK:
            status = "blocked"
            mcp_result = {"skipped": "blocked by guardrails"}
        elif args.get("create", False):
            client = BurpMCPClient(str(args.get("mcp_url")), host_header=args.get("host_header"), timeout=float(args.get("timeout", 10.0)))
            mcp_result = client.create_repeater_tab(tab_name, http_request)
        artifacts = write_burp_artifacts(self.harness.store.root, tab_name, http_request, result=mcp_result)
        return ToolResult(status, f"Burp artifacts written for {tab_name}.", {"decision": decision.to_dict(), "mcp_result": mcp_result}, artifacts)

    def bloodhound_import(self, args: dict[str, Any]) -> ToolResult:
        analysis = analyze_bloodhound(str(args.get("input")), principal=args.get("principal"))
        out = Path(args.get("out") or (self.harness.store.root / "ad" / "bloodhound-analysis.md"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(analysis.to_markdown(), encoding="utf-8")
        return ToolResult("ok", f"BloodHound analysis written: {out}", analysis.to_dict(), {"markdown": str(out)})

    def cve_advice(self, args: dict[str, Any]) -> ToolResult:
        advice = CveAdvisor.from_catalog_file(args.get("catalog")).advise(
            str(args.get("component", "")), version=str(args.get("version", "")), evidence=str(args.get("evidence", "")), online=bool(args.get("online", False))
        )
        out = Path(args.get("out") or (self.harness.store.root / "cve" / f"{safe_report_filename(str(args.get('component', 'component')))}.md"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(advice.to_markdown(), encoding="utf-8")
        return ToolResult("ok", f"CVE advice written: {out}", advice.to_dict(), {"markdown": str(out)})

    def export_finding(self, args: dict[str, Any]) -> ToolResult:
        finding = FindingInput.load(str(args.get("finding_file")))
        out = Path(args.get("out") or (self.harness.store.root / "reports" / f"{safe_report_filename(finding.title)}.md"))
        path = FindingMarkdownExporter().write_finding(finding, out)
        return ToolResult("ok", f"Finding draft written: {path}", finding.to_dict(), {"markdown": str(path)})

    def remember(self, args: dict[str, Any]) -> ToolResult:
        key = str(args.get("key", "")).strip()
        value = str(args.get("value", "")).strip()
        if not key or not value:
            return ToolResult("error", "remember requires key and value.")
        mem_id = self.store.remember(key, value, tags=str(args.get("tags", "")))
        return ToolResult("ok", f"Stored memory {mem_id}: {key}", {"id": mem_id, "key": key})

    def recall(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.recall(str(args.get("query", "")), limit=int(args.get("limit", 10)))
        return ToolResult("ok", f"Found {len(rows)} memory entries.", {"memories": rows})

    def search_session(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.search_messages(self.session_id, str(args.get("query", "")), limit=int(args.get("limit", 10)))
        return ToolResult("ok", f"Found {len(rows)} session messages.", {"messages": rows})

    def search_all_sessions(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.search_all_messages(str(args.get("query", "")), limit=int(args.get("limit", 10)))
        return ToolResult("ok", f"Found {len(rows)} message(s) across local sessions.", {"messages": rows})

    def context_snapshot(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", ""))
        limit = int(args.get("limit", 8))
        data = {
            "summary": self.store.latest_context_summary(self.session_id),
            "recent_messages": self.store.recent_messages(self.session_id, limit=limit),
            "memories": self.store.recall(query, limit=5) if query else [],
            "workspace": str(self.workspace_root),
        }
        return ToolResult("ok", "Context snapshot assembled.", data)

    def compact_context(self, args: dict[str, Any]) -> ToolResult:
        messages = self.store.recent_messages(self.session_id, limit=int(args.get("limit", 40)))
        if not messages:
            return ToolResult("ok", "No messages to compact.", {"summary_id": None})
        serialized = redact_secrets("\n".join(f"{row['id']} {row['role']}: {row['content']}" for row in messages)) or ""
        prompt = "Summarize this Phobos Agent session for future continuity. Preserve scope, decisions, evidence paths, approvals, jobs, and open tasks.\n\n" + serialized
        summary = redact_secrets(self.model_adapter.generate("evidence", prompt).content) or ""
        summary_id = self.store.create_context_summary(self.session_id, messages[0]["id"], messages[-1]["id"], summary)
        out = self.harness.store.root / "agent" / f"context-summary-{summary_id}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(summary, encoding="utf-8")
        return ToolResult("ok", f"Context summary {summary_id} written.", {"summary_id": summary_id, "summary": summary}, {"markdown": str(out)})

    def context_compact_node(self, args: dict[str, Any]) -> ToolResult:
        messages = self.store.recent_messages(self.session_id, limit=int(args.get("limit", 60)))
        if not messages:
            return ToolResult("ok", "No messages to compact into a context node.", {"node_id": None})
        title = str(args.get("title") or f"Session context {messages[0]['id']}-{messages[-1]['id']}")
        serialized = redact_secrets("\n".join(f"{row['id']} {row['role']}: {row['content']}" for row in messages)) or ""
        prompt = "Create an LCM-style Phobos context node. Preserve task state, decisions, evidence paths, scope constraints, approvals, and unresolved questions.\n\n" + serialized
        summary = redact_secrets(self.model_adapter.generate("evidence", prompt).content) or ""
        sources = [{"type": "message", "id": row["id"], "role": row["role"], "created_at": row["created_at"]} for row in messages]
        node_id = self.store.create_context_node(self.session_id, title, summary, sources, depth=0, metadata={"kind": "message_compaction", "source_from": messages[0]["id"], "source_to": messages[-1]["id"]})
        artifacts = {"markdown": str(_write_context_node_artifact(self.harness.store.root, node_id, title, summary))}
        parent_id: int | None = None
        if args.get("parent", False):
            children = self.store.list_context_nodes(self.session_id, limit=int(args.get("child_limit", 6)))
            child_lines = "\n\n".join(f"Node {child['id']} depth={child['depth']} title={child['title']}\n{child['summary']}" for child in reversed(children))
            parent_summary = redact_secrets(self.model_adapter.generate("evidence", "Roll these Phobos context nodes into a higher-level continuity summary.\n\n" + child_lines).content) or ""
            parent_sources = [{"type": "context_node", "id": child["id"], "title": child["title"]} for child in children]
            parent_id = self.store.create_context_node(self.session_id, f"Rollup through node {node_id}", parent_summary, parent_sources, depth=1, metadata={"kind": "rollup", "child_count": len(children)})
            artifacts["parent_markdown"] = str(_write_context_node_artifact(self.harness.store.root, parent_id, f"Rollup through node {node_id}", parent_summary))
        return ToolResult("ok", f"Context node {node_id} written.", {"node_id": node_id, "parent_id": parent_id, "summary": summary, "sources": sources}, artifacts)

    def context_describe(self, args: dict[str, Any]) -> ToolResult:
        node_arg = args.get("id") or args.get("node_id")
        if node_arg:
            node = self.store.get_context_node(int(node_arg))
            if not node:
                return ToolResult("error", f"Context node {node_arg} not found.")
            children = self.store.child_context_nodes(int(node_arg))
            preview = dict(node)
            preview["summary_preview"] = preview.pop("summary")[:1000]
            preview["source_count"] = len(node.get("sources", []))
            return ToolResult("ok", f"Context node {node_arg} described.", {"node": preview, "children": children})
        nodes = self.store.list_context_nodes(self.session_id, limit=int(args.get("limit", 20)))
        previews = []
        for node in nodes:
            previews.append({"id": node["id"], "parent_id": node["parent_id"], "depth": node["depth"], "title": node["title"], "source_count": len(node.get("sources", [])), "summary_preview": node["summary"][:500], "created_at": node["created_at"]})
        return ToolResult("ok", f"Found {len(previews)} context node(s).", {"nodes": previews})

    def context_expand(self, args: dict[str, Any]) -> ToolResult:
        node_id = int(args.get("id") or args.get("node_id"))
        node = self.store.get_context_node(node_id)
        if not node:
            return ToolResult("error", f"Context node {node_id} not found.")
        source_limit = int(args.get("source_limit", 40))
        expanded_sources = []
        for source in node.get("sources", [])[:source_limit]:
            if source.get("type") == "message":
                message = self.store.get_message(int(source.get("id")))
                if message:
                    expanded_sources.append({"type": "message", "message": _redacted_mapping(message)})
            elif source.get("type") == "context_node":
                child = self.store.get_context_node(int(source.get("id")))
                if child:
                    expanded_sources.append({"type": "context_node", "node": {"id": child["id"], "title": child["title"], "summary": redact_secrets(child["summary"])}})
        return ToolResult("ok", f"Context node {node_id} expanded.", {"node": _redacted_mapping(node), "expanded_sources": expanded_sources})

    def context_query(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", "")).strip()
        if not query:
            return ToolResult("error", "query is required.")
        limit = int(args.get("limit", 8))
        memories = self.store.recall(query, limit=limit)
        messages = self.store.search_messages(self.session_id, query, limit=limit)
        nodes = self.store.search_context_nodes(self.session_id, query, limit=limit)
        context = json.dumps(_redact_value({"memories": memories, "messages": messages, "context_nodes": nodes}), indent=2)[:16000]
        answer = redact_secrets(self.model_adapter.generate("evidence", f"Answer this from the supplied Phobos local context only. If evidence is missing, say what is missing.\n\nQuestion: {query}", context=context).content)
        return ToolResult("ok", "Context query answered from local memory/session/context nodes.", {"answer": answer, "memories": memories, "messages": messages, "context_nodes": nodes})

    def reflect_memory(self, args: dict[str, Any]) -> ToolResult:
        return self.context_query(args)

    def workspace_read(self, args: dict[str, Any]) -> ToolResult:
        path = self._workspace_path(str(args.get("path", "")))
        if not path.exists() or not path.is_file():
            return ToolResult("error", f"Workspace file not found: {path.relative_to(self.workspace_root)}")
        text = path.read_text(encoding="utf-8", errors="replace")
        limit = int(args.get("limit", 12000))
        return ToolResult("ok", f"Read {path.relative_to(self.workspace_root)}.", {"path": str(path), "content": text[:limit], "truncated": len(text) > limit})

    def workspace_write(self, args: dict[str, Any]) -> ToolResult:
        path = self._workspace_path(str(args.get("path", "")))
        content = str(args.get("content", ""))
        path.parent.mkdir(parents=True, exist_ok=True)
        if args.get("append", False):
            with path.open("a", encoding="utf-8") as handle:
                handle.write(content)
        else:
            path.write_text(content, encoding="utf-8")
        return ToolResult("ok", f"Wrote {path.relative_to(self.workspace_root)}.", {"path": str(path), "bytes": len(content.encode('utf-8'))}, {"file": str(path)})

    def workspace_search(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", ""))
        glob = str(args.get("glob", "**/*"))
        limit = int(args.get("limit", 20))
        if not query:
            return ToolResult("error", "query is required.")
        matches: list[dict[str, Any]] = []
        pattern = re.compile(query, re.IGNORECASE)
        for path in self.workspace_root.glob(glob):
            if not path.is_file():
                continue
            try:
                for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if pattern.search(line):
                        matches.append({"path": str(path.relative_to(self.workspace_root)), "line": number, "text": line[:500]})
                        if len(matches) >= limit:
                            return ToolResult("ok", f"Found {len(matches)} matches.", {"matches": matches})
            except UnicodeDecodeError:
                continue
        return ToolResult("ok", f"Found {len(matches)} matches.", {"matches": matches})

    def workspace_patch(self, args: dict[str, Any]) -> ToolResult:
        path = self._workspace_path(str(args.get("path", "")))
        old = str(args.get("old", ""))
        new = str(args.get("new", ""))
        if not old:
            return ToolResult("error", "old is required.")
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count == 0:
            return ToolResult("error", "old text not found.", {"path": str(path)})
        if count > 1 and not args.get("replace_all", False):
            return ToolResult("error", f"old text appears {count} times; pass replace_all=true to replace all.", {"path": str(path), "matches": count})
        updated = text.replace(old, new, -1 if args.get("replace_all", False) else 1)
        path.write_text(updated, encoding="utf-8")
        return ToolResult("ok", f"Patched {path.relative_to(self.workspace_root)}.", {"path": str(path), "replacements": count if args.get("replace_all", False) else 1})

    def schedule_job(self, args: dict[str, Any]) -> ToolResult:
        job_id = self.store.create_job(self.session_id, str(args.get("name", "job")), str(args.get("schedule", "manual")), str(args.get("prompt", "")))
        return ToolResult("ok", f"Scheduled job {job_id}.", {"job_id": job_id})

    def list_jobs(self, args: dict[str, Any]) -> ToolResult:
        jobs = [asdict(job) for job in self.store.list_jobs(self.session_id)]
        return ToolResult("ok", f"Found {len(jobs)} jobs.", {"jobs": jobs})

    def run_due_jobs(self, args: dict[str, Any]) -> ToolResult:
        jobs = [asdict(job) for job in self.store.due_jobs(self.session_id)]
        return ToolResult("ok", f"{len(jobs)} jobs are due. Use OffSecAgentRuntime.run_due_jobs() to execute them.", {"due_jobs": jobs})

    def subagent_review(self, args: dict[str, Any]) -> ToolResult:
        prompt = str(args.get("prompt") or args.get("finding") or "")
        roles = args.get("roles") or ["scope", "safety", "evidence", "impact", "cve", "report"]
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        context = str(args.get("context", ""))
        results: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(roles)))) as pool:
            future_map = {pool.submit(self.model_adapter.generate, role, prompt, context): role for role in roles}
            for future in as_completed(future_map):
                role = future_map[future]
                try:
                    results[role] = future.result().content
                except Exception as exc:
                    results[role] = f"ERROR: {exc}"
        out = self.harness.store.root / "agent" / "subagent-review.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# Subagent Review", "", f"Prompt: {prompt}", ""]
        for role in roles:
            lines += [f"## {role}", "", results.get(role, ""), ""]
        out.write_text("\n".join(lines), encoding="utf-8")
        return ToolResult("ok", f"Subagent review complete: {out}", {"roles": roles, "results": results}, {"markdown": str(out)})

    def delegate_tasks(self, args: dict[str, Any]) -> ToolResult:
        prompt = str(args.get("prompt") or "").strip()
        task_specs = _parse_delegate_tasks(args)
        if not task_specs:
            return ToolResult("error", "Provide tasks as JSON/list/newline text, or roles plus prompt.")
        delegation_id = self.store.create_delegation(self.session_id, prompt, task_specs)
        out_dir = self.harness.store.root / "agent" / "delegations" / f"delegation-{delegation_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(6, len(task_specs))) as pool:
            future_map = {}
            for idx, task in enumerate(task_specs, 1):
                role = str(task.get("role") or "impact")
                task_prompt = str(task.get("prompt") or task.get("goal") or prompt)
                task_context = str(task.get("context") or prompt)
                future_map[pool.submit(self.model_adapter.generate, role, task_prompt, task_context)] = (idx, role, task_prompt)
            for future in as_completed(future_map):
                idx, role, task_prompt = future_map[future]
                try:
                    content = redact_secrets(future.result().content) or ""
                    status = "ok"
                except Exception as exc:
                    content = f"ERROR: {exc}"
                    status = "error"
                path = out_dir / f"task-{idx}-{_safe_filename(role)}.md"
                path.write_text(f"# Delegated Task {idx}: {role}\n\nPrompt: {redact_secrets(task_prompt)}\n\n{content}\n", encoding="utf-8")
                results.append({"index": idx, "role": role, "prompt": redact_secrets(task_prompt), "status": status, "content": content, "artifact": str(path)})
        results.sort(key=lambda item: int(item["index"]))
        summary_path = out_dir / "SUMMARY.md"
        summary_lines = ["# Phobos Local Delegation", "", f"Delegation: {delegation_id}", f"Prompt: {redact_secrets(prompt)}", ""]
        for result in results:
            summary_lines += [f"## Task {result['index']} — {result['role']} ({result['status']})", "", str(result["content"])[:4000], ""]
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
        status = "ok" if all(result["status"] == "ok" for result in results) else "error"
        delegation = self.store.complete_delegation(delegation_id, status, results, {"summary": str(summary_path), "dir": str(out_dir)})
        return ToolResult(status, f"Delegation {delegation_id} completed with {len(results)} task(s).", {"delegation": delegation}, {"summary": str(summary_path), "directory": str(out_dir)})

    def list_delegations(self, args: dict[str, Any]) -> ToolResult:
        delegations = self.store.list_delegations(self.session_id, limit=int(args.get("limit", 20)))
        return ToolResult("ok", f"Found {len(delegations)} delegation batch(es).", {"delegations": delegations})

    def auth_status(self, args: dict[str, Any]) -> ToolResult:
        env_names = {"model_key_env": "OPENAI_API_KEY"}
        providers = []
        adapter_provider = getattr(self.model_adapter, "provider", "unknown")
        providers.append({"provider": adapter_provider, "configured": True})
        for name in ("OPENAI_API_KEY", "PHOBOS_DISCORD_TOKEN", "PHOBOS_SLACK_BOT_TOKEN", "PHOBOS_SLACK_APP_TOKEN", "PHOBOS_TELEGRAM_TOKEN"):
            env_names[name] = name
        env = {name: {"set": bool(os.environ.get(name)), "length": len(os.environ.get(name, "")) if args.get("include_environment", False) and os.environ.get(name) else None} for name in sorted(set(env_names.values()))}
        return ToolResult("ok", "Auth and token environment checked without revealing values.", {"provider": adapter_provider, "environment": env, "secret_values_redacted": True})

    def media_import(self, args: dict[str, Any]) -> ToolResult:
        src = Path(str(args.get("path", ""))).expanduser()
        if not src.exists() or not src.is_file():
            return ToolResult("error", f"Media/artifact source file not found: {src}")
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        mime_type = mimetypes.guess_type(str(src))[0] or "application/octet-stream"
        kind = str(args.get("kind") or _kind_from_mime(mime_type)).strip() or "file"
        media_dir = self.harness.store.root / "agent" / "media"
        media_dir.mkdir(parents=True, exist_ok=True)
        dest = media_dir / f"{digest[:12]}-{_safe_filename(src.name)}"
        shutil.copyfile(src, dest)
        media_id = self.store.create_media_artifact(self.session_id, kind, str(src), str(dest), mime_type, digest, len(data), {"original_name": src.name})
        return ToolResult("ok", f"Imported media/artifact {media_id}: {dest}", {"media": self.store.list_media_artifacts(self.session_id, limit=1)[0]}, {"file": str(dest)})

    def media_list(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.list_media_artifacts(self.session_id, limit=int(args.get("limit", 50)))
        return ToolResult("ok", f"Found {len(rows)} media/artifact file(s).", {"media": rows})

    def sealed_export(self, args: dict[str, Any]) -> ToolResult:
        passphrase_env = str(args.get("passphrase_env") or "").strip()
        passphrase = os.environ.get(passphrase_env, "") if passphrase_env else ""
        if not passphrase:
            return ToolResult("error", "passphrase_env must name an environment variable containing the passphrase; no secret value is accepted in args.")
        handoff = self.export_session({"out": f"sealed-source-{uuid.uuid4().hex[:8]}.json", "message_limit": int(args.get("message_limit", 1000))})
        if handoff.status != "ok":
            return handoff
        source_path = Path(handoff.data["path"])
        payload: dict[str, Any] = {"handoff": json.loads(source_path.read_text(encoding="utf-8"))}
        if args.get("include_pack", False):
            pack = self.export_pack({"out": f"sealed-source-{uuid.uuid4().hex[:8]}.zip"})
            payload["pack_manifest"] = pack.data.get("manifest", {}) if pack.status == "ok" else {"error": pack.message}
        sealed = seal_bytes(json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"), passphrase, aad=b"phobos-agent-sealed-export")
        out_arg = str(args.get("out") or "").strip()
        out = Path(out_arg) if out_arg else self.harness.store.root / "agent" / "sealed" / f"session-{uuid.uuid4().hex[:10]}.sealed.json"
        if not out.is_absolute():
            out = self.harness.store.root / "agent" / "sealed" / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(sealed)
        source_path.unlink(missing_ok=True)
        return ToolResult("ok", f"Sealed encrypted snapshot written: {out}", {"path": str(out), "format": "PHOBOS_SEALED_V1", "passphrase_env": passphrase_env}, {"sealed": str(out)})

    def sealed_import(self, args: dict[str, Any]) -> ToolResult:
        passphrase_env = str(args.get("passphrase_env") or "").strip()
        passphrase = os.environ.get(passphrase_env, "") if passphrase_env else ""
        if not passphrase:
            return ToolResult("error", "passphrase_env must name an environment variable containing the passphrase; no secret value is accepted in args.")
        path = Path(str(args.get("path", ""))).expanduser()
        if not path.exists() or not path.is_file():
            return ToolResult("error", f"Sealed snapshot not found: {path}")
        payload = json.loads(unseal_bytes(path.read_bytes(), passphrase, aad=b"phobos-agent-sealed-export").decode("utf-8"))
        handoff = payload.get("handoff")
        if not isinstance(handoff, dict):
            return ToolResult("error", "Sealed snapshot does not contain a session handoff.")
        tmp = self.harness.store.root / "agent" / "sealed" / f"import-{uuid.uuid4().hex[:8]}.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(handoff, indent=2, sort_keys=True), encoding="utf-8")
        try:
            result = self.import_session({"path": str(tmp), "merge_memories": bool(args.get("merge_memories", False))})
        finally:
            tmp.unlink(missing_ok=True)
        return ToolResult(result.status, "Sealed snapshot decrypted and imported; no commands executed.", result.data, result.artifacts)

    def list_approvals(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.list_approvals(self.session_id, status=str(args.get("status", "pending")))
        return ToolResult("ok", f"Found {len(rows)} approvals.", {"approvals": rows})

    def tool_schemas(self, args: dict[str, Any]) -> ToolResult:
        name = str(args.get("name", "")).strip()
        if name:
            if name not in self.tool_specs:
                return ToolResult("error", f"Tool schema not found: {name}", {"available": sorted(self.tool_specs)})
            specs = [self.tool_specs[name]]
        else:
            specs = self.specs()
        return ToolResult("ok", f"Returned {len(specs)} tool schema(s).", {"tools": [spec.to_dict() for spec in specs]})

    def audit_log(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.list_audit(self.session_id, limit=int(args.get("limit", 50)))
        return ToolResult("ok", f"Found {len(rows)} audit entries.", {"audit": rows})

    def runtime_status(self, args: dict[str, Any]) -> ToolResult:
        approvals = self.store.list_approvals(self.session_id, status="pending")
        jobs = self.store.list_jobs(self.session_id)
        processes = self.store.list_processes(self.session_id, limit=100)
        tasks = self.store.list_tasks(self.session_id, status="all", limit=100)
        context_nodes = self.store.list_context_nodes(self.session_id, limit=100)
        delegations = self.store.list_delegations(self.session_id, limit=100)
        media = self.store.list_media_artifacts(self.session_id, limit=100)
        data = {
            "session_id": self.session_id,
            "engagement": self.roe.to_dict(),
            "schema": self.store.schema_info(),
            "workspace": str(self.workspace_root),
            "tools": len(self.tool_specs),
            "pending_approvals": len(approvals),
            "jobs": len(jobs),
            "tasks": len(tasks),
            "open_tasks": len([task for task in tasks if task["status"] not in {"completed", "cancelled"}]),
            "context_nodes": len(context_nodes),
            "delegations": len(delegations),
            "media_artifacts": len(media),
            "processes": len(processes),
            "policy": {"blocked_tools": sorted(self.blocked_tools), "confirm_tools": sorted(self.confirm_tools)},
            "evidence_root": str(self.harness.store.root),
        }
        return ToolResult("ok", "Runtime status assembled.", data)

    def export_pack(self, args: dict[str, Any]) -> ToolResult:
        export_dir = self.harness.store.root / "agent" / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        out_arg = str(args.get("out") or "").strip()
        if out_arg:
            out_path = Path(out_arg)
            if not out_path.is_absolute():
                out_path = export_dir / out_path
        else:
            stamp = utc_now().replace(":", "").replace("+0000", "Z").replace("+00:00", "Z")
            out_path = export_dir / f"phobos-agent-pack-{stamp}.zip"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.suffix.lower() != ".zip":
            out_path = out_path.with_suffix(".zip")

        evidence_root = self.harness.store.root.resolve()
        manifest: dict[str, Any] = {
            "created_at": utc_now(),
            "session_id": self.session_id,
            "engagement": self.roe.name,
            "evidence_root": str(evidence_root),
            "redaction": "Text artifacts are passed through the harness secret redactor before packaging.",
            "files": [],
            "skipped": [],
        }
        state = {
            "session_id": self.session_id,
            "schema": self.store.schema_info(),
            "engagement": self.roe.to_dict(),
            "memories": self.store.recall("", limit=200),
            "pending_approvals": self.store.list_approvals(self.session_id, status="pending"),
            "jobs": [asdict(job) for job in self.store.list_jobs(self.session_id)],
            "tasks": [_redacted_mapping(row) for row in self.store.list_tasks(self.session_id, status="all", limit=500)],
            "context_nodes": [_redacted_mapping(row) for row in self.store.list_context_nodes(self.session_id, limit=500)],
            "delegations": [_redacted_mapping(row) for row in self.store.list_delegations(self.session_id, limit=200)],
            "media_artifacts": [_redacted_mapping(row) for row in self.store.list_media_artifacts(self.session_id, limit=200)],
            "processes": self.store.list_processes(self.session_id, limit=200),
            "audit": self.store.list_audit(self.session_id, limit=200),
        }
        text_suffixes = {".json", ".jsonl", ".md", ".txt", ".log", ".http", ".csv", ".yaml", ".yml"}

        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _zip_text(archive, "PACK_README.md", _pack_readme(self.roe.name))
            _zip_json(archive, "runtime/state.json", state)
            for path in sorted(evidence_root.rglob("*")):
                if not path.is_file():
                    continue
                if _is_relative_to(path.resolve(), export_dir.resolve()):
                    continue
                rel = path.relative_to(evidence_root).as_posix()
                if path.stat().st_size > 2_000_000:
                    manifest["skipped"].append({"path": rel, "reason": "larger than 2MB"})
                    continue
                if path.suffix.lower() not in text_suffixes:
                    manifest["skipped"].append({"path": rel, "reason": "non-text artifact omitted from redacted pack"})
                    continue
                raw = path.read_text(encoding="utf-8", errors="replace")
                redacted = redact_secrets(raw)
                arcname = f"evidence/{rel}"
                archive.writestr(arcname, redacted)
                manifest["files"].append({
                    "archive_path": arcname,
                    "source_path": str(path),
                    "bytes": len(redacted.encode("utf-8")),
                    "sha256": hashlib.sha256(redacted.encode("utf-8")).hexdigest(),
                })
            _zip_json(archive, "MANIFEST.json", manifest)
        return ToolResult("ok", f"Engagement pack exported: {out_path}", {"pack": str(out_path), "manifest": manifest}, {"zip": str(out_path)})

    def operator_briefing(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query", ""))
        tasks = self.store.list_tasks(self.session_id, status="all", limit=100)
        approvals = self.store.list_approvals(self.session_id, status="pending")
        jobs = [asdict(job) for job in self.store.list_jobs(self.session_id)]
        processes = self.store.list_processes(self.session_id, limit=20)
        summary = self.store.latest_context_summary(self.session_id)
        recent = self.store.recent_messages(self.session_id, limit=8)
        memories = self.store.recall(query, limit=8) if query else []
        status = {
            "session_id": self.session_id,
            "engagement": self.roe.name,
            "safety_mode": self.roe.safety_mode,
            "workspace": str(self.workspace_root),
            "schema": self.store.schema_info(),
            "pending_approvals": len(approvals),
            "open_tasks": len([task for task in tasks if task["status"] not in {"completed", "cancelled"}]),
            "jobs": len(jobs),
            "processes": len(processes),
        }
        lines = [
            "# Phobos Agent Operator Briefing",
            "",
            f"Generated: {utc_now()}",
            f"Engagement: {self.roe.name}",
            f"Safety mode: `{self.roe.safety_mode}`",
            f"Workspace: `{self.workspace_root}`",
            "",
            "## Runtime Status",
            "",
            "```json",
            json.dumps(status, indent=2),
            "```",
            "",
            "## Task Board",
            "",
        ]
        if tasks:
            for task in tasks:
                lines.append(f"- [{task['status']}] #{task['id']} {redact_secrets(task['content'])}")
        else:
            lines.append("- No tasks recorded.")
        lines += ["", "## Pending Approvals", ""]
        if approvals:
            for approval in approvals:
                lines.append(f"- #{approval['id']} `{approval['tool_name']}` requested {approval['requested_at']}: {redact_secrets(json.dumps(approval.get('args', {}), sort_keys=True))}")
        else:
            lines.append("- No pending approvals.")
        lines += ["", "## Latest Compact Context", "", summary["summary"] if summary else "No compact context summary yet.", "", "## Recent Messages", ""]
        for message in recent:
            content = redact_secrets(str(message["content"])).replace("\n", " ")[:500]
            lines.append(f"- {message['id']} `{message['role']}`: {content}")
        lines += ["", "## Relevant Memories", ""]
        if memories:
            for memory in memories:
                lines.append(f"- `{memory['key']}`: {redact_secrets(memory['value'])}")
        else:
            lines.append("- No query-specific memories included.")
        lines += ["", "## Jobs and Processes", ""]
        lines.append(f"- Jobs configured: {len(jobs)}")
        lines.append(f"- Processes tracked: {len(processes)}")
        text = "\n".join(lines) + "\n"
        out_arg = str(args.get("out") or "").strip()
        if out_arg:
            out = Path(out_arg)
            if not out.is_absolute():
                out = self.harness.store.root / "agent" / out
        else:
            stamp = utc_now().replace(":", "").replace("+00:00", "Z")
            out = self.harness.store.root / "agent" / f"operator-briefing-{stamp}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        redacted_tasks = [_redacted_mapping(task) for task in tasks]
        return ToolResult("ok", f"Operator briefing written: {out}", {"status": status, "tasks": redacted_tasks, "pending_approvals": [_redacted_mapping(row) for row in approvals], "briefing": text[:6000]}, {"markdown": str(out)})

    def export_session(self, args: dict[str, Any]) -> ToolResult:
        export_dir = self.harness.store.root / "agent" / "session-exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        out_arg = str(args.get("out") or "").strip()
        if out_arg:
            out = Path(out_arg)
            if not out.is_absolute():
                out = export_dir / out
        else:
            stamp = utc_now().replace(":", "").replace("+00:00", "Z")
            out = export_dir / f"session-handoff-{stamp}.json"
        if out.suffix.lower() != ".json":
            out = out.with_suffix(".json")
        out.parent.mkdir(parents=True, exist_ok=True)
        message_limit = int(args.get("message_limit", 1000))
        bundle = {
            "bundle_type": "phobos-agent-session-handoff",
            "version": 1,
            "created_at": utc_now(),
            "source_session_id": self.session_id,
            "session": self.store.get_session(self.session_id),
            "engagement": self.roe.to_dict(),
            "schema": self.store.schema_info(),
            "messages": [_redacted_mapping(row) for row in self.store.all_messages(self.session_id, limit=message_limit)],
            "context_summaries": [_redacted_mapping(row) for row in self.store.list_context_summaries(self.session_id, limit=50)],
            "context_nodes": [_redacted_mapping(row) for row in self.store.list_context_nodes(self.session_id, limit=500)],
            "memories": [_redacted_mapping(row) for row in self.store.recall("", limit=500)],
            "tasks": [_redacted_mapping(row) for row in self.store.list_tasks(self.session_id, status="all", limit=500)],
            "pending_approvals": [_redacted_mapping(row) for row in self.store.list_approvals(self.session_id, status="pending")],
            "jobs": [asdict(job) for job in self.store.list_jobs(self.session_id)],
            "delegations": [_redacted_mapping(row) for row in self.store.list_delegations(self.session_id, limit=500)],
            "media_artifacts": [_redacted_mapping(row) for row in self.store.list_media_artifacts(self.session_id, limit=500)],
            "processes": [_redacted_mapping(row) for row in self.store.list_processes(self.session_id, limit=500)],
            "audit": [_redacted_mapping(row) for row in self.store.list_audit(self.session_id, limit=500)],
        }
        redacted_bundle = _redact_value(bundle)
        out.write_text(json.dumps(redacted_bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return ToolResult("ok", f"Session handoff exported: {out}", {"path": str(out), "messages": len(bundle["messages"]), "memories": len(bundle["memories"]), "tasks": len(bundle["tasks"])}, {"json": str(out)})

    def import_session(self, args: dict[str, Any]) -> ToolResult:
        path = Path(str(args.get("path", ""))).expanduser()
        if not path.exists() or not path.is_file():
            return ToolResult("error", f"Session bundle not found: {path}")
        bundle = json.loads(path.read_text(encoding="utf-8"))
        if bundle.get("bundle_type") != "phobos-agent-session-handoff":
            return ToolResult("error", "Unsupported session bundle type; no data imported.")
        source = str(bundle.get("source_session_id", "unknown"))
        merge_memories = bool(args.get("merge_memories", False))
        imported_memories = 0
        for memory in bundle.get("memories", []):
            key = str(memory.get("key", "")).strip()
            value = str(memory.get("value", "")).strip()
            if not key or not value:
                continue
            self.store.remember(key if merge_memories else f"imported:{source}:{key}", value, tags=str(memory.get("tags", "imported")))
            imported_memories += 1
        summaries = bundle.get("context_summaries", [])
        if summaries:
            summary_text = "\n\n".join(str(item.get("summary", "")) for item in reversed(summaries) if item.get("summary"))
        else:
            msg_lines = []
            for message in bundle.get("messages", [])[-20:]:
                msg_lines.append(f"{message.get('role', 'unknown')}: {str(message.get('content', ''))[:500]}")
            summary_text = "Imported session messages:\n" + "\n".join(msg_lines)
        if summary_text.strip():
            self.store.create_context_summary(self.session_id, None, None, f"Imported handoff from {source} at {utc_now()}:\n\n{summary_text[:12000]}")
        imported_nodes = 0
        for node in bundle.get("context_nodes", [])[:100]:
            title = str(node.get("title", "imported context node")).strip() or "imported context node"
            summary = str(node.get("summary", "")).strip()
            if not summary:
                continue
            self.store.create_context_node(
                self.session_id,
                f"Imported from {source}: {title}",
                summary[:12000],
                sources=[{"type": "imported_context_node", "source_session_id": source, "source_node_id": node.get("id")}],
                depth=int(node.get("depth", 0) or 0),
                metadata={"imported": True, "source_session_id": source},
            )
            imported_nodes += 1
        imported_tasks = 0
        for task in bundle.get("tasks", []):
            content = str(task.get("content", "")).strip()
            if not content:
                continue
            try:
                imported_status = _normalize_task_status(str(task.get("status", "pending")))
            except ValueError:
                imported_status = "pending"
            self.store.create_task(self.session_id, f"Imported from {source}: {content}", status=imported_status, metadata={"source_session_id": source, "source_task_id": task.get("id")})
            imported_tasks += 1
        self.store.append_message(self.session_id, "system", f"Imported session handoff from {source}: {imported_memories} memories, {imported_nodes} context nodes, {imported_tasks} tasks, source file {path}")
        return ToolResult("ok", f"Imported handoff from {source}; no commands executed.", {"source_session_id": source, "imported_memories": imported_memories, "imported_context_nodes": imported_nodes, "imported_tasks": imported_tasks})

    def list_tasks(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.list_tasks(self.session_id, status=str(args.get("status", "all")), limit=int(args.get("limit", 100)))
        return ToolResult("ok", f"Found {len(rows)} task(s).", {"tasks": rows})

    def add_task(self, args: dict[str, Any]) -> ToolResult:
        content = str(args.get("content") or args.get("task") or "").strip()
        if not content:
            return ToolResult("error", "content is required.")
        status = _normalize_task_status(str(args.get("status", "pending")))
        task_id = self.store.create_task(self.session_id, content, status=status)
        return ToolResult("ok", f"Task {task_id} added.", {"task": self.store.get_task(task_id)})

    def update_task(self, args: dict[str, Any]) -> ToolResult:
        task_id = int(args.get("id") or args.get("task_id"))
        content = args.get("content")
        status = args.get("status")
        normalized = _normalize_task_status(str(status)) if status is not None else None
        task = self.store.update_task(task_id, content=str(content) if content is not None else None, status=normalized)
        if not task:
            return ToolResult("error", f"Task {task_id} not found.")
        return ToolResult("ok", f"Task {task_id} updated.", {"task": task})

    def _execute_allowed_command(self, request: ActionRequest, timeout: int, approval_id: int | None) -> ToolResult:
        if not request.command:
            return ToolResult("error", "No command supplied.")
        completed = subprocess.run(request.command, shell=True, text=True, capture_output=True, timeout=timeout, check=False)
        out_dir = self.harness.store.root / "executions"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_id = approval_id if approval_id is not None else "direct"
        path = out_dir / f"execution-{safe_id}.json"
        payload = {
            "target": request.target,
            "purpose": request.purpose,
            "command": redact_secrets(request.command),
            "exit_code": completed.returncode,
            "stdout": redact_secrets(completed.stdout[-4000:]),
            "stderr": redact_secrets(completed.stderr[-4000:]),
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return ToolResult("executed", f"Command executed with exit code {completed.returncode}.", payload, {"execution": str(path)})

    def _workspace_path(self, relative: str) -> Path:
        if not relative:
            raise ValueError("workspace path is required")
        path = (self.workspace_root / relative).resolve()
        if os.path.commonpath([str(self.workspace_root.resolve()), str(path)]) != str(self.workspace_root.resolve()):
            raise ValueError("workspace path escapes the engagement workspace")
        return path

    def _refresh_process(self, process_id: int) -> dict[str, Any] | None:
        process = self.store.get_process(process_id)
        if not process:
            return None
        rc_path = Path(process["rc_path"])
        status = process.get("status", "unknown")
        if rc_path.exists():
            try:
                exit_code = int(rc_path.read_text(encoding="utf-8").strip().splitlines()[-1])
            except (ValueError, IndexError):
                exit_code = None
            live = _LIVE_PROCESSES.pop(process_id, None)
            if live is not None:
                try:
                    live.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    _LIVE_PROCESSES[process_id] = live
            status = "completed" if exit_code == 0 else "failed"
            if process.get("status") != status or process.get("exit_code") != exit_code:
                self.store.update_process(process_id, status=status, exit_code=exit_code, ended_at=process.get("ended_at") or utc_now())
        elif process.get("pid") and _pid_running(int(process["pid"])):
            status = "running"
            if process.get("status") != "running":
                self.store.update_process(process_id, status="running")
        elif process.get("status") in {"running", "starting"}:
            status = "unknown"
            self.store.update_process(process_id, status="unknown", ended_at=process.get("ended_at") or utc_now())
        return self.store.get_process(process_id)


def _request_from_args(args: dict[str, Any]) -> ActionRequest:
    return ActionRequest(
        target=str(args.get("target", "")),
        action_type=str(args.get("action_type") or args.get("type") or "host"),
        purpose=str(args.get("purpose", "")),
        command=args.get("command"),
        actor=str(args.get("actor", "operator")),
    )


def _parse_delegate_tasks(args: dict[str, Any]) -> list[dict[str, Any]]:
    raw = args.get("tasks")
    prompt = str(args.get("prompt") or "").strip()
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, dict):
                out.append(dict(item))
            elif str(item).strip():
                out.append({"prompt": str(item).strip()})
        return out
    if isinstance(raw, str) and raw.strip():
        text = raw.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return _parse_delegate_tasks({"tasks": parsed, "prompt": prompt})
            except json.JSONDecodeError:
                pass
        return [{"prompt": line.strip()} for line in text.splitlines() if line.strip()]
    roles = args.get("roles")
    if isinstance(roles, str):
        role_list = [role.strip() for role in roles.split(",") if role.strip()]
    elif isinstance(roles, list):
        role_list = [str(role).strip() for role in roles if str(role).strip()]
    else:
        role_list = []
    if role_list and prompt:
        return [{"role": role, "prompt": prompt, "context": prompt} for role in role_list]
    return []


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return cleaned[:80] or "artifact"


def _kind_from_mime(mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("audio/"):
        return "audio"
    if mime_type.startswith("video/"):
        return "video"
    return "file"


def _write_context_node_artifact(root: Path, node_id: int, title: str, summary: str) -> Path:
    out = root / "agent" / "context-nodes" / f"context-node-{node_id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"# {redact_secrets(title)}\n\nNode: {node_id}\nGenerated: {utc_now()}\n\n{redact_secrets(summary)}\n", encoding="utf-8")
    return out


def _normalize_task_status(status: str) -> str:
    normalized = status.strip().lower().replace("-", "_")
    allowed = {"pending", "in_progress", "completed", "cancelled"}
    if normalized not in allowed:
        raise ValueError(f"Invalid task status {status!r}; expected one of {sorted(allowed)}")
    return normalized


def _redacted_mapping(row: dict[str, Any]) -> dict[str, Any]:
    redacted = _redact_value(row)
    return redacted if isinstance(redacted, dict) else {}


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value


def _safe_json(value: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(value, default=str)
    text = redact_secrets(text) or "{}"
    return json.loads(text)


def _string(description: str) -> dict[str, str]:
    return {"type": "string", "description": description}


def _spec(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> ToolSpec:
    return ToolSpec(name=name, description=description, schema={"type": "object", "properties": properties, "required": required or [], "additionalProperties": True})


def _tail(path: Path, limit: int) -> str:
    if not path.exists():
        return ""
    data = path.read_bytes()
    return data[-limit:].decode("utf-8", errors="replace")


def _pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _zip_text(archive: zipfile.ZipFile, arcname: str, text: str) -> None:
    archive.writestr(arcname, redact_secrets(text))


def _zip_json(archive: zipfile.ZipFile, arcname: str, value: dict[str, Any]) -> None:
    archive.writestr(arcname, json.dumps(_redact_value(value), indent=2, sort_keys=True) + "\n")


def _pack_readme(engagement_name: str) -> str:
    return f"""# Phobos Agent Engagement Pack

Engagement: {engagement_name}

This ZIP was generated by the standalone Phobos Agent runtime. Text artifacts
were redacted with the harness secret redactor before packaging. Review raw
source evidence in the original engagement directory if a client deliverable
requires exact request/response content.

Contents:

- `MANIFEST.json` — redacted file inventory and hashes of packaged text.
- `runtime/state.json` — session, schema, approvals, jobs, processes, audit, and ROE metadata.
- `evidence/` — redacted text evidence artifacts from the engagement evidence directory.
"""


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
