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
import xml.etree.ElementTree as ET

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
        runtime_metadata: dict[str, Any] | None = None,
    ):
        self.roe = roe
        self.harness = OffSecHarness(roe)
        self.store = store
        self.session_id = session_id
        self.model_adapter = model_adapter or HeuristicAdapter()
        self.default_timeout = default_timeout
        self.blocked_tools = {name.strip() for name in blocked_tools if name.strip()}
        self.confirm_tools = {name.strip() for name in confirm_tools if name.strip()}
        self.runtime_metadata = runtime_metadata or {}
        self._policy_bypass_tools = {"approve", "deny", "list_approvals", "tool_schemas", "runtime_status", "audit_log", "auth_status", "safety_preflight"}
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
        self.register_tool("export_finding", self.export_finding, _spec("export_finding", "Report-ready finding Markdown exporter for a finding JSON file.", {"finding_file": _string("Finding JSON path."), "out": _string("Optional output path.")}))
        self.register_tool("nmap_scan", self.nmap_scan, _spec("nmap_scan", "ROE-gated nmap-style service enumeration wrapper with structured parsing and evidence artifacts.", {"target": _string("In-scope host/IP/CIDR."), "ports": _string("Optional comma/range ports, e.g. 80,443,8000-8010."), "profile": _string("safe|version|quick; default version."), "stdout": _string("Optional captured output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": {"type": "integer"}}, ["target"]))
        self.register_tool("httpx_probe", self.httpx_probe, _spec("httpx_probe", "ROE-gated httpx-style HTTP probing wrapper with JSON/plaintext parsing and evidence artifacts.", {"url": _string("In-scope URL or host."), "target": _string("Alias for url."), "stdout": _string("Optional captured output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": {"type": "integer"}}, []))
        self.register_tool("nuclei_scan", self.nuclei_scan, _spec("nuclei_scan", "ROE-gated nuclei wrapper. Real execution requires an explicit safe template path; parser/dry-run paths remain available without nuclei installed.", {"url": _string("In-scope URL or host."), "target": _string("Alias for url."), "templates": _string("Template file/directory for execution; required when execute=true."), "template": _string("Alias for templates."), "rate_limit": {"type": "integer"}, "stdout": _string("Optional captured JSONL/plain output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": {"type": "integer"}}, []))
        self.register_tool("ffuf_scan", self.ffuf_scan, _spec("ffuf_scan", "ROE-gated ffuf-style content discovery wrapper with conservative rate limits and structured evidence.", {"url": _string("In-scope URL containing FUZZ or base URL where /FUZZ is appended."), "wordlist": _string("Wordlist path required for execution."), "rate": {"type": "integer"}, "stdout": _string("Optional captured JSON output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": {"type": "integer"}}, ["url"]))
        self.register_tool("list_tool_runs", self.list_tool_runs, _spec("list_tool_runs", "List structured wrapper runs and their parsed evidence artifacts.", {"limit": {"type": "integer"}, "tool_name": _string("Optional wrapper tool name filter.")}, []))
        self.register_tool("get_tool_run", self.get_tool_run, _spec("get_tool_run", "Get one structured wrapper run by id.", {"id": {"type": "integer"}}, ["id"]))
        self.register_tool("create_finding", self.create_finding, _spec("create_finding", "Create a finding lifecycle record linked to evidence/tool runs.", {"title": _string("Finding title."), "severity": _string("Informational/Low/Medium/High/Critical."), "status": _string("draft/needs-evidence/confirmed/resolved/accepted-risk."), "description": _string("Technical description."), "impact": _string("Impact statement."), "recommendation": _string("Remediation guidance."), "tool_run_ids": _string("Comma-separated structured tool run IDs to link."), "evidence": _string("Additional evidence refs as JSON/list/text."), "tags": _string("Comma-separated tags.")}, ["title"]))
        self.register_tool("update_finding", self.update_finding, _spec("update_finding", "Update a finding lifecycle record and optionally append evidence.", {"id": {"type": "integer"}, "title": _string("Optional title."), "severity": _string("Optional severity."), "status": _string("Optional status."), "description": _string("Optional description."), "impact": _string("Optional impact."), "recommendation": _string("Optional recommendation."), "tool_run_ids": _string("Additional linked tool run IDs."), "evidence": _string("Replacement or appended evidence refs."), "append_evidence": {"type": "boolean"}, "tags": _string("Optional tags.")}, ["id"]))
        self.register_tool("list_findings", self.list_findings, _spec("list_findings", "List finding lifecycle records.", {"status": _string("draft/confirmed/resolved/all; default all."), "limit": {"type": "integer"}}, []))
        self.register_tool("get_finding", self.get_finding, _spec("get_finding", "Get one finding lifecycle record by id.", {"id": {"type": "integer"}}, ["id"]))
        self.register_tool("finding_export", self.finding_export, _spec("finding_export", "Export a stored finding lifecycle record to report-ready Markdown.", {"id": {"type": "integer"}, "out": _string("Optional output path; relative paths go under agent/findings.")}, ["id"]))
        self.register_tool("finding_review", self.finding_review, _spec("finding_review", "Deterministically review a stored finding for report-readiness gaps without executing target actions.", {"id": {"type": "integer"}, "out": _string("Optional Markdown output path; relative paths go under agent/findings.")}, ["id"]))
        self.register_tool("remember", self.remember, _spec("remember", "Store local agent memory in SQLite.", {"key": _string("Memory key."), "value": _string("Memory value."), "tags": _string("Optional comma tags.")}, ["key", "value"]))
        self.register_tool("recall", self.recall, _spec("recall", "Search local agent memory.", {"query": _string("Memory search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("search_session", self.search_session, _spec("search_session", "Search current-session messages.", {"query": _string("Message search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("search_all_sessions", self.search_all_sessions, _spec("search_all_sessions", "Search messages across all local Phobos sessions in this DB.", {"query": _string("Message search query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("context_snapshot", self.context_snapshot, _spec("context_snapshot", "Return latest compact summary, recent messages, and relevant memory.", {"query": _string("Optional relevance query."), "limit": {"type": "integer"}}))
        self.register_tool("compact_context", self.compact_context, _spec("compact_context", "Summarize recent session messages into durable local context.", {"limit": {"type": "integer"}}))
        self.register_tool("context_compact_node", self.context_compact_node, _spec("context_compact_node", "Create an LCM-style context node from recent messages and optionally roll child nodes into a parent.", {"limit": {"type": "integer"}, "title": _string("Optional node title."), "parent": {"type": "boolean"}}, []))
        self.register_tool("context_describe", self.context_describe, _spec("context_describe", "Describe local LCM-style context nodes without expanding full sources.", {"id": {"type": "integer"}, "limit": {"type": "integer"}}, []))
        self.register_tool("context_expand", self.context_expand, _spec("context_expand", "Expand a local context node and recover its source messages/child summaries.", {"id": {"type": "integer"}, "source_limit": {"type": "integer"}}, ["id"]))
        self.register_tool("lcm_compact", self.context_compact_node, _spec("lcm_compact", "Alias for context_compact_node.", {"limit": {"type": "integer"}, "title": _string("Optional node title."), "parent": {"type": "boolean"}}, []))
        self.register_tool("lcm_describe", self.context_describe, _spec("lcm_describe", "Alias for context_describe.", {"id": {"type": "integer"}, "limit": {"type": "integer"}}, []))
        self.register_tool("lcm_expand", self.context_expand, _spec("lcm_expand", "Alias for context_expand.", {"id": {"type": "integer"}, "source_limit": {"type": "integer"}}, ["id"]))
        self.register_tool("context_query", self.context_query, _spec("context_query", "Search memories, session history, and LCM-style context nodes, then synthesize an answer.", {"query": _string("Question or recall query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("reflect_memory", self.reflect_memory, _spec("reflect_memory", "Synthesize an answer from local memories and session/context recall without executing tools.", {"query": _string("Question to answer from memory/context."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("hindsight_retain", self.hindsight_retain, _spec("hindsight_retain", "Store a Hindsight-style durable local memory with context/tags metadata.", {"content": _string("Memory content to retain."), "context": _string("Short context label."), "tags": _string("Comma-separated tags."), "key": _string("Optional stable key.")}, ["content"]))
        self.register_tool("hindsight_recall", self.hindsight_recall, _spec("hindsight_recall", "Recall Hindsight-style memory plus related session/context matches.", {"query": _string("Recall query."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("hindsight_reflect", self.hindsight_reflect, _spec("hindsight_reflect", "Synthesize an answer across retained memory, messages, and local LCM-style context nodes.", {"query": _string("Question to reflect on."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("workspace_read", self.workspace_read, _spec("workspace_read", "Read a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "limit": {"type": "integer"}}, ["path"]))
        self.register_tool("workspace_write", self.workspace_write, _spec("workspace_write", "Write or append a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "content": _string("Text content."), "append": {"type": "boolean"}}, ["path", "content"]))
        self.register_tool("workspace_search", self.workspace_search, _spec("workspace_search", "Search text files inside the engagement workspace.", {"query": _string("Substring/regex query."), "glob": _string("Glob like **/*.md."), "limit": {"type": "integer"}}, ["query"]))
        self.register_tool("workspace_patch", self.workspace_patch, _spec("workspace_patch", "Targeted text replacement inside a workspace file.", {"path": _string("Workspace-relative path."), "old": _string("Text to replace."), "new": _string("Replacement text."), "replace_all": {"type": "boolean"}}, ["path", "old", "new"]))
        self.register_tool("schedule_job", self.schedule_job, _spec("schedule_job", "Create a local scheduled job; run with run_due_jobs or external cron.", {"name": _string("Job name."), "schedule": _string("manual/every 15 m/every 1 h."), "prompt": _string("Agent prompt to run.")}))
        self.register_tool("list_jobs", self.list_jobs, _spec("list_jobs", "List scheduled jobs.", {}))
        self.register_tool("run_due_jobs", self.run_due_jobs, _spec("run_due_jobs", "List due jobs from tool-only context; runtime executes them.", {}))
        self.register_tool("subagent_review", self.subagent_review, _spec("subagent_review", "Run parallel role reviews using the configured model adapter.", {"prompt": _string("Task/finding to review."), "roles": _string("Comma-separated roles."), "context": _string("Optional context.")}))
        self.register_tool("delegate_tasks", self.delegate_tasks, _spec("delegate_tasks", "Run bounded local pseudo-subagent tasks in parallel and persist their artifacts; isolated child sessions are created by default.", {"prompt": _string("Overall task."), "tasks": _string("JSON/list or newline-separated task prompts."), "roles": _string("Comma roles when tasks is omitted."), "isolate": {"type": "boolean", "description": "Create separate child sessions for each local subagent task; default true."}}, []))
        self.register_tool("list_delegations", self.list_delegations, _spec("list_delegations", "List durable local delegation batches.", {"limit": {"type": "integer"}}, []))
        self.register_tool("auth_status", self.auth_status, _spec("auth_status", "Check model/provider and bridge token environment variables without revealing secret values.", {"include_environment": {"type": "boolean"}}, []))
        self.register_tool("safety_preflight", self.safety_preflight, _spec("safety_preflight", "Run a read-only engagement/runtime readiness preflight and write a redacted Markdown report.", {"out": _string("Optional Markdown output path; relative paths go under agent/preflight.")}, []))
        self.register_tool("media_import", self.media_import, _spec("media_import", "Copy an operator-supplied local media/artifact file into evidence with hash metadata.", {"path": _string("Source file path."), "kind": _string("image/audio/video/file; inferred when omitted.")}, ["path"]))
        self.register_tool("media_list", self.media_list, _spec("media_list", "List imported media/artifact files for this session.", {"limit": {"type": "integer"}}, []))
        self.register_tool("sealed_export", self.sealed_export, _spec("sealed_export", "Create an authenticated encrypted portable snapshot from a session handoff or pack.", {"passphrase_env": _string("Environment variable containing passphrase."), "out": _string("Optional output .sealed.json path."), "include_pack": {"type": "boolean"}}, ["passphrase_env"]))
        self.register_tool("sealed_import", self.sealed_import, _spec("sealed_import", "Decrypt a sealed session snapshot and import its handoff data; no commands are executed.", {"path": _string("Sealed snapshot path."), "passphrase_env": _string("Environment variable containing passphrase."), "merge_memories": {"type": "boolean"}}, ["path", "passphrase_env"]))
        self.register_tool("list_approvals", self.list_approvals, _spec("list_approvals", "List pending approvals.", {"status": _string("Approval status; default pending.")}))
        self.register_tool("tool_schemas", self.tool_schemas, _spec("tool_schemas", "Return JSON-style schemas for available tools.", {"name": _string("Optional tool name.")}))
        self.register_tool("audit_log", self.audit_log, _spec("audit_log", "List recent redacted audit log entries.", {"limit": {"type": "integer"}}))
        self.register_tool("evidence_timeline", self.evidence_timeline, _spec("evidence_timeline", "Assemble a redacted operator timeline across tool runs, findings, approvals, tasks, processes, media, delegations, and selected audit events.", {"limit": {"type": "integer"}, "category": _string("Optional comma-separated category filter."), "order": _string("desc or asc; default desc."), "include_audit": {"type": "boolean"}, "out": _string("Optional Markdown output path; relative paths go under agent/timelines.")}, []))
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

    def nmap_scan(self, args: dict[str, Any]) -> ToolResult:
        target = str(args.get("target") or args.get("host") or "").strip()
        if not target:
            return ToolResult("error", "target is required.")
        try:
            command = _build_nmap_command(target, str(args.get("ports") or ""), str(args.get("profile") or "version"))
        except ValueError as exc:
            return ToolResult("error", str(exc))
        return self._structured_tool_run(args, "nmap_scan", target, command, "service-enumeration", str(args.get("purpose") or "Structured nmap service enumeration."), _parse_nmap_output)

    def httpx_probe(self, args: dict[str, Any]) -> ToolResult:
        target = _normalize_url(str(args.get("url") or args.get("target") or "").strip())
        if not target:
            return ToolResult("error", "url or target is required.")
        command = _build_httpx_command(target)
        return self._structured_tool_run(args, "httpx_probe", target, command, "web", str(args.get("purpose") or "Structured HTTP probing."), _parse_httpx_output)

    def nuclei_scan(self, args: dict[str, Any]) -> ToolResult:
        target = _normalize_url(str(args.get("url") or args.get("target") or "").strip())
        if not target:
            return ToolResult("error", "url or target is required.")
        rate_limit = max(1, min(25, int(args.get("rate_limit") or args.get("rate") or 5)))
        templates = str(args.get("templates") or args.get("template") or "").strip()
        if args.get("execute") and not templates:
            return ToolResult("error", "templates/template is required when execute=true for nuclei_scan; use stdout/input_file for parser-only imports.")
        command = _build_nuclei_command(target, rate_limit, templates)
        return self._structured_tool_run(args, "nuclei_scan", target, command, "vulnerability-scan", str(args.get("purpose") or "Structured nuclei validation with explicit operator-selected templates."), _parse_nuclei_output)

    def ffuf_scan(self, args: dict[str, Any]) -> ToolResult:
        target = _normalize_url(str(args.get("url") or args.get("target") or "").strip())
        if not target:
            return ToolResult("error", "url is required.")
        rate = max(1, min(50, int(args.get("rate") or 10)))
        command = _build_ffuf_command(target, str(args.get("wordlist") or ""), rate)
        if args.get("execute") and not str(args.get("wordlist") or "").strip():
            return ToolResult("error", "wordlist is required when execute=true for ffuf_scan.")
        return self._structured_tool_run(args, "ffuf_scan", target, command, "content-discovery", str(args.get("purpose") or "Structured ffuf content discovery with conservative rate limit."), _parse_ffuf_output)

    def _structured_tool_run(
        self,
        args: dict[str, Any],
        tool_name: str,
        target: str,
        command: str,
        action_type: str,
        purpose: str,
        parser: Callable[[str], dict[str, Any]],
    ) -> ToolResult:
        timeout = int(args.get("timeout", self.default_timeout))
        request = ActionRequest(target=target, action_type=action_type, purpose=purpose, command=command, actor=str(args.get("actor", "operator")))
        decision = self.harness.guardrails.evaluate(self.roe, request)
        evidence_path = self.harness.store.record_decision(request, decision)
        if decision.status is DecisionStatus.BLOCK:
            result = self._record_tool_run(tool_name, target, command, "blocked", decision.to_dict(), {}, {"decision_log": str(evidence_path)})
            return ToolResult("blocked", f"{tool_name} blocked by guardrails.", result | {"decision": decision.to_dict()}, {"decision_log": str(evidence_path), "tool_run": result.get("artifact_path", "")})
        if decision.status is DecisionStatus.CONFIRM and not (args.get("_approved") or args.get("_policy_approved")):
            approval_id = self.store.create_approval(self.session_id, tool_name, args, decision.to_dict())
            return ToolResult("needs_approval", f"{tool_name} requires approval before execution. Approval ID: {approval_id}", {"approval_id": approval_id, "decision": decision.to_dict()}, {"decision_log": str(evidence_path)})

        try:
            raw_output = _load_structured_output(args)
        except OSError as exc:
            return ToolResult("error", str(exc), {"decision": decision.to_dict()}, {"decision_log": str(evidence_path)})
        completed_payload: dict[str, Any] = {}
        status = "parsed" if raw_output is not None else "dry_run"
        if raw_output is None and args.get("execute", False):
            try:
                completed = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                result = self._record_tool_run(tool_name, target, command, "timeout", decision.to_dict(), {}, {"decision_log": str(evidence_path), "timeout": timeout})
                return ToolResult("timeout", f"{tool_name} timed out after {timeout}s.", result | {"decision": decision.to_dict()}, {"decision_log": str(evidence_path), "tool_run": result.get("artifact_path", "")})
            raw_output = completed.stdout or ""
            status = "executed" if completed.returncode == 0 else "failed"
            completed_payload = {"exit_code": completed.returncode, "stderr_tail": redact_secrets(completed.stderr[-2000:])}
        parsed = parser(raw_output or "") if raw_output is not None else {"items": [], "summary": {"count": 0}}
        metadata = {"decision_log": str(evidence_path), "execute": bool(args.get("execute", False)), **completed_payload}
        result = self._record_tool_run(tool_name, target, command, status, decision.to_dict(), parsed, metadata, raw_output=raw_output or "")
        message = f"{tool_name} {status}; structured run #{result['run_id']} recorded."
        if status == "dry_run":
            message = f"{tool_name} allowed but not executed; pass execute=true or provide stdout/input_file to parse. Structured run #{result['run_id']} recorded."
        return ToolResult(status, message, result | {"decision": decision.to_dict()}, {"decision_log": str(evidence_path), "tool_run": result.get("artifact_path", "")})

    def _record_tool_run(self, tool_name: str, target: str, command: str, status: str, decision: dict[str, Any], parsed: dict[str, Any], metadata: dict[str, Any], raw_output: str = "") -> dict[str, Any]:
        out_dir = self.harness.store.root / "agent" / "tool-runs"
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = out_dir / f"{tool_name}-{uuid.uuid4().hex[:10]}.json"
        run_id = self.store.create_tool_run(self.session_id, tool_name, target, redact_secrets(command), status, _redact_value(decision), _redact_value(parsed), str(artifact_path), _redact_value(metadata))
        payload = {
            "run_id": run_id,
            "tool_name": tool_name,
            "target": target,
            "command": redact_secrets(command),
            "status": status,
            "decision": _redact_value(decision),
            "parsed": _redact_value(parsed),
            "metadata": _redact_value(metadata),
            "raw_output_tail": redact_secrets((raw_output or "")[-8000:]),
            "created_at": utc_now(),
        }
        artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"run_id": run_id, "tool_name": tool_name, "target": target, "status": status, "parsed": _redact_value(parsed), "artifact_path": str(artifact_path), "metadata": _redact_value(metadata)}

    def list_tool_runs(self, args: dict[str, Any]) -> ToolResult:
        runs = self.store.list_tool_runs(self.session_id, limit=int(args.get("limit", 50)), tool_name=str(args.get("tool_name") or "") or None)
        return ToolResult("ok", f"{len(runs)} structured tool runs returned.", {"runs": [_redacted_mapping(run) for run in runs]})

    def get_tool_run(self, args: dict[str, Any]) -> ToolResult:
        run = self.store.get_tool_run(int(args.get("id") or args.get("run_id")))
        if not run:
            return ToolResult("error", "Structured tool run not found.")
        return ToolResult("ok", f"Structured tool run #{run['id']} returned.", {"run": _redacted_mapping(run)})

    def create_finding(self, args: dict[str, Any]) -> ToolResult:
        title = str(args.get("title") or "").strip()
        if not title:
            return ToolResult("error", "title is required.")
        evidence = self._finding_evidence_from_args(args)
        finding_id = self.store.create_finding(
            self.session_id,
            title=title,
            severity=_normalize_severity(str(args.get("severity") or "Informational")),
            status=_normalize_finding_status(str(args.get("status") or "draft")),
            description=str(args.get("description") or ""),
            impact=str(args.get("impact") or ""),
            recommendation=str(args.get("recommendation") or ""),
            evidence=evidence,
            tags=str(args.get("tags") or ""),
        )
        finding = self.store.get_finding(finding_id) or {}
        self.store.audit(self.session_id, "finding_created", {"id": finding_id, "title": redact_secrets(title), "severity": finding.get("severity"), "status": finding.get("status")})
        return ToolResult("ok", f"Finding #{finding_id} created.", {"finding": _redacted_mapping(finding)})

    def update_finding(self, args: dict[str, Any]) -> ToolResult:
        finding_id = int(args.get("id") or args.get("finding_id"))
        existing = self.store.get_finding(finding_id)
        if not existing:
            return ToolResult("error", "Finding not found.")
        evidence = None
        new_evidence = self._finding_evidence_from_args(args)
        if new_evidence:
            evidence = (existing.get("evidence") or []) + new_evidence if args.get("append_evidence", True) else new_evidence
        finding = self.store.update_finding(
            finding_id,
            title=str(args["title"]) if "title" in args else None,
            severity=_normalize_severity(str(args["severity"])) if "severity" in args else None,
            status=_normalize_finding_status(str(args["status"])) if "status" in args else None,
            description=str(args["description"]) if "description" in args else None,
            impact=str(args["impact"]) if "impact" in args else None,
            recommendation=str(args["recommendation"]) if "recommendation" in args else None,
            evidence=evidence,
            tags=str(args["tags"]) if "tags" in args else None,
        )
        self.store.audit(self.session_id, "finding_updated", {"id": finding_id, "status": finding.get("status") if finding else None})
        return ToolResult("ok", f"Finding #{finding_id} updated.", {"finding": _redacted_mapping(finding or {})})

    def list_findings(self, args: dict[str, Any]) -> ToolResult:
        findings = self.store.list_findings(self.session_id, status=str(args.get("status") or "all"), limit=int(args.get("limit", 50)))
        return ToolResult("ok", f"{len(findings)} findings returned.", {"findings": [_redacted_mapping(row) for row in findings]})

    def get_finding(self, args: dict[str, Any]) -> ToolResult:
        finding = self.store.get_finding(int(args.get("id") or args.get("finding_id")))
        if not finding:
            return ToolResult("error", "Finding not found.")
        return ToolResult("ok", f"Finding #{finding['id']} returned.", {"finding": _redacted_mapping(finding)})

    def finding_export(self, args: dict[str, Any]) -> ToolResult:
        finding = self.store.get_finding(int(args.get("id") or args.get("finding_id")))
        if not finding:
            return ToolResult("error", "Finding not found.")
        evidence_lines = _finding_evidence_lines(finding.get("evidence") or [])
        affected_assets = sorted({str(item.get("target")) for item in finding.get("evidence", []) if isinstance(item, dict) and item.get("target")})
        report = FindingInput(
            title=finding["title"],
            severity=finding["severity"],
            impact=finding.get("impact") or "Impact should be finalized during QA based on confirmed evidence.",
            description=finding.get("description") or "",
            supporting_evidence=evidence_lines,
            affected_assets=affected_assets,
            recommendation=finding.get("recommendation") or "",
            confirmed=finding.get("status") in {"confirmed", "accepted-risk", "resolved"},
            limitations=[] if finding.get("status") == "confirmed" else [f"Current lifecycle status is {finding.get('status')}; validate evidence before client delivery."],
        )
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "findings",
            str(args.get("out") or "").strip(),
            f"finding-{finding['id']}-{safe_report_filename(finding['title'])}.md",
            suffix=".md",
        )
        path = FindingMarkdownExporter().write_finding(report, out)
        return ToolResult("ok", f"Finding #{finding['id']} exported: {path}", {"finding": _redacted_mapping(finding), "path": str(path)}, {"markdown": str(path)})

    def finding_review(self, args: dict[str, Any]) -> ToolResult:
        """Review a stored finding for operator/report-readiness without target activity."""

        finding = self.store.get_finding(int(args.get("id") or args.get("finding_id")))
        if not finding:
            return ToolResult("error", "Finding not found.")
        review = self._build_finding_review(finding)
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "findings",
            str(args.get("out") or "").strip(),
            f"finding-{finding['id']}-review-{safe_report_filename(finding['title'])}.md",
            suffix=".md",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        markdown = _finding_review_markdown(finding, review)
        out.write_text(markdown, encoding="utf-8")
        self.store.audit(self.session_id, "finding_reviewed", {"id": finding["id"], "readiness": review["readiness"], "blocking_gaps": len(review["blocking_gaps"]), "advisory_gaps": len(review["advisory_gaps"])})
        return ToolResult("ok", f"Finding #{finding['id']} review: {review['readiness']}.", {"finding": _redacted_mapping(finding), "review": review}, {"markdown": str(out)})

    def _build_finding_review(self, finding: dict[str, Any]) -> dict[str, Any]:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        status = str(finding.get("status") or "draft")
        linked_runs: list[dict[str, Any]] = []
        artifact_refs: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []

        def add_check(name: str, passed: bool, severity: str, detail: str) -> None:
            checks.append({"name": name, "passed": bool(passed), "severity": severity, "detail": redact_secrets(detail)})

        report_ready_status = status in {"confirmed", "resolved", "accepted-risk"}
        add_check("Lifecycle status is operator-confirmed", report_ready_status, "blocking", f"Current status: {status}")
        for field_name, label in (("description", "technical description"), ("impact", "impact statement"), ("recommendation", "remediation guidance")):
            value = str(finding.get(field_name) or "").strip()
            add_check(f"Finding has {label}", len(value) >= 20, "blocking", f"{field_name} length: {len(value)}")

        add_check("At least one evidence reference is linked", bool(evidence), "blocking", f"Evidence references: {len(evidence)}")
        evidence_text = redact_secrets(json.dumps(evidence, sort_keys=True, default=str)) or ""
        target_refs: set[str] = set()
        missing_artifacts = 0
        existing_artifacts = 0
        for item in evidence:
            if not isinstance(item, dict):
                continue
            for key in ("target", "affected_asset", "url", "matched_at"):
                if item.get(key):
                    target_refs.add(str(item.get(key)))
            if item.get("type") == "tool_run" and item.get("id"):
                run = self.store.get_tool_run(int(item.get("id")))
                if run:
                    redacted_run = _redacted_mapping(run)
                    linked_runs.append(redacted_run)
                    if run.get("target"):
                        target_refs.add(str(run.get("target")))
                    artifact_path = str(run.get("artifact_path") or "")
                    artifact_status = _artifact_status(artifact_path)
                    if artifact_status["exists"]:
                        existing_artifacts += 1
                    elif artifact_path:
                        missing_artifacts += 1
                    artifact_refs.append({"source": f"tool_run:{run['id']}", "path": artifact_path, **artifact_status})
                else:
                    missing_artifacts += 1
                    artifact_refs.append({"source": f"tool_run:{item.get('id')}", "path": "", "exists": False, "note": "linked tool run not found"})
            for key in ("artifact_path", "path", "file"):
                if item.get(key):
                    artifact_path = str(item.get(key) or "")
                    artifact_status = _artifact_status(artifact_path, root=self.harness.store.root)
                    if artifact_status["exists"]:
                        existing_artifacts += 1
                    else:
                        missing_artifacts += 1
                    artifact_refs.append({"source": key, "path": artifact_path, **artifact_status})
        add_check("Linked evidence artifacts are present", existing_artifacts > 0 or (bool(evidence) and not artifact_refs), "blocking" if missing_artifacts else "advisory", f"Existing artifacts: {existing_artifacts}; missing artifacts: {missing_artifacts}")
        add_check("Affected asset/target is explicit", bool(target_refs), "blocking", f"Targets/assets: {', '.join(sorted(target_refs)) or 'none'}")

        lower_blob = "\n".join([evidence_text, str(finding.get("description") or ""), str(finding.get("impact") or ""), str(finding.get("recommendation") or "")]).lower()
        add_check("Negative control or baseline is referenced", any(token in lower_blob for token in ("negative control", "baseline", "control request", "control account", "known-good")), "advisory", "Look for a scoped negative control proving the issue is not expected behaviour.")
        add_check("Reproduction material is referenced", any(token in lower_blob for token in ("repro", "step", "request", "response", "curl", "http")), "advisory", "Look for replayable request/response or step evidence.")
        add_check("Side effects / cleanup are addressed", any(token in lower_blob for token in ("no state change", "read-only", "cleanup", "reversible", "no side effects", "side effect")), "advisory", "Document whether validation changed state and any cleanup performed.")

        blocking_gaps = [check["detail"] for check in checks if check["severity"] == "blocking" and not check["passed"]]
        advisory_gaps = [check["detail"] for check in checks if check["severity"] == "advisory" and not check["passed"]]
        if blocking_gaps:
            readiness = "needs_evidence"
        elif advisory_gaps:
            readiness = "ready_with_advisories"
        else:
            readiness = "ready_for_operator_review"
        passed = len([check for check in checks if check["passed"]])
        score = {"passed": passed, "total": len(checks), "percent": round((passed / len(checks)) * 100, 1) if checks else 0.0}
        recommendations = _finding_review_recommendations(blocking_gaps, advisory_gaps, status)
        return _redacted_mapping({
            "readiness": readiness,
            "score": score,
            "checks": checks,
            "blocking_gaps": blocking_gaps,
            "advisory_gaps": advisory_gaps,
            "linked_tool_runs": linked_runs,
            "artifact_refs": artifact_refs,
            "affected_assets": sorted(target_refs),
            "recommendations": recommendations,
        })

    def _finding_evidence_from_args(self, args: dict[str, Any]) -> list[dict[str, Any]]:
        evidence = _parse_evidence_arg(args.get("evidence"))
        run_ids = _parse_id_list(args.get("tool_run_ids") or args.get("tool_run_id") or args.get("run_ids"))
        for run_id in run_ids:
            run = self.store.get_tool_run(run_id)
            if run:
                evidence.append({"type": "tool_run", "id": run_id, "tool_name": run.get("tool_name"), "target": run.get("target"), "status": run.get("status"), "artifact_path": run.get("artifact_path")})
        return [_redact_value(item) for item in evidence]

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

    def hindsight_retain(self, args: dict[str, Any]) -> ToolResult:
        content = str(args.get("content") or args.get("value") or "").strip()
        if not content:
            return ToolResult("error", "content is required.")
        context = str(args.get("context") or "").strip()
        tags = str(args.get("tags") or "hindsight").strip()
        key = str(args.get("key") or "").strip()
        if not key:
            digest = hashlib.sha256(f"{context}\n{content}".encode("utf-8")).hexdigest()[:16]
            key = f"hindsight-{digest}"
        value = content if not context else f"[{context}] {content}"
        mem_id = self.store.remember(key, value, tags=tags)
        self.store.audit(self.session_id, "hindsight_retain", {"key": key, "context": context, "tags": tags})
        return ToolResult("ok", f"Retained Hindsight-style memory {mem_id}: {key}", {"id": mem_id, "key": key, "context": context, "tags": tags})

    def hindsight_recall(self, args: dict[str, Any]) -> ToolResult:
        query = str(args.get("query") or "")
        limit = int(args.get("limit", 10))
        memories = self.store.recall(query, limit=limit)
        messages = self.store.search_all_messages(query, limit=limit) if query else []
        nodes = self.store.search_context_nodes(self.session_id, query, limit=limit) if query else []
        return ToolResult("ok", f"Found {len(memories)} memories, {len(messages)} messages, and {len(nodes)} context node(s).", {"memories": memories, "messages": messages, "context_nodes": nodes})

    def hindsight_reflect(self, args: dict[str, Any]) -> ToolResult:
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
            resolved = self._contained_workspace_candidate(path)
            if resolved is None or not resolved.is_file():
                continue
            try:
                display_path = str(resolved.relative_to(self.workspace_root.resolve()))
            except ValueError:
                continue
            try:
                for number, line in enumerate(resolved.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if pattern.search(line):
                        matches.append({"path": display_path, "line": number, "text": line[:500]})
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
        isolate = bool(args.get("isolate", True))
        delegation_id = self.store.create_delegation(self.session_id, prompt, task_specs)
        out_dir = self.harness.store.root / "agent" / "delegations" / f"delegation-{delegation_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        parent_session = self.store.get_session(self.session_id) or {}
        engagement_path = str(parent_session.get("engagement_path") or self.roe.name)
        prepared: list[dict[str, Any]] = []
        for idx, task in enumerate(task_specs, 1):
            role = str(task.get("role") or "impact")
            task_prompt = str(task.get("prompt") or task.get("goal") or prompt)
            task_context = str(task.get("context") or prompt)
            child_session_id = ""
            child_session_name = ""
            if isolate:
                child_session_name = f"delegation-{delegation_id}-task-{idx}-{_safe_filename(role)}"
                child_session_id = self.store.get_or_create_session(child_session_name, engagement_path)
                self.store.append_message(child_session_id, "user", task_prompt, {"delegation_id": delegation_id, "parent_session_id": self.session_id, "role": role})
            prepared.append({"index": idx, "role": role, "prompt": task_prompt, "context": task_context, "child_session_id": child_session_id, "child_session_name": child_session_name})
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(6, len(prepared))) as pool:
            future_map = {pool.submit(self.model_adapter.generate, item["role"], item["prompt"], item["context"]): item for item in prepared}
            for future in as_completed(future_map):
                item = future_map[future]
                idx = int(item["index"])
                role = str(item["role"])
                task_prompt = str(item["prompt"])
                try:
                    content = redact_secrets(future.result().content) or ""
                    status = "ok"
                except Exception as exc:
                    content = f"ERROR: {exc}"
                    status = "error"
                if item.get("child_session_id"):
                    self.store.append_message(str(item["child_session_id"]), "assistant", content, {"delegation_id": delegation_id, "parent_session_id": self.session_id, "role": role, "status": status})
                path = out_dir / f"task-{idx}-{_safe_filename(role)}.md"
                child_line = f"Child session: {item.get('child_session_id') or 'none'}\n\n"
                path.write_text(f"# Delegated Task {idx}: {role}\n\n{child_line}Prompt: {redact_secrets(task_prompt)}\n\n{content}\n", encoding="utf-8")
                results.append({"index": idx, "role": role, "prompt": redact_secrets(task_prompt), "status": status, "content": content, "artifact": str(path), "child_session_id": item.get("child_session_id") or "", "child_session_name": item.get("child_session_name") or ""})
        results.sort(key=lambda item: int(item["index"]))
        summary_path = out_dir / "SUMMARY.md"
        summary_lines = ["# Phobos Local Delegation", "", f"Delegation: {delegation_id}", f"Parent session: {self.session_id}", f"Isolated child sessions: {isolate}", f"Prompt: {redact_secrets(prompt)}", ""]
        for result in results:
            session_note = f" — child session `{result.get('child_session_id')}`" if result.get("child_session_id") else ""
            summary_lines += [f"## Task {result['index']} — {result['role']} ({result['status']}){session_note}", "", str(result["content"])[:4000], ""]
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
        status = "ok" if all(result["status"] == "ok" for result in results) else "error"
        delegation = self.store.complete_delegation(delegation_id, status, results, {"summary": str(summary_path), "dir": str(out_dir), "isolated_child_sessions": isolate})
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

    def safety_preflight(self, args: dict[str, Any]) -> ToolResult:
        checks = _preflight_checks(
            self.roe,
            self.harness.store.root,
            self.workspace_root,
            self.store,
            self.session_id,
            self.blocked_tools,
            self.confirm_tools,
            sorted(self.tool_specs),
            self.runtime_metadata,
        )
        counts = _preflight_counts(checks)
        readiness = "blocked" if counts.get("fail", 0) else "review" if counts.get("warn", 0) else "ready"
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "preflight",
            str(args.get("out") or "").strip(),
            f"safety-preflight-{stamp}.md",
            suffix=".md",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        report = _preflight_markdown(self.roe.name, readiness, checks, counts)
        out.write_text(report, encoding="utf-8")
        data = _redacted_mapping({
            "readiness": readiness,
            "counts": counts,
            "checks": checks,
            "path": str(out),
            "no_target_activity": True,
            "secret_values_redacted": True,
            "plaintext_db_caveat": "Local SQLite/WAL/SHM files remain plaintext unless the deployment adds filesystem encryption, SQLCipher, or uses db-seal backups with plaintext removal while runtimes are closed.",
        })
        return ToolResult(
            "ok",
            f"Safety preflight {readiness}: {counts.get('fail', 0)} fail, {counts.get('warn', 0)} warn, {counts.get('pass', 0)} pass.",
            data,
            {"markdown": str(out)},
        )

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
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "sealed",
            str(args.get("out") or "").strip(),
            f"session-{uuid.uuid4().hex[:10]}.sealed.json",
            suffix=".json",
        )
        handoff = self.export_session({"out": f"sealed-source-{uuid.uuid4().hex[:8]}.json", "message_limit": int(args.get("message_limit", 1000))})
        if handoff.status != "ok":
            return handoff
        source_path = Path(handoff.data["path"])
        payload: dict[str, Any] = {"handoff": json.loads(source_path.read_text(encoding="utf-8"))}
        if args.get("include_pack", False):
            pack = self.export_pack({"out": f"sealed-source-{uuid.uuid4().hex[:8]}.zip"})
            payload["pack_manifest"] = pack.data.get("manifest", {}) if pack.status == "ok" else {"error": pack.message}
        sealed = seal_bytes(json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"), passphrase, aad=b"phobos-agent-sealed-export")
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
        tool_runs = self.store.list_tool_runs(self.session_id, limit=100)
        findings = self.store.list_findings(self.session_id, status="all", limit=100)
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
            "tool_runs": len(tool_runs),
            "findings": len(findings),
            "open_findings": len([finding for finding in findings if finding["status"] not in {"resolved", "accepted-risk", "false-positive"}]),
            "processes": len(processes),
            "policy": {"blocked_tools": sorted(self.blocked_tools), "confirm_tools": sorted(self.confirm_tools)},
            "evidence_root": str(self.harness.store.root),
        }
        return ToolResult("ok", "Runtime status assembled.", data)

    def evidence_timeline(self, args: dict[str, Any]) -> ToolResult:
        limit = max(1, min(int(args.get("limit", 100)), 500))
        order = str(args.get("order") or "desc").strip().lower()
        reverse = order not in {"asc", "oldest", "oldest-first"}
        raw_categories = str(args.get("category") or args.get("categories") or "").strip()
        category_filter = {part.strip().lower().replace("-", "_") for part in re.split(r"[,\s]+", raw_categories) if part.strip()} if raw_categories else set()
        include_audit = bool(args.get("include_audit", True))
        entries: list[dict[str, Any]] = []

        def add(timestamp: str | None, category: str, title: str, *, status: str = "", ref: str = "", summary: str = "", artifacts: list[str] | None = None, data: dict[str, Any] | None = None) -> None:
            category_name = category.strip().lower().replace("-", "_")
            if category_filter and category_name not in category_filter:
                return
            entry = {
                "timestamp": str(timestamp or ""),
                "category": category_name,
                "status": str(status or ""),
                "ref": str(ref or ""),
                "title": str(title or ""),
                "summary": str(summary or ""),
                "artifacts": [str(item) for item in (artifacts or []) if str(item)],
            }
            if data:
                entry["data"] = data
            entries.append(_redacted_mapping(entry))

        for run in self.store.list_tool_runs(self.session_id, limit=max(limit, 100)):
            parsed = run.get("parsed") if isinstance(run.get("parsed"), dict) else {}
            parsed_summary = parsed.get("summary") if isinstance(parsed.get("summary"), dict) else {}
            summary_parts = [str(run.get("command") or "").strip()]
            if parsed_summary:
                summary_parts.append("parsed=" + json.dumps(parsed_summary, sort_keys=True))
            add(
                run.get("created_at"),
                "tool_run",
                f"{run.get('tool_name')} against {run.get('target')}",
                status=str(run.get("status") or ""),
                ref=f"tool_run:{run.get('id')}",
                summary="; ".join(part for part in summary_parts if part),
                artifacts=[str(run.get("artifact_path") or "")],
                data={"id": run.get("id"), "tool_name": run.get("tool_name"), "target": run.get("target"), "parsed_summary": parsed_summary},
            )

        for finding in self.store.list_findings(self.session_id, status="all", limit=max(limit, 100)):
            add(
                finding.get("updated_at") or finding.get("created_at"),
                "finding",
                f"{finding.get('severity')} — {finding.get('title')}",
                status=str(finding.get("status") or ""),
                ref=f"finding:{finding.get('id')}",
                summary=str(finding.get("description") or finding.get("impact") or "")[:600],
                data={"id": finding.get("id"), "evidence_count": len(finding.get("evidence") or [])},
            )

        for approval_status in ("pending", "approved", "denied"):
            for approval in self.store.list_approvals(self.session_id, status=approval_status):
                add(
                    approval.get("resolved_at") or approval.get("requested_at"),
                    "approval",
                    f"{approval.get('tool_name')} approval #{approval.get('id')}",
                    status=str(approval.get("status") or approval_status),
                    ref=f"approval:{approval.get('id')}",
                    summary=json.dumps(approval.get("args", {}), sort_keys=True)[:800],
                    data={"id": approval.get("id"), "tool_name": approval.get("tool_name"), "decision": approval.get("decision", {})},
                )

        for task in self.store.list_tasks(self.session_id, status="all", limit=max(limit, 100)):
            add(
                task.get("updated_at") or task.get("created_at"),
                "task",
                str(task.get("content") or "")[:240],
                status=str(task.get("status") or ""),
                ref=f"task:{task.get('id')}",
                data={"id": task.get("id")},
            )

        for process in self.store.list_processes(self.session_id, limit=max(limit, 100)):
            add(
                process.get("ended_at") or process.get("started_at"),
                "process",
                f"{process.get('purpose')} on {process.get('target')}",
                status=str(process.get("status") or ""),
                ref=f"process:{process.get('id')}",
                summary=str(process.get("command") or "")[:800],
                artifacts=[str(process.get("stdout_path") or ""), str(process.get("stderr_path") or "")],
                data={"id": process.get("id"), "exit_code": process.get("exit_code")},
            )

        for delegation in self.store.list_delegations(self.session_id, limit=max(limit, 100)):
            add(
                delegation.get("updated_at") or delegation.get("created_at"),
                "delegation",
                str(delegation.get("prompt") or "")[:240],
                status=str(delegation.get("status") or ""),
                ref=f"delegation:{delegation.get('id')}",
                artifacts=[str(value) for value in (delegation.get("artifacts") or {}).values()],
                data={"id": delegation.get("id"), "task_count": len(delegation.get("tasks") or []), "result_count": len(delegation.get("results") or [])},
            )

        for media in self.store.list_media_artifacts(self.session_id, limit=max(limit, 100)):
            add(
                media.get("created_at"),
                "media",
                f"{media.get('kind')} artifact #{media.get('id')}",
                status=str(media.get("mime_type") or ""),
                ref=f"media:{media.get('id')}",
                summary=f"{media.get('size')} bytes sha256={media.get('sha256')}",
                artifacts=[str(media.get("artifact_path") or "")],
                data={"id": media.get("id"), "kind": media.get("kind"), "metadata": media.get("metadata", {})},
            )

        if include_audit:
            for row in self.store.list_audit(self.session_id, limit=max(limit, 100)):
                event = str(row.get("event") or "")
                if event == "gateway_access":
                    continue
                data = row.get("data") if isinstance(row.get("data"), dict) else {}
                title, status, summary = _timeline_audit_preview(event, data)
                add(
                    row.get("created_at"),
                    "audit",
                    title,
                    status=status,
                    ref=f"audit:{row.get('id')}",
                    summary=summary,
                    data={"id": row.get("id"), "event": event},
                )

        entries.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=reverse)
        total_entries = len(entries)
        entries = entries[:limit]
        counts: dict[str, int] = {}
        for entry in entries:
            category = str(entry.get("category") or "unknown")
            counts[category] = counts.get(category, 0) + 1
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "timelines",
            str(args.get("out") or "").strip(),
            f"evidence-timeline-{stamp}.md",
            suffix=".md",
        )
        if out.suffix.lower() != ".md":
            out = out.with_suffix(".md")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_timeline_markdown(self.roe.name, entries, counts, total_entries, category_filter, include_audit), encoding="utf-8")
        return ToolResult("ok", f"Evidence timeline assembled with {len(entries)} event(s).", {"entries": entries, "counts": counts, "total_entries": total_entries, "order": "desc" if reverse else "asc", "category_filter": sorted(category_filter), "include_audit": include_audit, "path": str(out)}, {"markdown": str(out)})

    def export_pack(self, args: dict[str, Any]) -> ToolResult:
        export_dir = self.harness.store.root / "agent" / "exports"
        stamp = utc_now().replace(":", "").replace("+0000", "Z").replace("+00:00", "Z")
        out_path = _scoped_artifact_output_path(
            self.harness.store.root,
            "exports",
            str(args.get("out") or "").strip(),
            f"phobos-agent-pack-{stamp}.zip",
            suffix=".zip",
        )

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
            "tool_runs": [_redacted_mapping(row) for row in self.store.list_tool_runs(self.session_id, limit=500)],
            "findings": [_redacted_mapping(row) for row in self.store.list_findings(self.session_id, status="all", limit=500)],
            "processes": self.store.list_processes(self.session_id, limit=200),
            "audit": self.store.list_audit(self.session_id, limit=200),
        }
        text_suffixes = {".json", ".jsonl", ".md", ".txt", ".log", ".http", ".csv", ".yaml", ".yml"}

        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _zip_text(archive, "PACK_README.md", _pack_readme(self.roe.name))
            _zip_json(archive, "runtime/state.json", state)
            for path in sorted(evidence_root.rglob("*")):
                try:
                    resolved = path.resolve()
                    rel = path.relative_to(evidence_root).as_posix()
                except (OSError, ValueError):
                    manifest["skipped"].append({"path": str(path), "reason": "path could not be safely resolved"})
                    continue
                if not _is_relative_to(resolved, evidence_root):
                    manifest["skipped"].append({"path": rel, "reason": "symlink target outside evidence root"})
                    continue
                if not resolved.is_file():
                    continue
                if _is_relative_to(resolved, export_dir.resolve()):
                    continue
                if resolved.stat().st_size > 2_000_000:
                    manifest["skipped"].append({"path": rel, "reason": "larger than 2MB"})
                    continue
                if path.suffix.lower() not in text_suffixes:
                    manifest["skipped"].append({"path": rel, "reason": "non-text artifact omitted from redacted pack"})
                    continue
                raw = resolved.read_text(encoding="utf-8", errors="replace")
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
        findings = self.store.list_findings(self.session_id, status="all", limit=100)
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
            "open_findings": len([finding for finding in findings if finding["status"] not in {"resolved", "accepted-risk", "false-positive"}]),
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
        lines += ["", "## Findings", ""]
        if findings:
            for finding in findings:
                lines.append(f"- [{finding['status']}] #{finding['id']} {finding['severity']} — {redact_secrets(finding['title'])}")
        else:
            lines.append("- No findings recorded.")
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
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "briefings",
            str(args.get("out") or "").strip(),
            f"operator-briefing-{stamp}.md",
            suffix=".md",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        redacted_tasks = [_redacted_mapping(task) for task in tasks]
        return ToolResult("ok", f"Operator briefing written: {out}", {"status": status, "tasks": redacted_tasks, "findings": [_redacted_mapping(row) for row in findings], "pending_approvals": [_redacted_mapping(row) for row in approvals], "briefing": text[:6000]}, {"markdown": str(out)})

    def export_session(self, args: dict[str, Any]) -> ToolResult:
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "session-exports",
            str(args.get("out") or "").strip(),
            f"session-handoff-{stamp}.json",
            suffix=".json",
        )
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
            "tool_runs": [_redacted_mapping(row) for row in self.store.list_tool_runs(self.session_id, limit=500)],
            "findings": [_redacted_mapping(row) for row in self.store.list_findings(self.session_id, status="all", limit=500)],
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

    def _contained_workspace_candidate(self, path: Path) -> Path | None:
        """Resolve a candidate path and return it only if it stays inside the workspace.

        Workspace globbing can surface symlink files. pathlib's is_file()/read_text()
        follow symlinks, so a symlink inside the workspace could otherwise expose
        an operator or host file outside the engagement workspace during search.
        """
        try:
            root = self.workspace_root.resolve()
            resolved = path.resolve()
            if os.path.commonpath([str(root), str(resolved)]) != str(root):
                return None
            return resolved
        except (OSError, ValueError):
            return None

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


def _build_nmap_command(target: str, ports: str, profile: str) -> str:
    profile = profile.strip().lower() or "version"
    args = ["nmap", "--reason", "-oX", "-"]
    if profile in {"version", "safe"}:
        args.append("-sV")
    elif profile == "quick":
        args.extend(["-T3", "--top-ports", "100"])
    else:
        args.append("-sV")
    if ports:
        if not re.fullmatch(r"[0-9,\- ]{1,200}", ports):
            raise ValueError("ports may contain only digits, commas, spaces, and ranges")
        args.extend(["-p", ports.replace(" ", "")])
    args.append(target)
    return " ".join(shlex.quote(part) for part in args)


def _build_httpx_command(url: str) -> str:
    return " ".join(shlex.quote(part) for part in [_scanner_binary("httpx", "PHOBOS_HTTPX_BIN"), "-json", "-status-code", "-title", "-tech-detect", "-follow-redirects", "-u", url])


def _scanner_binary(name: str, env_var: str) -> str:
    candidates = [os.environ.get(env_var), str(Path.home() / "go" / "bin" / name), f"/root/go/bin/{name}", shutil.which(name), name]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if Path(candidate).is_absolute():
            path = Path(candidate)
            if path.exists() and os.access(path, os.X_OK):
                return str(path)
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return name


def _build_nuclei_command(url: str, rate_limit: int, templates: str = "") -> str:
    # Keep prohibited words such as DoS/destructive out of the shell command text
    # itself so the ROE guardrail does not false-positive on a safety exclusion.
    # Real execution requires an explicit operator-selected template path; this
    # prevents accidental broad default-template runs in smoke/VPS contexts.
    args = ["nuclei", "-jsonl", "-silent", "-duc", "-u", url, "-rl", str(rate_limit)]
    if templates:
        args.extend(["-t", templates])
    else:
        args.extend(["-severity", "info,low,medium,high,critical", "-etags", "intrusive,fuzz"])
    return " ".join(shlex.quote(part) for part in args)


def _build_ffuf_command(url: str, wordlist: str, rate: int) -> str:
    fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
    args = ["ffuf", "-json", "-u", fuzz_url, "-w", wordlist or "WORDLIST_REQUIRED", "-rate", str(rate), "-mc", "200,204,301,302,307,308,401,403"]
    return " ".join(shlex.quote(part) for part in args)


def _normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        return value
    return "https://" + value


def _load_structured_output(args: dict[str, Any]) -> str | None:
    for key in ("stdout", "output"):
        value = args.get(key)
        if value is not None:
            return str(value)
    input_file = str(args.get("input_file") or args.get("file") or "").strip()
    if input_file:
        path = Path(input_file).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"structured output file not found: {path}")
        return path.read_text(encoding="utf-8", errors="replace")
    return None


def _parse_nmap_output(text: str) -> dict[str, Any]:
    ports: list[dict[str, Any]] = []
    hosts: set[str] = set()
    stripped = text.strip()
    if stripped.startswith("<"):
        try:
            root = ET.fromstring(stripped)
            for host in root.findall(".//host"):
                addr = ""
                addr_el = host.find("address")
                if addr_el is not None:
                    addr = addr_el.attrib.get("addr", "")
                    if addr:
                        hosts.add(addr)
                for port in host.findall(".//port"):
                    state_el = port.find("state")
                    service_el = port.find("service")
                    state = state_el.attrib.get("state", "") if state_el is not None else ""
                    if state != "open":
                        continue
                    ports.append({
                        "host": addr,
                        "port": int(port.attrib.get("portid", "0") or 0),
                        "protocol": port.attrib.get("protocol", "tcp"),
                        "state": state,
                        "service": service_el.attrib.get("name", "") if service_el is not None else "",
                        "product": service_el.attrib.get("product", "") if service_el is not None else "",
                        "version": service_el.attrib.get("version", "") if service_el is not None else "",
                    })
        except ET.ParseError:
            pass
    if not ports:
        current_host = ""
        for line in text.splitlines():
            host_match = re.search(r"Nmap scan report for\s+(.+)$", line)
            if host_match:
                current_host = host_match.group(1).strip()
                hosts.add(current_host)
            match = re.match(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)$", line.strip())
            if match and match.group(3) == "open":
                ports.append({"host": current_host, "port": int(match.group(1)), "protocol": match.group(2), "state": match.group(3), "service": match.group(4), "banner": match.group(5).strip()})
    return {"hosts": sorted(hosts), "open_ports": ports, "summary": {"hosts": len(hosts) or (1 if ports else 0), "open_ports": len(ports)}}


def _json_line_objects(text: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            objects.append(item)
    return objects


def _parse_httpx_output(text: str) -> dict[str, Any]:
    responses: list[dict[str, Any]] = []
    for item in _json_line_objects(text):
        responses.append({"url": item.get("url") or item.get("input") or item.get("host"), "status_code": item.get("status_code") or item.get("status-code"), "title": item.get("title", ""), "technologies": item.get("tech") or item.get("technologies") or [], "webserver": item.get("webserver") or item.get("server") or ""})
    if not responses:
        for line in text.splitlines():
            match = re.search(r"(https?://\S+)\s+\[(\d{3})\]", line)
            if match:
                responses.append({"url": match.group(1), "status_code": int(match.group(2)), "title": "", "technologies": [], "webserver": ""})
    return {"responses": responses, "summary": {"count": len(responses), "status_codes": sorted({str(item.get('status_code')) for item in responses if item.get('status_code')})}}


def _parse_nuclei_output(text: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for item in _json_line_objects(text):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        findings.append({"template_id": item.get("template-id") or item.get("template_id"), "name": info.get("name") or item.get("name", ""), "severity": info.get("severity") or item.get("severity", "unknown"), "matched_at": item.get("matched-at") or item.get("matched_at") or item.get("host"), "type": item.get("type", ""), "matcher": item.get("matcher-name") or item.get("matcher_name") or ""})
    return {"findings": findings, "summary": {"count": len(findings), "severities": sorted({str(item.get('severity')) for item in findings if item.get('severity')})}}


def _parse_ffuf_output(text: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        data = {}
    raw_results = data.get("results", []) if isinstance(data, dict) else []
    if not raw_results:
        raw_results = _json_line_objects(text)
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not url and isinstance(item.get("input"), dict):
            url = item.get("input", {}).get("FUZZ")
        results.append({"url": url, "status": item.get("status"), "length": item.get("length"), "words": item.get("words"), "lines": item.get("lines"), "redirectlocation": item.get("redirectlocation", "")})
    return {"results": results, "summary": {"count": len(results), "statuses": sorted({str(item.get('status')) for item in results if item.get('status')})}}


def _parse_id_list(value: Any) -> list[int]:
    if value is None or value == "":
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        out: list[int] = []
        for item in value:
            out.extend(_parse_id_list(item))
        return out
    out = []
    for part in re.split(r"[,\s]+", str(value)):
        if part.strip().isdigit():
            out.append(int(part.strip()))
    return out


def _parse_evidence_arg(value: Any) -> list[dict[str, Any]]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [item if isinstance(item, dict) else {"type": "note", "value": str(item)} for item in value]
    if isinstance(value, dict):
        return [value]
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return _parse_evidence_arg(parsed)
    except json.JSONDecodeError:
        return [{"type": "note", "value": part.strip()} for part in re.split(r"[\n,]+", text) if part.strip()]


def _normalize_severity(value: str) -> str:
    lookup = {"info": "Informational", "informational": "Informational", "low": "Low", "medium": "Medium", "med": "Medium", "high": "High", "critical": "Critical", "crit": "Critical"}
    return lookup.get(value.strip().lower(), value.strip() or "Informational")


def _normalize_finding_status(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-") or "draft"
    allowed = {"draft", "needs-evidence", "confirmed", "resolved", "accepted-risk", "false-positive"}
    return normalized if normalized in allowed else "draft"


def _finding_evidence_lines(evidence: list[dict[str, Any]]) -> list[str]:
    lines = []
    for item in evidence:
        if not isinstance(item, dict):
            lines.append(str(item))
            continue
        if item.get("type") == "tool_run":
            lines.append(f"Tool run #{item.get('id')} `{item.get('tool_name')}` against `{item.get('target')}` — {item.get('artifact_path', '')}")
        elif item.get("artifact_path"):
            lines.append(str(item.get("artifact_path")))
        else:
            lines.append(redact_secrets(json.dumps(item, sort_keys=True)))
    return lines


def _scoped_artifact_output_path(evidence_root: Path, subdir: str, out_arg: str, default_name: str, *, suffix: str | None = None) -> Path:
    """Return a user-selected artifact output path only if it stays in its artifact dir.

    Runtime artifact writers are reachable through the authenticated gateway and
    chat bridges. A relative ``out`` path is useful, but it must not become a
    host-file write primitive through ``..`` traversal, absolute paths, or
    symlinks placed under the evidence tree. Resolve existing path components
    before writing so symlink destinations are checked before ``write_text()`` or
    ``ZipFile`` follows them.
    """

    root = evidence_root.resolve(strict=False)
    base_dir = (evidence_root / "agent" / subdir).resolve(strict=False) if subdir else (evidence_root / "agent").resolve(strict=False)
    if not _is_relative_to(base_dir, root):
        raise ValueError("artifact output directory escapes the engagement evidence root")
    base_dir.mkdir(parents=True, exist_ok=True)
    candidate = Path(out_arg).expanduser() if out_arg else base_dir / default_name
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    if suffix and candidate.suffix.lower() != suffix.lower():
        candidate = candidate.with_suffix(suffix)
    parent = candidate.parent.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    if not _is_relative_to(parent, base_dir) or not _is_relative_to(resolved, base_dir):
        raise ValueError(f"artifact output path escapes the {subdir or 'agent'} artifact directory")
    return candidate


def _artifact_status(path_value: str, root: Path | None = None) -> dict[str, Any]:
    if not path_value:
        return {"exists": False, "resolved": "", "note": "no artifact path recorded"}
    try:
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute() and root is not None:
            candidate = root / candidate
        exists = candidate.exists()
        resolved = str(candidate.resolve()) if exists else str(candidate)
        return {"exists": bool(exists), "resolved": redact_secrets(resolved)}
    except (OSError, RuntimeError, ValueError) as exc:
        return {"exists": False, "resolved": redact_secrets(path_value), "note": f"artifact path check failed: {exc}"}


def _finding_review_recommendations(blocking_gaps: list[str], advisory_gaps: list[str], status: str) -> list[str]:
    recommendations: list[str] = []
    if status not in {"confirmed", "resolved", "accepted-risk"}:
        recommendations.append("Keep the finding internal/candidate until the operator confirms impact and evidence quality.")
    for gap in blocking_gaps[:8]:
        recommendations.append(f"Close blocking gap: {gap}")
    for gap in advisory_gaps[:5]:
        recommendations.append(f"Improve evidence package: {gap}")
    if not recommendations:
        recommendations.append("Finding looks ready for operator QA; run /finding-export after final severity and wording review.")
    return [redact_secrets(item) or "" for item in recommendations if item]


def _finding_review_markdown(finding: dict[str, Any], review: dict[str, Any]) -> str:
    raw_score = review.get("score")
    score: dict[str, Any] = raw_score if isinstance(raw_score, dict) else {}
    lines = [
        "# Phobos Finding Review",
        "",
        f"Generated: {utc_now()}",
        f"Finding: #{finding.get('id')} {redact_secrets(str(finding.get('title') or ''))}",
        f"Severity: {redact_secrets(str(finding.get('severity') or ''))}",
        f"Lifecycle status: {redact_secrets(str(finding.get('status') or ''))}",
        f"Readiness: `{redact_secrets(str(review.get('readiness') or 'unknown'))}`",
        f"Checklist score: {score.get('passed', 0)}/{score.get('total', 0)} ({score.get('percent', 0)}%)",
        "",
        "## Blocking gaps",
        "",
    ]
    blocking = review.get("blocking_gaps") if isinstance(review.get("blocking_gaps"), list) else []
    if blocking:
        lines.extend(f"- {redact_secrets(str(gap))}" for gap in blocking)
    else:
        lines.append("- None identified.")
    lines += ["", "## Advisory improvements", ""]
    advisories = review.get("advisory_gaps") if isinstance(review.get("advisory_gaps"), list) else []
    if advisories:
        lines.extend(f"- {redact_secrets(str(gap))}" for gap in advisories)
    else:
        lines.append("- None identified.")
    lines += ["", "## Checklist", "", "| Check | Result | Severity | Detail |", "|---|---|---|---|"]
    checks = review.get("checks") if isinstance(review.get("checks"), list) else []
    for check in checks:
        if not isinstance(check, dict):
            continue
        result = "PASS" if check.get("passed") else "GAP"
        lines.append("| " + " | ".join(_md_cell(value) for value in [check.get("name"), result, check.get("severity"), check.get("detail")]) + " |")
    lines += ["", "## Linked tool runs", "", "| ID | Tool | Target | Status | Artifact |", "|---|---|---|---|---|"]
    linked = review.get("linked_tool_runs") if isinstance(review.get("linked_tool_runs"), list) else []
    if linked:
        for run in linked:
            if not isinstance(run, dict):
                continue
            lines.append("| " + " | ".join(_md_cell(value) for value in [run.get("id"), run.get("tool_name"), run.get("target"), run.get("status"), run.get("artifact_path")]) + " |")
    else:
        lines.append("| | | | | No linked tool runs. |")
    lines += ["", "## Evidence references", ""]
    evidence_lines = _finding_evidence_lines(finding.get("evidence") if isinstance(finding.get("evidence"), list) else [])
    if evidence_lines:
        lines.extend(f"- {redact_secrets(line)}" for line in evidence_lines)
    else:
        lines.append("- No evidence references recorded.")
    lines += ["", "## Recommendations", ""]
    for item in review.get("recommendations", []) if isinstance(review.get("recommendations"), list) else []:
        lines.append(f"- {redact_secrets(str(item))}")
    return redact_secrets("\n".join(lines) + "\n") or ""


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


def _timeline_audit_preview(event: str, data: dict[str, Any]) -> tuple[str, str, str]:
    tool = str(data.get("tool") or "").strip()
    if event == "tool_call" and tool:
        return (f"Tool call: {tool}", "", json.dumps(data.get("args", {}), sort_keys=True)[:800])
    if event == "tool_result" and tool:
        result = data.get("result") if isinstance(data.get("result"), dict) else {}
        status = str(result.get("status") or "")
        message = str(result.get("message") or "")
        return (f"Tool result: {tool}", status, message[:800])
    if event == "tool_policy_confirm" and tool:
        return (f"Tool approval queued: {tool}", "needs_approval", f"approval_id={data.get('approval_id')}")
    if event == "tool_blocked" and tool:
        return (f"Tool blocked: {tool}", "blocked", json.dumps(data.get("args", {}), sort_keys=True)[:800])
    if event == "natural_response":
        return ("Natural response", "no_tools_executed", str(data.get("message_preview") or "")[:800])
    if event == "gateway_auth_failed":
        return ("Gateway auth failed", "blocked", str(data.get("path") or "")[:800])
    if event == "agent_init":
        return ("Agent initialized", "ok", json.dumps({key: data.get(key) for key in ("engagement", "safety_mode", "scope") if key in data}, sort_keys=True)[:800])
    summary = json.dumps(data, sort_keys=True, default=str)[:800] if data else ""
    return (event.replace("_", " ").title() or "Audit event", "", summary)


def _preflight_check(category: str, name: str, status: str, detail: str, recommendation: str = "") -> dict[str, Any]:
    normalized = status.strip().lower().replace("warning", "warn")
    if normalized not in {"pass", "warn", "fail", "info"}:
        normalized = "info"
    return _redacted_mapping({
        "category": category,
        "name": name,
        "status": normalized,
        "detail": detail,
        "recommendation": recommendation,
    })


def _preflight_counts(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for check in checks:
        status = str(check.get("status") or "info")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _preflight_checks(
    roe: EngagementROE,
    evidence_root: Path,
    workspace_root: Path,
    store: AgentStore,
    session_id: str,
    blocked_tools: set[str],
    confirm_tools: set[str],
    registered_tools: list[str],
    runtime_metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(category: str, name: str, status: str, detail: str, recommendation: str = "") -> None:
        checks.append(_preflight_check(category, name, status, detail, recommendation))

    add(
        "roe",
        "authorization",
        "pass" if roe.authorized else "fail",
        "Engagement is marked authorized." if roe.authorized else "Engagement is not marked authorized.",
        "Load an ROE JSON with authorized=true before assessing or executing target-affecting actions." if not roe.authorized else "",
    )

    targets = [str(item).strip() for item in roe.in_scope_targets if str(item).strip()]
    broad_targets = [target for target in targets if _looks_broad_scope_target(target)]
    if not targets:
        add("roe", "scope_targets", "fail", "No in-scope targets are defined.", "Add exact hostnames, IPs, CIDRs, or URLs to in_scope_targets before use.")
    elif broad_targets:
        add(
            "roe",
            "scope_targets",
            "warn",
            f"{len(targets)} target pattern(s) configured; broad patterns present: {', '.join(broad_targets[:4])}.",
            "Prefer explicit assets or CIDRs from the signed ROE; broad catch-alls make out-of-scope blocking weaker.",
        )
    else:
        add("roe", "scope_targets", "pass", f"{len(targets)} explicit target pattern(s) configured.")

    safety_mode = (roe.safety_mode or "").strip().lower().replace("-", "_")
    if safety_mode in {"non_destructive", "standard"}:
        add("guardrails", "safety_mode", "pass", f"Safety mode is {safety_mode}.")
    else:
        add("guardrails", "safety_mode", "warn", f"Unknown safety mode {roe.safety_mode!r}; guardrails fall back conservatively.", "Use non_destructive for operator-default active testing, or standard for conservative demos/customers.")

    required_prohibitions = {"dos", "destructive", "persistence", "evasion", "malware"}
    configured_prohibitions = {str(item).strip().lower().replace("-", "_") for item in roe.prohibited_techniques if str(item).strip()}
    missing_prohibitions = sorted(required_prohibitions - configured_prohibitions)
    if missing_prohibitions:
        add(
            "guardrails",
            "prohibited_techniques",
            "warn",
            f"ROE prohibited_techniques is missing default hard classes: {', '.join(missing_prohibitions)}.",
            "Keep dos, destructive, persistence, evasion, and malware in prohibited_techniques even though built-in pattern rules also block common forms.",
        )
    else:
        add("guardrails", "prohibited_techniques", "pass", "Default hard-stop technique classes are present in the ROE.")

    stop_conditions = [str(item).strip() for item in roe.stop_conditions if str(item).strip()]
    if len(stop_conditions) < 2:
        add("roe", "stop_conditions", "warn", f"Only {len(stop_conditions)} stop condition(s) configured.", "Record explicit stop conditions for production impact, personal data, lockouts, availability, persistence/evasion, and client escalation.")
    else:
        add("roe", "stop_conditions", "pass", f"{len(stop_conditions)} stop condition(s) configured.")

    try:
        evidence_resolved = evidence_root.resolve(strict=False)
        evidence_ok = evidence_root.exists() and evidence_root.is_dir()
    except (OSError, RuntimeError):
        evidence_resolved = evidence_root
        evidence_ok = False
    add(
        "artifacts",
        "evidence_root",
        "pass" if evidence_ok else "fail",
        f"Evidence root: {evidence_resolved}",
        "Ensure the evidence directory exists and is writable before running tools." if not evidence_ok else "",
    )

    try:
        workspace_resolved = workspace_root.resolve(strict=False)
        workspace_ok = workspace_root.exists() and workspace_root.is_dir()
    except (OSError, RuntimeError):
        workspace_resolved = workspace_root
        workspace_ok = False
    add(
        "artifacts",
        "workspace_root",
        "pass" if workspace_ok else "warn",
        f"Workspace root: {workspace_resolved}",
        "Create the workspace before using /read, /write, /workspace-search, or /patch-file." if not workspace_ok else "",
    )

    schema = store.schema_info()
    add("state", "sqlite_schema", "pass" if schema.get("schema_version") == schema.get("latest_supported_schema_version") else "warn", f"Schema version {schema.get('schema_version')} (latest supported {schema.get('latest_supported_schema_version')}); FTS available={schema.get('fts_available')}.")
    add("state", "session_record", "pass" if store.get_session(session_id) else "fail", f"Session ID {session_id} exists in the local DB." if store.get_session(session_id) else f"Session ID {session_id} was not found in the local DB.")

    plaintext_files = []
    for path in [store.path, Path(str(store.path) + "-wal"), Path(str(store.path) + "-shm")]:
        try:
            plaintext_files.append(f"{path.name}:exists={path.exists()} bytes={path.stat().st_size if path.exists() else 0}")
        except OSError:
            plaintext_files.append(f"{path.name}:status=unreadable")
    add(
        "state",
        "plaintext_db_caveat",
        "info",
        "; ".join(plaintext_files),
        "Exports and sealed snapshots can be encrypted/redacted, but the live SQLite DB/WAL/SHM remain plaintext unless the deployment adds filesystem encryption or SQLCipher.",
    )

    expected_core_tools = {"assess_action", "run_command", "start_process", "list_approvals", "approve", "deny", "runtime_status", "safety_preflight"}
    missing_tools = sorted(expected_core_tools - set(registered_tools))
    add("runtime", "core_tools_registered", "fail" if missing_tools else "pass", "Missing core tools: " + ", ".join(missing_tools) if missing_tools else f"{len(registered_tools)} tools registered including core guardrail/status tools.")

    policy_sensitive = expected_core_tools | {"tool_schemas", "auth_status"}
    blocked_sensitive = sorted(policy_sensitive & blocked_tools)
    confirm_sensitive = sorted({"safety_preflight", "runtime_status", "list_approvals", "tool_schemas"} & confirm_tools)
    if blocked_sensitive or confirm_sensitive:
        add(
            "runtime",
            "tool_policy",
            "warn",
            f"Policy affects safety/inspection tools: blocked={blocked_sensitive}; confirm={confirm_sensitive}.",
            "Avoid blocking or approval-gating read-only status/preflight/schema tools; keep policy gates for side-effecting tools.",
        )
    else:
        add("runtime", "tool_policy", "pass", f"Runtime policy configured: blocked={len(blocked_tools)}, confirm={len(confirm_tools)}; read-only inspection tools remain reachable.")

    auto_execute = bool(runtime_metadata.get("auto_execute_natural", False))
    add(
        "runtime",
        "natural_language_execution",
        "warn" if auto_execute else "pass",
        f"auto_execute_natural={auto_execute}; auto_model_planning={bool(runtime_metadata.get('auto_model_planning', False))}; max_auto_steps={runtime_metadata.get('max_auto_steps', 'unknown')}.",
        "Keep auto_execute_natural=false for production/default operation; use explicit /auto apply=true and execute=true when action is intended." if auto_execute else "",
    )

    timeout = int(runtime_metadata.get("tool_timeout") or 0)
    add("runtime", "tool_timeout", "warn" if timeout and timeout > 300 else "pass", f"tool_timeout={timeout or 'unknown'} seconds.", "Keep foreground tool timeouts bounded; use tracked background processes for longer local jobs." if timeout and timeout > 300 else "")

    _add_provider_preflight(checks, runtime_metadata)
    _add_path_list_preflight(checks, "plugins", "plugin_dirs", runtime_metadata.get("plugin_dirs"))
    _add_path_list_preflight(checks, "skills", "skill_dirs", runtime_metadata.get("skill_dirs"))
    _add_bridge_preflight(checks, runtime_metadata.get("bridges"))
    return checks


def _add_provider_preflight(checks: list[dict[str, Any]], runtime_metadata: dict[str, Any]) -> None:
    providers = runtime_metadata.get("model_providers")
    if not isinstance(providers, list) or not providers:
        provider = str(runtime_metadata.get("provider") or "").strip()
        providers = [{"provider": provider, "model": runtime_metadata.get("model"), "key_env": runtime_metadata.get("key_env"), "base_url": runtime_metadata.get("base_url")}] if provider else []
    if not providers:
        checks.append(_preflight_check("models", "provider_chain", "info", "No model provider metadata available; heuristic fallback may still be active."))
        return
    warnings: list[str] = []
    descriptions: list[str] = []
    for item in providers:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider") or "unknown")
        model = str(item.get("model") or "")
        key_env = str(item.get("key_env") or "")
        base_url = str(item.get("base_url") or "")
        local_base = base_url.startswith(("http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost"))
        descriptions.append(f"{provider}/{model or 'default'} key_env={key_env or 'none'} env_set={bool(os.environ.get(key_env)) if key_env else 'n/a'}")
        if provider in {"openai"} and key_env and not os.environ.get(key_env) and not local_base:
            warnings.append(f"{provider} key env {key_env} is absent")
    checks.append(_preflight_check("models", "provider_chain", "warn" if warnings else "pass", "; ".join(descriptions) or "Provider metadata present.", "; ".join(warnings) if warnings else ""))


def _add_path_list_preflight(checks: list[dict[str, Any]], category: str, name: str, value: Any) -> None:
    paths = [str(item) for item in value] if isinstance(value, list | tuple) else []
    if not paths:
        checks.append(_preflight_check(category, name, "info", f"No {name} configured."))
        return
    missing = []
    for item in paths:
        try:
            if not Path(item).expanduser().exists():
                missing.append(item)
        except OSError:
            missing.append(item)
    checks.append(_preflight_check(category, name, "warn" if missing else "pass", f"Configured paths: {len(paths)}; missing/unreadable: {len(missing)}.", "Create or remove missing configured directories: " + ", ".join(missing[:4]) if missing else ""))


def _add_bridge_preflight(checks: list[dict[str, Any]], bridges: Any) -> None:
    if not isinstance(bridges, dict):
        checks.append(_preflight_check("bridges", "bridge_configs", "info", "No bridge config metadata available."))
        return
    enabled = {str(name): data for name, data in bridges.items() if isinstance(data, dict) and bool(data.get("enabled", False))}
    if not enabled:
        checks.append(_preflight_check("bridges", "bridge_configs", "pass", "No chat bridges are enabled in config; CLI bridge commands can still start explicitly with allowlists."))
        return
    for name, data in enabled.items():
        issues: list[str] = []
        token_envs = [str(data.get(key) or "").strip() for key in ("token_env", "bot_token_env", "app_token_env") if str(data.get(key) or "").strip()]
        missing_envs = [env for env in token_envs if not os.environ.get(env)]
        if missing_envs:
            issues.append("missing env vars: " + ", ".join(missing_envs))
        allowed_channels = data.get("allowed_channel_ids") if isinstance(data.get("allowed_channel_ids"), list | tuple) else []
        allowed_users = data.get("allowed_user_ids") if isinstance(data.get("allowed_user_ids"), list | tuple) else []
        if bool(data.get("allow_all", False)):
            issues.append("allow_all=true")
        elif not allowed_channels and not allowed_users:
            issues.append("no channel/user allowlist configured")
        if bool(data.get("allow_approval_actions", False)):
            issues.append("approval actions enabled over bridge")
        if not bool(data.get("ignore_bots", True)):
            issues.append("bot senders are not ignored")
        if not str(data.get("command_prefix") or "").strip() and not bool(data.get("mention_required", False)):
            issues.append("no prefix or mention gate configured")
        checks.append(_preflight_check(
            "bridges",
            f"{name}_bridge",
            "warn" if issues else "pass",
            "; ".join(issues) if issues else "Enabled bridge has token-env metadata, allowlist/trigger gates, and approval actions disabled.",
            "Use env-var tokens, explicit channel/user allowlists or intentionally documented allow_all, prefix/mention gates, bot ignores, and keep bridge approvals disabled by default." if issues else "",
        ))


def _looks_broad_scope_target(target: str) -> bool:
    normalized = target.strip().lower()
    return normalized in {"*", "any", "all", "internet", "0/0", "0.0.0.0/0", "::/0"}


def _preflight_markdown(engagement_name: str, readiness: str, checks: list[dict[str, Any]], counts: dict[str, int]) -> str:
    lines = [
        "# Phobos Safety Preflight",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Readiness: `{readiness}`",
        "No target activity was performed by this preflight.",
        "",
        "## Summary",
        "",
        f"- Pass: {counts.get('pass', 0)}",
        f"- Warn: {counts.get('warn', 0)}",
        f"- Fail: {counts.get('fail', 0)}",
        f"- Info: {counts.get('info', 0)}",
        "- Local SQLite/WAL/SHM remain plaintext unless deployment adds filesystem encryption, SQLCipher, or uses sealed backups with plaintext removal while runtimes are closed.",
        "",
        "## Checks",
        "",
        "| Category | Check | Status | Detail | Recommendation |",
        "|---|---|---|---|---|",
    ]
    for check in checks:
        lines.append("| " + " | ".join(_md_cell(check.get(key)) for key in ["category", "name", "status", "detail", "recommendation"]) + " |")
    return redact_secrets("\n".join(lines) + "\n") or ""


def _timeline_markdown(engagement_name: str, entries: list[dict[str, Any]], counts: dict[str, int], total_entries: int, category_filter: set[str], include_audit: bool) -> str:
    lines = [
        "# Phobos Evidence Timeline",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Events returned: {len(entries)} of {total_entries}",
        f"Categories: {', '.join(f'{key}={value}' for key, value in sorted(counts.items())) or 'none'}",
        f"Category filter: {', '.join(sorted(category_filter)) or 'none'}",
        f"Audit events included: {include_audit}",
        "",
        "| Time | Category | Status | Ref | Summary | Artifacts |",
        "|---|---|---|---|---|---|",
    ]
    if not entries:
        lines.append("| | | | | No timeline entries matched. | |")
    for entry in entries:
        title = str(entry.get("title") or "")
        summary = str(entry.get("summary") or "")
        detail = title if not summary else f"{title} — {summary}"
        artifacts = "; ".join(str(item) for item in entry.get("artifacts", []) if str(item))
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in [entry.get("timestamp", ""), entry.get("category", ""), entry.get("status", ""), entry.get("ref", ""), detail, artifacts]
            )
            + " |"
        )
    return redact_secrets("\n".join(lines) + "\n") or ""


def _md_cell(value: Any) -> str:
    text = redact_secrets(str(value or "")) or ""
    return text.replace("|", "\\|").replace("\n", "<br>")[:1200]


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
