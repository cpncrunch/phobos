from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
import hashlib
import json
import math
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
from urllib.parse import urlsplit

from .bloodhound import analyze_bloodhound
from .burp_mcp import BurpMCPClient, HTTPRequestArtifact, write_burp_artifacts
from .cve_advisor import CveAdvisor
from .harness import OffSecHarness
from .model_adapters import BaseModelAdapter, HeuristicAdapter
from .models import ActionRequest, DecisionStatus, EngagementROE, redact_secrets
from .scope import target_in_scope
from .reporting import FindingInput, FindingMarkdownExporter, safe_report_filename
from .agent_store import AgentStore, utc_now
from .agent_crypto import seal_bytes, unseal_bytes


_LIVE_PROCESSES: dict[int, subprocess.Popen] = {}

_TASK_STATUS_VALUES = ("pending", "in_progress", "completed", "cancelled")
_TASK_LIST_STATUS_VALUES = ("all", *_TASK_STATUS_VALUES)
_FINDING_STATUS_VALUES = ("draft", "needs-evidence", "confirmed", "resolved", "accepted-risk", "false-positive")
_FINDING_LIST_STATUS_VALUES = ("all", *_FINDING_STATUS_VALUES)
_FINDING_SEVERITY_VALUES = ("Informational", "Low", "Medium", "High", "Critical")
_FINDING_SEVERITY_ALIASES = {"info": "Informational", "med": "Medium", "crit": "Critical"}
_TIMELINE_ORDER_VALUES = ("desc", "asc", "newest", "newest-first", "oldest", "oldest-first")
_MEDIA_KIND_VALUES = ("image", "audio", "voice", "video", "file")
_NMAP_PROFILE_VALUES = ("safe", "version", "quick")

# Registry-level resource ceilings for operator/API-controlled numeric args.
# Handlers may keep defensive clamps, but the generic /tool and gateway boundary
# should reject runaway local reads/scans before dispatch or approval queueing.
_SCHEMA_ROW_LIMIT_MAX = 5_000
_SCHEMA_CONTEXT_LIMIT_MAX = 1_000
_SCHEMA_TIMELINE_LIMIT_MAX = 500
_SCHEMA_WORKSPACE_READ_MAX = 1_000_000
_SCHEMA_WORKSPACE_SEARCH_LIMIT_MAX = 1_000
_SCHEMA_LOG_TAIL_MAX = 200_000
_SCHEMA_COMMAND_TIMEOUT_MAX = 600
_SCHEMA_SCANNER_TIMEOUT_MAX = 300
_SCHEMA_WAIT_TIMEOUT_MAX = 300
_SCHEMA_SCANNER_RATE_MAX = 50
_SCHEMA_MANIFEST_MAX_BYTES = 500_000_000
_SCHEMA_LOCAL_TEXT_MAX_BYTES = 50_000_000


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
        self._policy_bypass_tools = {"approve", "deny", "list_approvals", "get_approval", "tool_schemas", "runtime_status", "audit_log", "get_audit", "auth_status", "safety_preflight", "guardrail_selftest"}
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
        if not isinstance(args, dict):
            return ToolResult("error", "Tool args must be an object.")
        if name in self.blocked_tools and name not in self._policy_bypass_tools:
            result = ToolResult("blocked", f"Tool {name} is blocked by runtime policy.", {"tool": name})
            self.store.audit(self.session_id, "tool_blocked", {"tool": name, "args": _safe_json(args)})
            return result
        args, arg_error = self._validated_tool_args(name, args)
        if arg_error is not None:
            self.store.audit(self.session_id, "tool_argument_error", {"tool": name, "error": arg_error.message})
            return arg_error
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

    def _validated_tool_args(self, name: str, args: dict[str, Any]) -> tuple[dict[str, Any], ToolResult | None]:
        """Validate schema-declared arguments before dispatch/approval.

        Tool handlers are still defensive, but malformed or incomplete
        operator-controlled schema fields should not fall through to Python
        ``ValueError`` strings, Python truthiness surprises, handler-specific
        missing-key errors, or queued approval replay.  The registry owns the
        generic ``/tool`` and gateway dispatch boundary, so normalize safe
        integer/number/boolean strings, normalize schema-declared enum aliases, and reject
        ambiguous, out-of-set, missing required, blank required scalar, non-string
        string-typed values, malformed collection values, schema-declared
        string/collection size-bound violations, and closed-schema unexpected
        arguments with clean operator errors before policy confirm queues are
        created.
        """

        spec = self.tool_specs.get(name)
        schema = spec.schema if spec else {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []
        if not isinstance(properties, dict):
            return dict(args), None
        validated = dict(args)
        if isinstance(schema, dict) and schema.get("additionalProperties") is False:
            unexpected = _schema_unexpected_args(validated, properties)
            if unexpected:
                return validated, ToolResult("error", _schema_unexpected_args_message(unexpected))
        for arg_name, arg_schema in properties.items():
            if not isinstance(arg_schema, dict):
                continue
            arg_type = arg_schema.get("type")
            enum_values = arg_schema.get("enum")
            if arg_name not in validated or validated.get(arg_name) in (None, ""):
                continue
            raw_value = validated.get(arg_name)
            if isinstance(enum_values, list) and enum_values:
                parsed_enum, ok = _parse_schema_enum(raw_value, enum_values, arg_schema.get("x-aliases"))
                if not ok:
                    return validated, ToolResult("error", f"{arg_name} must be one of: {_schema_enum_error_values(enum_values)}.")
                validated[arg_name] = parsed_enum
                continue
            if arg_type == "integer":
                if raw_value is None or isinstance(raw_value, bool):
                    return validated, ToolResult("error", f"{arg_name} must be an integer.")
                try:
                    parsed_int = int(raw_value)
                except (TypeError, ValueError):
                    return validated, ToolResult("error", f"{arg_name} must be an integer.")
                minimum = arg_schema.get("minimum")
                maximum = arg_schema.get("maximum")
                if isinstance(minimum, (int, float)) and parsed_int < minimum:
                    return validated, ToolResult("error", f"{arg_name} must be at least {_format_schema_bound(minimum)}.")
                if isinstance(maximum, (int, float)) and parsed_int > maximum:
                    return validated, ToolResult("error", f"{arg_name} must be at most {_format_schema_bound(maximum)}.")
                validated[arg_name] = parsed_int
                continue
            if arg_type == "number":
                parsed_number, ok = _parse_schema_number(raw_value)
                if not ok:
                    return validated, ToolResult("error", f"{arg_name} must be a number.")
                minimum = arg_schema.get("minimum")
                maximum = arg_schema.get("maximum")
                if isinstance(minimum, (int, float)) and parsed_number < minimum:
                    return validated, ToolResult("error", f"{arg_name} must be at least {_format_schema_bound(minimum)}.")
                if isinstance(maximum, (int, float)) and parsed_number > maximum:
                    return validated, ToolResult("error", f"{arg_name} must be at most {_format_schema_bound(maximum)}.")
                validated[arg_name] = parsed_number
                continue
            if arg_type == "boolean":
                parsed, ok = _parse_schema_bool(raw_value)
                if not ok:
                    return validated, ToolResult("error", f"{arg_name} must be a boolean.")
                validated[arg_name] = parsed
                continue
            if arg_type == "string":
                if not isinstance(raw_value, str) and not arg_schema.get("x-allow-non-string", False):
                    return validated, ToolResult("error", f"{arg_name} must be a string.")
                if isinstance(raw_value, str):
                    min_length = _schema_size_bound(arg_schema.get("minLength"))
                    max_length = _schema_size_bound(arg_schema.get("maxLength"))
                    if min_length is not None and len(raw_value) < min_length:
                        return validated, ToolResult("error", f"{arg_name} must be at least {_format_schema_count('character', min_length)}.")
                    if max_length is not None and len(raw_value) > max_length:
                        return validated, ToolResult("error", f"{arg_name} must be at most {_format_schema_count('character', max_length)}.")
                continue
            if arg_type == "array":
                if not isinstance(raw_value, list):
                    return validated, ToolResult("error", f"{arg_name} must be an array.")
                min_items = _schema_size_bound(arg_schema.get("minItems"))
                max_items = _schema_size_bound(arg_schema.get("maxItems"))
                if min_items is not None and len(raw_value) < min_items:
                    return validated, ToolResult("error", f"{arg_name} must contain at least {_format_schema_count('item', min_items)}.")
                if max_items is not None and len(raw_value) > max_items:
                    return validated, ToolResult("error", f"{arg_name} must contain at most {_format_schema_count('item', max_items)}.")
                continue
            if arg_type == "object":
                if not isinstance(raw_value, dict):
                    return validated, ToolResult("error", f"{arg_name} must be an object.")
                min_properties = _schema_size_bound(arg_schema.get("minProperties"))
                max_properties = _schema_size_bound(arg_schema.get("maxProperties"))
                if min_properties is not None and len(raw_value) < min_properties:
                    return validated, ToolResult("error", f"{arg_name} must contain at least {_format_schema_count('field', min_properties)}.")
                if max_properties is not None and len(raw_value) > max_properties:
                    return validated, ToolResult("error", f"{arg_name} must contain at most {_format_schema_count('field', max_properties)}.")
                continue
        if isinstance(required, list):
            for arg_name in required:
                if not isinstance(arg_name, str):
                    continue
                arg_schema = properties.get(arg_name, {}) if isinstance(properties, dict) else {}
                if arg_name not in validated or validated.get(arg_name) is None:
                    return validated, ToolResult("error", f"{arg_name} is required.")
                if validated.get(arg_name) == "" and _blank_required_value_is_missing(arg_schema):
                    return validated, ToolResult("error", f"{arg_name} is required.")
        return validated, None

    def _register_builtins(self) -> None:
        self.register_tool("assess_action", self.assess_action, _spec("assess_action", "Evaluate a proposed action/command against ROE guardrails without executing it.", {
            "target": _string("Target host/IP/URL in the engagement scope."),
            "type": _string("Action type, e.g. host, web, api, service-enumeration."),
            "purpose": _string("Why the action is being performed."),
            "command": _string("Command/action text to assess."),
        }, ["target", "purpose", "command"]))
        self.register_tool("scope_check", self.scope_check, _spec("scope_check", "Read-only ROE scope summary and optional target match check; performs no target activity.", {
            "target": _string("Optional host/IP/URL to match against in-scope target rules."),
            "host": _string("Alias for target."),
            "url": _string("Alias for target."),
        }, []))
        self.register_tool("run_command", self.run_command, _spec("run_command", "Run a short shell command through ROE guardrails; confirm-level actions are queued for approval.", {
            "target": _string("In-scope target or local artifact context."),
            "type": _string("Action type."),
            "purpose": _string("Purpose for audit/evidence."),
            "command": _string("Shell command."),
            "execute": {"type": "boolean", "description": "Must be true to execute; false returns dry-run."},
            "timeout": _integer("Foreground timeout in seconds.", minimum=1, maximum=_SCHEMA_COMMAND_TIMEOUT_MAX),
        }, ["target", "purpose", "command"]))
        self.register_tool("start_process", self.start_process, _spec("start_process", "Start a guarded background process and capture stdout/stderr logs.", {
            "target": _string("In-scope target or local artifact context."),
            "type": _string("Action type."),
            "purpose": _string("Purpose for audit/evidence."),
            "command": _string("Shell command to run in the background."),
            "execute": {"type": "boolean", "description": "Must be true to start."},
        }, ["target", "purpose", "command"]))
        self.register_tool("poll_process", self.poll_process, _spec("poll_process", "Poll a background process status.", {"id": _integer("Current-session process id.", minimum=1)}, ["id"]))
        self.register_tool("wait_process", self.wait_process, _spec("wait_process", "Wait up to timeout seconds for a background process to complete, then return status and log tails.", {"id": _integer("Current-session process id.", minimum=1), "timeout": _integer("Seconds to wait; 0 performs an immediate status check.", minimum=0, maximum=_SCHEMA_WAIT_TIMEOUT_MAX), "limit": _integer("Maximum log-tail bytes to return.", minimum=1, maximum=_SCHEMA_LOG_TAIL_MAX)}, ["id"]))
        self.register_tool("process_log", self.process_log, _spec("process_log", "Read redacted stdout/stderr tails for a background process.", {"id": _integer("Current-session process id.", minimum=1), "limit": _integer("Maximum log-tail bytes to return.", minimum=1, maximum=_SCHEMA_LOG_TAIL_MAX)}, ["id"]))
        self.register_tool("kill_process", self.kill_process, _spec("kill_process", "Terminate a tracked background process.", {"id": _integer("Current-session process id.", minimum=1)}, ["id"]))
        self.register_tool("list_processes", self.list_processes, _spec("list_processes", "List tracked background processes for the current session.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("get_process", self.get_process, _spec("get_process", "Get one current-session tracked background process by id with redacted command metadata.", {"id": _integer("Current-session process id.", minimum=1)}, ["id"]))
        self.register_tool("approve", self.approve, _spec("approve", "Approve and execute/start a pending confirm-level action.", {"id": _integer("Current-session approval id.", minimum=1)}, ["id"]))
        self.register_tool("deny", self.deny, _spec("deny", "Deny a pending approval.", {"id": _integer("Current-session approval id.", minimum=1), "reason": _string("Reason for audit log.")}, ["id"]))
        self.register_tool("impact_plan", self.impact_plan, _spec("impact_plan", "Generate a safe impact-validation plan from an observed finding.", {"finding": _string("Observed weakness or finding draft.")}, ["finding"]))
        self.register_tool("burp_tab", self.burp_tab, _spec("burp_tab", "Create/save Burp Repeater request artifacts and optionally call Burp MCP.", {"request_file": _string("Raw HTTP request artifact path."), "target": _string("In-scope target."), "tab_name": _string("Repeater tab/artifact name."), "create": {"type": "boolean"}}))
        self.register_tool("bloodhound_import", self.bloodhound_import, _spec("bloodhound_import", "Offline BloodHound/ADCS graph analysis.", {"input": _string("BloodHound JSON/dir/zip."), "principal": _string("Optional principal to path from.")}))
        self.register_tool("cve_advice", self.cve_advice, _spec("cve_advice", "CVE candidate review with non-invasive validation guidance.", {"component": _string("Product/component name."), "version": _string("Observed version."), "catalog": _string("Local CVE catalog JSON."), "online": {"type": "boolean"}}))
        self.register_tool("export_finding", self.export_finding, _spec("export_finding", "Report-ready finding Markdown exporter for a finding JSON file.", {"finding_file": _string("Finding JSON path."), "out": _string("Optional output path.")}))
        self.register_tool("nmap_scan", self.nmap_scan, _spec("nmap_scan", "ROE-gated nmap-style service enumeration wrapper with structured parsing and evidence artifacts.", {"target": _string("In-scope host/IP/CIDR."), "ports": _string("Optional comma/range ports, e.g. 80,443,8000-8010."), "profile": _string_enum("safe|version|quick; default version.", _NMAP_PROFILE_VALUES), "stdout": _string("Optional captured output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": _integer("Execution timeout in seconds.", minimum=1, maximum=_SCHEMA_SCANNER_TIMEOUT_MAX)}, ["target"]))
        self.register_tool("httpx_probe", self.httpx_probe, _spec("httpx_probe", "ROE-gated httpx-style HTTP probing wrapper with JSON/plaintext parsing and evidence artifacts.", {"url": _string("In-scope URL or host."), "target": _string("Alias for url."), "stdout": _string("Optional captured output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": _integer("Execution timeout in seconds.", minimum=1, maximum=_SCHEMA_SCANNER_TIMEOUT_MAX)}, []))
        self.register_tool("nuclei_scan", self.nuclei_scan, _spec("nuclei_scan", "ROE-gated nuclei wrapper. Real execution requires an explicit safe template path; parser/dry-run paths remain available without nuclei installed.", {"url": _string("In-scope URL or host."), "target": _string("Alias for url."), "templates": _string("Template file/directory for execution; required when execute=true."), "template": _string("Alias for templates."), "rate_limit": _integer("Maximum requests per second for execution.", minimum=1, maximum=_SCHEMA_SCANNER_RATE_MAX), "stdout": _string("Optional captured JSONL/plain output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": _integer("Execution timeout in seconds.", minimum=1, maximum=_SCHEMA_SCANNER_TIMEOUT_MAX)}, []))
        self.register_tool("ffuf_scan", self.ffuf_scan, _spec("ffuf_scan", "ROE-gated ffuf-style content discovery wrapper with conservative rate limits and structured evidence.", {"url": _string("In-scope URL containing FUZZ or base URL where /FUZZ is appended."), "wordlist": _string("Wordlist path required for execution."), "rate": _integer("Maximum requests per second for execution.", minimum=1, maximum=_SCHEMA_SCANNER_RATE_MAX), "stdout": _string("Optional captured JSON output to parse without executing."), "input_file": _string("Optional output file to parse without executing."), "execute": {"type": "boolean"}, "timeout": _integer("Execution timeout in seconds.", minimum=1, maximum=_SCHEMA_SCANNER_TIMEOUT_MAX)}, ["url"]))
        self.register_tool("list_tool_runs", self.list_tool_runs, _spec("list_tool_runs", "List structured wrapper runs and their parsed evidence artifacts.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX), "tool_name": _string("Optional wrapper tool name filter.")}, []))
        self.register_tool("get_tool_run", self.get_tool_run, _spec("get_tool_run", "Get one structured wrapper run by id.", {"id": _integer("Current-session tool-run id.", minimum=1)}, ["id"]))
        self.register_tool("create_finding", self.create_finding, _spec("create_finding", "Create a finding lifecycle record linked to evidence/tool runs.", {"title": _string("Finding title."), "severity": _string_enum("Informational/Low/Medium/High/Critical.", _FINDING_SEVERITY_VALUES, _FINDING_SEVERITY_ALIASES), "status": _string_enum("draft/needs-evidence/confirmed/resolved/accepted-risk/false-positive.", _FINDING_STATUS_VALUES), "description": _string("Technical description."), "impact": _string("Impact statement."), "recommendation": _string("Remediation guidance."), "tool_run_ids": _string("Comma-separated structured tool run IDs to link.", allow_non_string=True), "evidence": _string("Additional evidence refs as JSON/list/text.", allow_non_string=True), "tags": _string("Comma-separated tags.")}, ["title"]))
        self.register_tool("update_finding", self.update_finding, _spec("update_finding", "Update a finding lifecycle record and optionally append evidence.", {"id": _integer("Current-session finding id.", minimum=1), "title": _string("Optional title."), "severity": _string_enum("Optional severity.", _FINDING_SEVERITY_VALUES, _FINDING_SEVERITY_ALIASES), "status": _string_enum("Optional status.", _FINDING_STATUS_VALUES), "description": _string("Optional description."), "impact": _string("Optional impact."), "recommendation": _string("Optional recommendation."), "tool_run_ids": _string("Additional linked tool run IDs.", allow_non_string=True), "evidence": _string("Replacement or appended evidence refs.", allow_non_string=True), "append_evidence": {"type": "boolean"}, "tags": _string("Optional tags.")}, ["id"]))
        self.register_tool("list_findings", self.list_findings, _spec("list_findings", "List finding lifecycle records.", {"status": _string_enum("draft/needs-evidence/confirmed/resolved/accepted-risk/false-positive/all; default all.", _FINDING_LIST_STATUS_VALUES), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("get_finding", self.get_finding, _spec("get_finding", "Get one finding lifecycle record by id.", {"id": _integer("Current-session finding id.", minimum=1)}, ["id"]))
        self.register_tool("finding_export", self.finding_export, _spec("finding_export", "Export a stored finding lifecycle record to report-ready Markdown.", {"id": _integer("Current-session finding id.", minimum=1), "out": _string("Optional output path; relative paths go under agent/findings.")}, ["id"]))
        self.register_tool("finding_review", self.finding_review, _spec("finding_review", "Deterministically review a stored finding for report-readiness gaps without executing target actions.", {"id": _integer("Current-session finding id.", minimum=1), "out": _string("Optional Markdown output path; relative paths go under agent/findings.")}, ["id"]))
        self.register_tool("finding_bundle", self.finding_bundle, _spec("finding_bundle", "Create a redacted ZIP bundle for one stored finding with report draft, QA review, linked text evidence, and a manifest; no target activity.", {"id": _integer("Current-session finding id.", minimum=1), "out": _string("Optional ZIP output path; relative paths go under agent/findings."), "max_bytes": _integer("Skip linked evidence files larger than this many bytes; default 2000000.", minimum=1, maximum=_SCHEMA_LOCAL_TEXT_MAX_BYTES)}, ["id"]))
        self.register_tool("remember", self.remember, _spec("remember", "Store local agent memory in SQLite.", {"key": _string("Memory key."), "value": _string("Memory value."), "tags": _string("Optional comma tags.")}, ["key", "value"]))
        self.register_tool("recall", self.recall, _spec("recall", "Search local agent memory.", {"query": _string("Memory search query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("list_memories", self.list_memories, _spec("list_memories", "List redacted local agent memory keys/values for hygiene review.", {"query": _string("Optional memory search query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("get_memory", self.get_memory, _spec("get_memory", "Get one redacted local agent memory by id or key.", {"id": _integer("Current-session memory id.", minimum=1), "key": _string("Memory key.")}, []))
        self.register_tool("forget_memory", self.forget_memory, _spec("forget_memory", "Delete one local agent memory by id or key; useful for removing stale or over-sensitive retained context.", {"id": _integer("Current-session memory id.", minimum=1), "key": _string("Memory key.")}, []))
        self.register_tool("search_session", self.search_session, _spec("search_session", "Search current-session messages.", {"query": _string("Message search query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("search_all_sessions", self.search_all_sessions, _spec("search_all_sessions", "Search messages across all local Phobos sessions in this DB.", {"query": _string("Message search query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("context_snapshot", self.context_snapshot, _spec("context_snapshot", "Return latest compact summary, recent messages, and relevant memory.", {"query": _string("Optional relevance query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("compact_context", self.compact_context, _spec("compact_context", "Summarize recent session messages into durable local context.", {"limit": _integer("Maximum recent messages to summarize.", minimum=1, maximum=_SCHEMA_CONTEXT_LIMIT_MAX)}))
        self.register_tool("context_compact_node", self.context_compact_node, _spec("context_compact_node", "Create an LCM-style context node from recent messages and optionally roll child nodes into a parent.", {"limit": _integer("Maximum recent messages to summarize.", minimum=1, maximum=_SCHEMA_CONTEXT_LIMIT_MAX), "title": _string("Optional node title."), "parent": {"type": "boolean"}}, []))
        self.register_tool("context_describe", self.context_describe, _spec("context_describe", "Describe local LCM-style context nodes without expanding full sources.", {"id": _integer("Current-session context node id.", minimum=1), "limit": _integer("Maximum nodes to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("context_expand", self.context_expand, _spec("context_expand", "Expand a local context node and recover its source messages/child summaries.", {"id": _integer("Current-session context node id.", minimum=1), "source_limit": _integer("Maximum source rows to include.", minimum=1, maximum=_SCHEMA_CONTEXT_LIMIT_MAX)}, ["id"]))
        self.register_tool("lcm_compact", self.context_compact_node, _spec("lcm_compact", "Alias for context_compact_node.", {"limit": _integer("Maximum recent messages to summarize.", minimum=1, maximum=_SCHEMA_CONTEXT_LIMIT_MAX), "title": _string("Optional node title."), "parent": {"type": "boolean"}}, []))
        self.register_tool("lcm_describe", self.context_describe, _spec("lcm_describe", "Alias for context_describe.", {"id": _integer("Current-session context node id.", minimum=1), "limit": _integer("Maximum nodes to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("lcm_expand", self.context_expand, _spec("lcm_expand", "Alias for context_expand.", {"id": _integer("Current-session context node id.", minimum=1), "source_limit": _integer("Maximum source rows to include.", minimum=1, maximum=_SCHEMA_CONTEXT_LIMIT_MAX)}, ["id"]))
        self.register_tool("context_query", self.context_query, _spec("context_query", "Search memories, session history, and LCM-style context nodes, then synthesize an answer.", {"query": _string("Question or recall query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("reflect_memory", self.reflect_memory, _spec("reflect_memory", "Synthesize an answer from local memories and session/context recall without executing tools.", {"query": _string("Question to answer from memory/context."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("hindsight_retain", self.hindsight_retain, _spec("hindsight_retain", "Store a Hindsight-style durable local memory with context/tags metadata.", {"content": _string("Memory content to retain."), "context": _string("Short context label."), "tags": _string("Comma-separated tags."), "key": _string("Optional stable key.")}, ["content"]))
        self.register_tool("hindsight_recall", self.hindsight_recall, _spec("hindsight_recall", "Recall Hindsight-style memory plus related session/context matches.", {"query": _string("Recall query."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("hindsight_reflect", self.hindsight_reflect, _spec("hindsight_reflect", "Synthesize an answer across retained memory, messages, and local LCM-style context nodes.", {"query": _string("Question to reflect on."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, ["query"]))
        self.register_tool("workspace_read", self.workspace_read, _spec("workspace_read", "Read a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "limit": _integer("Maximum bytes/characters to return.", minimum=1, maximum=_SCHEMA_WORKSPACE_READ_MAX)}, ["path"]))
        self.register_tool("workspace_write", self.workspace_write, _spec("workspace_write", "Write or append a text file inside the engagement workspace.", {"path": _string("Workspace-relative path."), "content": _string("Text content."), "append": {"type": "boolean"}}, ["path", "content"]))
        self.register_tool("workspace_search", self.workspace_search, _spec("workspace_search", "Search text files inside the engagement workspace.", {"query": _string("Substring/regex query."), "glob": _string("Glob like **/*.md."), "limit": _integer("Maximum matches to return.", minimum=1, maximum=_SCHEMA_WORKSPACE_SEARCH_LIMIT_MAX)}, ["query"]))
        self.register_tool("workspace_patch", self.workspace_patch, _spec("workspace_patch", "Targeted text replacement inside a workspace file.", {"path": _string("Workspace-relative path."), "old": _string("Text to replace."), "new": _string("Replacement text."), "replace_all": {"type": "boolean"}}, ["path", "old", "new"]))
        self.register_tool("schedule_job", self.schedule_job, _spec("schedule_job", "Create a local scheduled job; run with run_due_jobs or external cron.", {"name": _string("Job name."), "schedule": _string("manual/every 15 m/every 1 h."), "prompt": _string("Agent prompt to run.")}))
        self.register_tool("list_jobs", self.list_jobs, _spec("list_jobs", "List scheduled jobs for the current session with redacted prompts/results.", {}))
        self.register_tool("get_job", self.get_job, _spec("get_job", "Get one current-session scheduled job by id with redacted prompt/result detail.", {"id": _integer("Current-session scheduled job id.", minimum=1)}, ["id"]))
        self.register_tool("update_job", self.update_job, _spec("update_job", "Update a current-session scheduled job name, schedule, prompt, or enabled flag.", {"id": _integer("Current-session scheduled job id.", minimum=1), "name": _string("Optional replacement job name."), "schedule": _string("Optional schedule: manual/every 15 m/every 1 h."), "prompt": _string("Optional replacement agent prompt."), "enabled": {"type": "boolean"}}, ["id"]))
        self.register_tool("enable_job", self.enable_job, _spec("enable_job", "Enable a current-session scheduled job without changing its prompt.", {"id": _integer("Current-session scheduled job id.", minimum=1)}, ["id"]))
        self.register_tool("disable_job", self.disable_job, _spec("disable_job", "Disable a current-session scheduled job without deleting audit history.", {"id": _integer("Current-session scheduled job id.", minimum=1)}, ["id"]))
        self.register_tool("run_due_jobs", self.run_due_jobs, _spec("run_due_jobs", "List due current-session jobs from tool-only context; runtime executes them.", {}))
        self.register_tool("subagent_review", self.subagent_review, _spec("subagent_review", "Run parallel role reviews using the configured model adapter.", {"prompt": _string("Task/finding to review."), "roles": _string("Comma-separated roles."), "context": _string("Optional context.")}))
        self.register_tool("delegate_tasks", self.delegate_tasks, _spec("delegate_tasks", "Run bounded local pseudo-subagent tasks in parallel and persist their artifacts; isolated child sessions are created by default.", {"prompt": _string("Overall task."), "tasks": _string("JSON/list or newline-separated task prompts.", allow_non_string=True), "roles": _string("Comma roles when tasks is omitted.", allow_non_string=True), "isolate": {"type": "boolean", "description": "Create separate child sessions for each local subagent task; default true."}}, []))
        self.register_tool("list_delegations", self.list_delegations, _spec("list_delegations", "List durable local delegation batches.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("get_delegation", self.get_delegation, _spec("get_delegation", "Get one current-session delegation batch by id, including child-session metadata and artifact paths.", {"id": _integer("Current-session delegation id.", minimum=1)}, ["id"]))
        self.register_tool("auth_status", self.auth_status, _spec("auth_status", "Check model/provider and bridge token environment variables without revealing secret values.", {"include_environment": {"type": "boolean"}}, []))
        self.register_tool("safety_preflight", self.safety_preflight, _spec("safety_preflight", "Run a read-only engagement/runtime readiness preflight and write a redacted Markdown report.", {"out": _string("Optional Markdown output path; relative paths go under agent/preflight.")}, []))
        self.register_tool("guardrail_selftest", self.guardrail_selftest, _spec("guardrail_selftest", "Run a read-only guardrail simulator over representative allow/confirm/block cases; writes a redacted Markdown report and performs no target activity.", {"target": _string("Optional in-scope host/IP/URL to use for synthetic allow/confirm cases."), "host": _string("Alias for target."), "url": _string("Alias for target."), "out": _string("Optional Markdown output path; relative paths go under agent/guardrails.")}, []))
        self.register_tool("media_import", self.media_import, _spec("media_import", "Copy an operator-supplied local media/artifact file into evidence with hash metadata.", {"path": _string("Source file path."), "kind": _string_enum("image/audio/voice/video/file; inferred when omitted.", _MEDIA_KIND_VALUES)}, ["path"]))
        self.register_tool("media_list", self.media_list, _spec("media_list", "List imported media/artifact files for this session.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}, []))
        self.register_tool("media_get", self.media_get, _spec("media_get", "Get one current-session media/artifact metadata record by id without reading file contents.", {"id": _integer("Current-session media id.", minimum=1)}, ["id"]))
        self.register_tool("sealed_export", self.sealed_export, _spec("sealed_export", "Create an authenticated encrypted portable snapshot from a session handoff or pack.", {"passphrase_env": _string("Environment variable containing passphrase."), "out": _string("Optional output .sealed.json path."), "include_pack": {"type": "boolean"}}, ["passphrase_env"]))
        self.register_tool("sealed_import", self.sealed_import, _spec("sealed_import", "Decrypt a sealed session snapshot and import its handoff data; no commands are executed.", {"path": _string("Sealed snapshot path."), "passphrase_env": _string("Environment variable containing passphrase."), "merge_memories": {"type": "boolean"}}, ["path", "passphrase_env"]))
        self.register_tool("list_approvals", self.list_approvals, _spec("list_approvals", "List approvals for the current session with redacted arguments/decisions.", {"status": _string("Approval status; default pending; use all for resolved approvals too."), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("get_approval", self.get_approval, _spec("get_approval", "Return one current-session approval with redacted arguments, decision, and replay result.", {"id": _integer("Current-session approval id.", minimum=1)}, ["id"]))
        self.register_tool("tool_schemas", self.tool_schemas, _spec("tool_schemas", "Return JSON-style schemas for available tools.", {"name": _string("Optional tool name.")}))
        self.register_tool("audit_log", self.audit_log, _spec("audit_log", "List recent redacted audit log entries.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("get_audit", self.get_audit, _spec("get_audit", "Return one current-session audit log entry with redacted payload metadata.", {"id": _integer("Current-session audit id.", minimum=1), "audit_id": _integer("Alias for id.", minimum=1)}, ["id"]))
        self.register_tool("evidence_timeline", self.evidence_timeline, _spec("evidence_timeline", "Assemble a redacted operator timeline across tool runs, findings, approvals, tasks, processes, media, delegations, and selected audit events.", {"limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_TIMELINE_LIMIT_MAX), "category": _string("Optional comma-separated category filter."), "order": _string_enum("desc/asc/newest/newest-first/oldest/oldest-first; default desc.", _TIMELINE_ORDER_VALUES), "include_audit": {"type": "boolean"}, "out": _string("Optional Markdown output path; relative paths go under agent/timelines.")}, []))
        self.register_tool("evidence_manifest", self.evidence_manifest, _spec("evidence_manifest", "Create a read-only SHA-256 inventory of engagement evidence artifacts without reading or emitting file contents.", {"limit": _integer("Maximum artifact rows to include.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX), "max_bytes": _integer("Skip files larger than this many bytes; default 50000000.", minimum=1, maximum=_SCHEMA_MANIFEST_MAX_BYTES), "include_agent": {"type": "boolean", "description": "Include agent-generated artifacts; default true."}, "out": _string("Optional JSON output path; relative paths go under agent/manifests.")}, []))
        self.register_tool("evidence_manifest_verify", self.evidence_manifest_verify, _spec("evidence_manifest_verify", "Verify a prior evidence manifest against current local artifacts, reporting missing/changed/new files without target activity.", {"path": _string("Manifest JSON path under agent/manifests; defaults to latest evidence manifest."), "manifest": _string("Alias for path."), "max_bytes": _integer("Skip current files larger than this many bytes; default 50000000.", minimum=1, maximum=_SCHEMA_MANIFEST_MAX_BYTES), "limit": _integer("Maximum new-artifact rows to include; default 1000.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX), "detect_new": {"type": "boolean", "description": "Report artifacts not present in the source manifest; default true."}, "out": _string("Optional JSON output path; relative paths go under agent/manifests.")}, []))
        self.register_tool("evidence_secret_scan", self.evidence_secret_scan, _spec("evidence_secret_scan", "Read-only local evidence-root scan for secret-like material; emits redacted previews only and performs no target activity.", {"limit": _integer("Maximum finding rows to return/write; default 200.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX), "max_bytes": _integer("Skip files larger than this many bytes; default 2000000.", minimum=1, maximum=_SCHEMA_LOCAL_TEXT_MAX_BYTES), "include_agent": {"type": "boolean", "description": "Include agent-generated artifacts; default true."}, "out": _string("Optional JSON output path; relative paths go under agent/secret-scans.")}, []))
        self.register_tool("closeout_review", self.closeout_review, _spec("closeout_review", "Run a read-only engagement closeout readiness review across ROE, approvals, tasks, findings, processes, and evidence artifacts.", {"out": _string("Optional Markdown output path; relative paths go under agent/closeout.")}, []))
        self.register_tool("resolve_local_ref", self.resolve_local_ref, _spec("resolve_local_ref", "Resolve a redacted local drill-down ref such as approval:1, task:1, finding:1, tool-run:1, media:1, context-node:1, audit:1, or artifact:agent/path without target activity.", {"ref": _string("Local ref, e.g. task:1 or artifact:agent/preflight/report.md."), "kind": _string("Optional kind when id/path is supplied separately."), "id": _integer("Current-session entity id when kind is supplied.", minimum=1), "path": _string("Artifact path under the engagement evidence root."), "max_bytes": _integer("Maximum artifact bytes to hash; default 50000000.", minimum=1, maximum=_SCHEMA_LOCAL_TEXT_MAX_BYTES)}, []))
        self.register_tool("runtime_status", self.runtime_status, _spec("runtime_status", "Return runtime health, schema, workspace, tool, approval, job, and process counts.", {}))
        self.register_tool("export_pack", self.export_pack, _spec("export_pack", "Create a redacted engagement pack ZIP containing evidence, runtime state, and a manifest.", {"out": _string("Optional ZIP output path; relative paths are written under agent/exports.")}))
        self.register_tool("operator_briefing", self.operator_briefing, _spec("operator_briefing", "Create a Hermes-like operator briefing from context, tasks, approvals, jobs, processes, and recent evidence.", {"query": _string("Optional recall query for relevant memory."), "out": _string("Optional Markdown output path.")}))
        self.register_tool("export_session", self.export_session, _spec("export_session", "Export a redacted portable session handoff JSON bundle.", {"out": _string("Optional JSON output path; relative paths are written under agent/session-exports."), "message_limit": _integer("Maximum recent messages to include.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("import_session", self.import_session, _spec("import_session", "Import memories and context summary from a portable session handoff JSON bundle; no commands are executed.", {"path": _string("Path to exported session JSON."), "merge_memories": {"type": "boolean"}}, ["path"]))
        self.register_tool("list_tasks", self.list_tasks, _spec("list_tasks", "List the current session task board.", {"status": _string_enum("Filter by pending/in_progress/completed/cancelled/all.", _TASK_LIST_STATUS_VALUES), "limit": _integer("Maximum rows to return.", minimum=1, maximum=_SCHEMA_ROW_LIMIT_MAX)}))
        self.register_tool("get_task", self.get_task, _spec("get_task", "Get one current-session task board item by id with redacted content.", {"id": _integer("Current-session task id.", minimum=1)}, ["id"]))
        self.register_tool("add_task", self.add_task, _spec("add_task", "Add an item to the current session task board.", {"content": _string("Task description."), "status": _string_enum("pending/in_progress/completed/cancelled; default pending.", _TASK_STATUS_VALUES)}, ["content"]))
        self.register_tool("update_task", self.update_task, _spec("update_task", "Update a task board item by id.", {"id": _integer("Current-session task id.", minimum=1), "content": _string("Optional replacement content."), "status": _string_enum("pending/in_progress/completed/cancelled.", _TASK_STATUS_VALUES)}, ["id"]))

    def assess_action(self, args: dict[str, Any]) -> ToolResult:
        request = _request_from_args(args)
        result = self.harness.assess(request, execute=False)
        status = result.decision.status.value
        return ToolResult(status, f"Guardrail decision: {status}", result.to_dict(), {"decision_log": result.evidence_path})

    def scope_check(self, args: dict[str, Any]) -> ToolResult:
        """Return a read-only ROE scope summary and optionally classify one target."""

        raw_target = str(args.get("target") or args.get("host") or args.get("url") or "").strip()
        summary: dict[str, Any] = {
            "engagement": redact_secrets(self.roe.name),
            "authorized": bool(self.roe.authorized),
            "safety_mode": self.roe.safety_mode,
            "testing_window": redact_secrets(self.roe.testing_window),
            "in_scope_targets": _redact_value(self.roe.in_scope_targets),
            "allowed_techniques": _redact_value(self.roe.allowed_techniques),
            "prohibited_techniques": _redact_value(self.roe.prohibited_techniques),
            "stop_conditions": _redact_value(self.roe.stop_conditions),
            "evidence_dir": redact_secrets(self.roe.evidence_dir),
            "no_target_activity": True,
        }
        if not raw_target:
            readiness = "ready" if self.roe.authorized and self.roe.in_scope_targets else "review"
            summary["scope_status"] = readiness
            return ToolResult("ok", "Engagement scope summary generated without target activity.", summary)

        match = target_in_scope(raw_target, self.roe.in_scope_targets)
        decision = "allow" if self.roe.authorized and match.in_scope else "block"
        reason = match.reason
        if not self.roe.authorized:
            reason = "Engagement is not marked authorized; target actions must be blocked. " + reason
        summary["target_check"] = {
            "target": redact_secrets(raw_target),
            "in_scope": bool(match.in_scope),
            "matched_rule": redact_secrets(match.matched_rule) if match.matched_rule else None,
            "decision": decision,
            "reason": redact_secrets(reason),
        }
        message = "Target is in scope." if decision == "allow" else "Target is not authorized for target activity."
        return ToolResult("ok", message, summary)

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
        self.store.update_process(process_id, session_id=self.session_id, pid=proc.pid, status="running")
        _LIVE_PROCESSES[process_id] = proc
        return ToolResult("started", f"Background process {process_id} started with pid {proc.pid}.", {"process_id": process_id, "pid": proc.pid, "decision": decision.to_dict()}, {"stdout": str(stdout_path), "stderr": str(stderr_path), "return_code": str(rc_path), "decision_log": str(evidence_path)})

    def poll_process(self, args: dict[str, Any]) -> ToolResult:
        process_id = _first_int_arg(args, "id", "process_id")
        if process_id is None:
            return ToolResult("error", "Process id is required.")
        process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", "Process not found in this session.")
        return ToolResult(process["status"], f"Process {process['id']} is {process['status']}.", {"process": _redacted_mapping(process), "secret_values_redacted": True})

    def wait_process(self, args: dict[str, Any]) -> ToolResult:
        process_id = _first_int_arg(args, "id", "process_id")
        if process_id is None:
            return ToolResult("error", "Process id is required.")
        deadline = time.monotonic() + max(0, int(args.get("timeout", 30)))
        process = self._refresh_process(process_id)
        while process and process.get("status") in {"running", "starting"} and time.monotonic() < deadline:
            time.sleep(0.05)
            process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", "Process not found in this session.")
        log = self.process_log({"id": process_id, "limit": int(args.get("limit", 4000))})
        return ToolResult(process["status"], f"Process {process_id} wait ended with status {process['status']}.", {"process": _redacted_mapping(process), "stdout": log.data.get("stdout", ""), "stderr": log.data.get("stderr", ""), "secret_values_redacted": True})

    def process_log(self, args: dict[str, Any]) -> ToolResult:
        process_id = _first_int_arg(args, "id", "process_id")
        if process_id is None:
            return ToolResult("error", "Process id is required.")
        process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", "Process not found in this session.")
        limit = int(args.get("limit", 4000))
        stdout = redact_secrets(_tail(Path(process["stdout_path"]), limit))
        stderr = redact_secrets(_tail(Path(process["stderr_path"]), limit))
        return ToolResult("ok", f"Process {process['id']} log tails.", {"process": _redacted_mapping(process), "stdout": stdout, "stderr": stderr, "secret_values_redacted": True})

    def kill_process(self, args: dict[str, Any]) -> ToolResult:
        process_id = _first_int_arg(args, "id", "process_id")
        if process_id is None:
            return ToolResult("error", "Process id is required.")
        process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", "Process not found in this session.")
        pid = process.get("pid")
        if process.get("status") not in {"running", "starting"} or not pid:
            return ToolResult("ok", f"Process {process['id']} is already {process.get('status')}.", {"process": _redacted_mapping(process), "secret_values_redacted": True})
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        self.store.update_process(int(process["id"]), session_id=self.session_id, status="killed", ended_at=utc_now())
        process = self.store.get_process(int(process["id"]), session_id=self.session_id) or process
        return ToolResult("killed", f"Process {process['id']} terminated.", {"process": _redacted_mapping(process), "secret_values_redacted": True})

    def list_processes(self, args: dict[str, Any]) -> ToolResult:
        rows = [self._refresh_process(int(row["id"])) or row for row in self.store.list_processes(self.session_id, limit=int(args.get("limit", 20)))]
        return ToolResult("ok", f"Found {len(rows)} processes.", {"processes": [_redacted_mapping(row) for row in rows], "secret_values_redacted": True})

    def get_process(self, args: dict[str, Any]) -> ToolResult:
        process_id = _first_int_arg(args, "id", "process_id")
        if process_id is None:
            return ToolResult("error", "process id is required.")
        process = self._refresh_process(process_id)
        if not process:
            return ToolResult("error", f"Process {process_id} not found in this session.")
        return ToolResult("ok", f"Process {process_id} returned.", {"process": _redacted_mapping(process), "secret_values_redacted": True})

    def approve(self, args: dict[str, Any]) -> ToolResult:
        approval_id = _first_int_arg(args, "id", "approval_id")
        if approval_id is None:
            return ToolResult("error", "Approval id is required.")
        approval = self.store.get_approval(approval_id, session_id=self.session_id)
        if not approval:
            return ToolResult("error", f"Approval {approval_id} not found in this session.")
        if approval["status"] != "pending":
            return ToolResult("error", f"Approval {approval_id} is already {approval['status']}.", {"approval": _redacted_mapping(approval)})
        if _contains_redacted_marker(approval.get("args")):
            result = {
                "reason": "Approval arguments were redacted before SQLite storage; replay would execute altered input.",
                "operator_action": "Review the redacted approval detail, then re-submit the action using environment variables or a fresh command if execution is still intended.",
            }
            self.store.resolve_approval(approval_id, "blocked_redacted_args", args.get("by", "operator"), result, session_id=self.session_id)
            return ToolResult(
                "blocked",
                "Approval contains redacted arguments and cannot be replayed safely; re-submit the action if execution is still intended.",
                {"approval_id": approval_id, **result},
            )
        if approval["tool_name"] == "run_command":
            approved_args = dict(approval["args"])
            approved_args["_approved"] = True
            approved_args["_approval_id"] = approval_id
            request = _request_from_args(approved_args)
            decision = self.harness.guardrails.evaluate(self.roe, request)
            if decision.status is DecisionStatus.BLOCK:
                self.store.resolve_approval(approval_id, "blocked_on_recheck", args.get("by", "operator"), {"decision": decision.to_dict()}, session_id=self.session_id)
                return ToolResult("blocked", "Approval was blocked on re-check; command was not executed.", {"decision": decision.to_dict()})
            result = self.run_command(approved_args)
            self.store.resolve_approval(approval_id, "approved_executed", args.get("by", "operator"), result.to_dict(), session_id=self.session_id)
            return result
        if approval["tool_name"] == "start_process":
            approved_args = dict(approval["args"])
            approved_args["_approved"] = True
            approved_args["_approval_id"] = approval_id
            decision = self.harness.guardrails.evaluate(self.roe, _request_from_args(approved_args))
            if decision.status is DecisionStatus.BLOCK:
                self.store.resolve_approval(approval_id, "blocked_on_recheck", args.get("by", "operator"), {"decision": decision.to_dict()}, session_id=self.session_id)
                return ToolResult("blocked", "Approval was blocked on re-check; process was not started.", {"decision": decision.to_dict()})
            result = self.start_process(approved_args, approval_id=approval_id)
            self.store.resolve_approval(approval_id, "approved_started", args.get("by", "operator"), result.to_dict(), session_id=self.session_id)
            return result
        if approval["tool_name"] in self.tools:
            approved_args = dict(approval["args"])
            approved_args["_policy_approved"] = True
            result = self.run(approval["tool_name"], approved_args)
            self.store.resolve_approval(approval_id, "approved_executed", args.get("by", "operator"), result.to_dict(), session_id=self.session_id)
            return result
        self.store.resolve_approval(approval_id, "approved", args.get("by", "operator"), {"note": "Approved non-command tool."}, session_id=self.session_id)
        return ToolResult("approved", f"Approval {approval_id} approved.")

    def deny(self, args: dict[str, Any]) -> ToolResult:
        approval_id = _first_int_arg(args, "id", "approval_id")
        if approval_id is None:
            return ToolResult("error", "Approval id is required.")
        approval = self.store.get_approval(approval_id, session_id=self.session_id)
        if not approval:
            return ToolResult("error", f"Approval {approval_id} not found in this session.")
        if approval["status"] != "pending":
            return ToolResult("error", f"Approval {approval_id} is already {approval['status']}.", {"approval": _redacted_mapping(approval)})
        self.store.resolve_approval(approval_id, "denied", args.get("by", "operator"), {"reason": args.get("reason", "")}, session_id=self.session_id)
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
        run_id = _first_int_arg(args, "id", "run_id")
        if run_id is None:
            return ToolResult("error", "id is required.")
        run = self.store.get_tool_run(run_id, session_id=self.session_id)
        if not run:
            return ToolResult("error", "Structured tool run not found in this session.")
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
        finding = self.store.get_finding(finding_id, session_id=self.session_id) or {}
        self.store.audit(self.session_id, "finding_created", {"id": finding_id, "title": redact_secrets(title), "severity": finding.get("severity"), "status": finding.get("status")})
        return ToolResult("ok", f"Finding #{finding_id} created.", {"finding": _redacted_mapping(finding)})

    def update_finding(self, args: dict[str, Any]) -> ToolResult:
        finding_id = _first_int_arg(args, "id", "finding_id")
        if finding_id is None:
            return ToolResult("error", "id is required.")
        existing = self.store.get_finding(finding_id, session_id=self.session_id)
        if not existing:
            return ToolResult("error", "Finding not found in this session.")
        evidence = None
        new_evidence = self._finding_evidence_from_args(args)
        if new_evidence:
            evidence = (existing.get("evidence") or []) + new_evidence if args.get("append_evidence", True) else new_evidence
        finding = self.store.update_finding(
            finding_id,
            session_id=self.session_id,
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
        if not finding:
            return ToolResult("error", "Finding not found in this session.")
        return ToolResult("ok", f"Finding #{finding_id} updated.", {"finding": _redacted_mapping(finding or {})})

    def list_findings(self, args: dict[str, Any]) -> ToolResult:
        findings = self.store.list_findings(self.session_id, status=str(args.get("status") or "all"), limit=int(args.get("limit", 50)))
        return ToolResult("ok", f"{len(findings)} findings returned.", {"findings": [_redacted_mapping(row) for row in findings]})

    def get_finding(self, args: dict[str, Any]) -> ToolResult:
        finding_id = _first_int_arg(args, "id", "finding_id")
        if finding_id is None:
            return ToolResult("error", "id is required.")
        finding = self.store.get_finding(finding_id, session_id=self.session_id)
        if not finding:
            return ToolResult("error", "Finding not found in this session.")
        return ToolResult("ok", f"Finding #{finding['id']} returned.", {"finding": _redacted_mapping(finding)})

    def finding_export(self, args: dict[str, Any]) -> ToolResult:
        finding_id = _first_int_arg(args, "id", "finding_id")
        if finding_id is None:
            return ToolResult("error", "id is required.")
        finding = self.store.get_finding(finding_id, session_id=self.session_id)
        if not finding:
            return ToolResult("error", "Finding not found in this session.")
        report = _finding_report_input(finding)
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

        finding_id = _first_int_arg(args, "id", "finding_id")
        if finding_id is None:
            return ToolResult("error", "id is required.")
        finding = self.store.get_finding(finding_id, session_id=self.session_id)
        if not finding:
            return ToolResult("error", "Finding not found in this session.")
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

    def finding_bundle(self, args: dict[str, Any]) -> ToolResult:
        """Package one finding's report draft, QA review, and linked text evidence."""

        finding_id = _first_int_arg(args, "id", "finding_id")
        if finding_id is None:
            return ToolResult("error", "id is required.")
        finding = self.store.get_finding(finding_id, session_id=self.session_id)
        if not finding:
            return ToolResult("error", "Finding not found in this session.")
        try:
            max_bytes = max(1, min(int(args.get("max_bytes", 2_000_000)), 50_000_000))
            out = _scoped_artifact_output_path(
                self.harness.store.root,
                "findings",
                str(args.get("out") or "").strip(),
                f"finding-{finding['id']}-bundle-{safe_report_filename(finding['title'])}.zip",
                suffix=".zip",
            )
        except (TypeError, ValueError) as exc:
            return ToolResult("error", f"finding_bundle input rejected: {exc}")

        evidence_root = self.harness.store.root.resolve(strict=False)
        review = self._build_finding_review(finding)
        report = _finding_report_input(finding)
        finding_markdown = FindingMarkdownExporter().render_finding(report)
        review_markdown = _finding_review_markdown(finding, review)
        manifest: dict[str, Any] = {
            "created_at": utc_now(),
            "session_id": self.session_id,
            "engagement": redact_secrets(self.roe.name),
            "finding_id": finding["id"],
            "finding_title": redact_secrets(str(finding.get("title") or "")),
            "max_bytes": max_bytes,
            "no_target_activity": True,
            "raw_file_contents_emitted": False,
            "secret_values_redacted": True,
            "redaction": "Text artifacts are passed through the Phobos secret redactor before packaging; binary/oversized/out-of-root files are skipped.",
            "files": [],
            "skipped": [],
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        seen_resolved: set[Path] = set()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _zip_text(archive, "BUNDLE_README.md", _finding_bundle_readme(self.roe.name, finding["id"], finding.get("title") or ""))
            _zip_json(archive, "finding/finding.json", {"finding": _redacted_mapping(finding), "review": review})
            _zip_text(archive, "finding/finding.md", finding_markdown)
            _zip_text(archive, "finding/review.md", review_markdown)
            manifest["files"].extend([
                _zip_manifest_entry("BUNDLE_README.md", "generated", _finding_bundle_readme(self.roe.name, finding["id"], finding.get("title") or "")),
                _zip_manifest_entry("finding/finding.json", "generated", json.dumps({"finding": _redacted_mapping(finding), "review": review}, indent=2, sort_keys=True)),
                _zip_manifest_entry("finding/finding.md", "generated", finding_markdown),
                _zip_manifest_entry("finding/review.md", "generated", review_markdown),
            ])
            for path_value, source in self._finding_bundle_artifact_candidates(finding):
                result = _zip_redacted_evidence_artifact(
                    archive,
                    evidence_root,
                    path_value,
                    source,
                    max_bytes=max_bytes,
                    seen_resolved=seen_resolved,
                    skip_path=out,
                )
                if result.get("archive_path"):
                    manifest["files"].append(result)
                else:
                    manifest["skipped"].append(result)
            _zip_json(archive, "MANIFEST.json", manifest)
        self.store.audit(self.session_id, "finding_bundle_exported", {"id": finding["id"], "path": str(out), "files": len(manifest["files"]), "skipped": len(manifest["skipped"])})
        payload = _redacted_mapping({
            "finding": finding,
            "review": review,
            "bundle": str(out),
            "manifest": manifest,
            "no_target_activity": True,
            "raw_file_contents_emitted": False,
            "secret_values_redacted": True,
        })
        return ToolResult("ok", f"Finding #{finding['id']} evidence bundle exported: {out}", payload, {"zip": str(out)})

    def _finding_bundle_artifact_candidates(self, finding: dict[str, Any]) -> list[tuple[str, str]]:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        candidates: list[tuple[str, str]] = []

        def add(path_value: Any, source: str) -> None:
            text = str(path_value or "").strip()
            if text:
                candidates.append((text, redact_secrets(source) or source))

        for item in evidence:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "tool_run" and item.get("id"):
                run_id = _coerce_int(item.get("id"))
                run = self.store.get_tool_run(run_id, session_id=self.session_id) if run_id is not None else None
                if run:
                    add(run.get("artifact_path"), f"tool_run:{run['id']}")
            for key in ("artifact_path", "path", "file"):
                add(item.get(key), f"finding_evidence:{key}")
        return candidates

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
                run_id = _coerce_int(item.get("id"))
                run = self.store.get_tool_run(run_id, session_id=self.session_id) if run_id is not None else None
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
            run = self.store.get_tool_run(run_id, session_id=self.session_id)
            if run:
                evidence.append({"type": "tool_run", "id": run_id, "tool_name": run.get("tool_name"), "target": run.get("target"), "status": run.get("status"), "artifact_path": run.get("artifact_path")})
        return [_redact_value(item) for item in evidence]

    def remember(self, args: dict[str, Any]) -> ToolResult:
        key = str(args.get("key", "")).strip()
        value = str(args.get("value", "")).strip()
        if not key or not value:
            return ToolResult("error", "remember requires key and value.")
        mem_id = self.store.remember(key, value, tags=str(args.get("tags", "")))
        display_key = redact_secrets(key) or ""
        return ToolResult("ok", f"Stored memory {mem_id}: {display_key}", {"id": mem_id, "key": display_key})

    def recall(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.recall(str(args.get("query", "")), limit=int(args.get("limit", 10)))
        return ToolResult("ok", f"Found {len(rows)} memory entries.", {"memories": rows})

    def list_memories(self, args: dict[str, Any]) -> ToolResult:
        limit = max(1, min(int(args.get("limit", 50)), 200))
        query = str(args.get("query", "")).strip()
        rows = self.store.recall(query, limit=limit) if query else self.store.list_memories(limit=limit)
        return ToolResult("ok", f"Found {len(rows)} memory entries.", {"memories": rows, "secret_values_redacted": True})

    def get_memory(self, args: dict[str, Any]) -> ToolResult:
        raw_id = args.get("id") or args.get("memory_id")
        key = str(args.get("key", "")).strip()
        memory = self.store.get_memory(memory_id=int(raw_id) if raw_id else None, key=key or None)
        if not memory:
            return ToolResult("error", "Memory not found.")
        return ToolResult("ok", f"Memory {memory['id']} retrieved.", {"memory": _redacted_mapping(memory), "secret_values_redacted": True})

    def forget_memory(self, args: dict[str, Any]) -> ToolResult:
        raw_id = args.get("id") or args.get("memory_id")
        key = str(args.get("key", "")).strip()
        if not raw_id and not key:
            return ToolResult("error", "forget_memory requires id or key.")
        memory = self.store.delete_memory(memory_id=int(raw_id) if raw_id else None, key=key or None)
        if not memory:
            return ToolResult("error", "Memory not found.")
        return ToolResult("ok", f"Deleted memory {memory['id']}.", {"deleted": _redacted_mapping(memory), "secret_values_redacted": True})

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
            node = self.store.get_context_node(int(node_arg), session_id=self.session_id)
            if not node:
                return ToolResult("error", f"Context node {node_arg} not found in this session.")
            children = self.store.child_context_nodes(int(node_arg), session_id=self.session_id)
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
        node = self.store.get_context_node(node_id, session_id=self.session_id)
        if not node:
            return ToolResult("error", f"Context node {node_id} not found in this session.")
        source_limit = int(args.get("source_limit", 40))
        expanded_sources = []
        for source in node.get("sources", [])[:source_limit]:
            if source.get("type") == "message":
                message = self.store.get_message(int(source.get("id")), session_id=self.session_id)
                if message:
                    expanded_sources.append({"type": "message", "message": _redacted_mapping(message)})
            elif source.get("type") == "context_node":
                child = self.store.get_context_node(int(source.get("id")), session_id=self.session_id)
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
        display_key = redact_secrets(key) or ""
        display_context = redact_secrets(context) or ""
        display_tags = redact_secrets(tags) or ""
        self.store.audit(self.session_id, "hindsight_retain", {"key": display_key, "context": display_context, "tags": display_tags})
        return ToolResult("ok", f"Retained Hindsight-style memory {mem_id}: {display_key}", {"id": mem_id, "key": display_key, "context": display_context, "tags": display_tags})

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
        jobs = [_redacted_mapping(asdict(job)) for job in self.store.list_jobs(self.session_id)]
        return ToolResult("ok", f"Found {len(jobs)} jobs.", {"jobs": jobs, "secret_values_redacted": True})

    def get_job(self, args: dict[str, Any]) -> ToolResult:
        job_id = _first_int_arg(args, "id", "job_id")
        if job_id is None:
            return ToolResult("error", "Job id is required.")
        job = self.store.get_job(job_id, session_id=self.session_id)
        if not job:
            return ToolResult("error", f"Job {job_id} not found in this session.")
        return ToolResult("ok", f"Job {job_id} returned.", {"job": _redacted_mapping(asdict(job)), "secret_values_redacted": True})

    def update_job(self, args: dict[str, Any]) -> ToolResult:
        job_id = _first_int_arg(args, "id", "job_id")
        if job_id is None:
            return ToolResult("error", "Job id is required.")
        updates: dict[str, Any] = {}
        if "name" in args:
            updates["name"] = str(args.get("name") or "")
        if "schedule" in args:
            updates["schedule"] = str(args.get("schedule") or "manual")
        if "prompt" in args:
            updates["prompt"] = str(args.get("prompt") or "")
        if "enabled" in args:
            updates["enabled"] = _truthy_bool(args.get("enabled"), default=True)
        job = self.store.update_job(job_id, session_id=self.session_id, **updates)
        if not job:
            return ToolResult("error", f"Job {job_id} not found in this session.")
        self.store.audit(self.session_id, "job_updated", {"id": job_id, "updates": _safe_json(updates)})
        return ToolResult("ok", f"Job {job_id} updated.", {"job": _redacted_mapping(asdict(job)), "secret_values_redacted": True})

    def enable_job(self, args: dict[str, Any]) -> ToolResult:
        job_id = _first_int_arg(args, "id", "job_id")
        if job_id is None:
            return ToolResult("error", "Job id is required.")
        job = self.store.update_job(job_id, session_id=self.session_id, enabled=True)
        if not job:
            return ToolResult("error", f"Job {job_id} not found in this session.")
        self.store.audit(self.session_id, "job_enabled", {"id": job_id})
        return ToolResult("ok", f"Job {job_id} enabled.", {"job": _redacted_mapping(asdict(job)), "secret_values_redacted": True})

    def disable_job(self, args: dict[str, Any]) -> ToolResult:
        job_id = _first_int_arg(args, "id", "job_id")
        if job_id is None:
            return ToolResult("error", "Job id is required.")
        job = self.store.update_job(job_id, session_id=self.session_id, enabled=False)
        if not job:
            return ToolResult("error", f"Job {job_id} not found in this session.")
        self.store.audit(self.session_id, "job_disabled", {"id": job_id})
        return ToolResult("ok", f"Job {job_id} disabled.", {"job": _redacted_mapping(asdict(job)), "secret_values_redacted": True})

    def run_due_jobs(self, args: dict[str, Any]) -> ToolResult:
        jobs = [_redacted_mapping(asdict(job)) for job in self.store.due_jobs(self.session_id)]
        return ToolResult("ok", f"{len(jobs)} jobs are due. Use OffSecAgentRuntime.run_due_jobs() to execute them.", {"due_jobs": jobs, "secret_values_redacted": True})

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
        delegation = self.store.complete_delegation(
            delegation_id,
            status,
            results,
            {"summary": str(summary_path), "dir": str(out_dir), "isolated_child_sessions": isolate},
            session_id=self.session_id,
        )
        return ToolResult(status, f"Delegation {delegation_id} completed with {len(results)} task(s).", {"delegation": delegation}, {"summary": str(summary_path), "directory": str(out_dir)})

    def list_delegations(self, args: dict[str, Any]) -> ToolResult:
        delegations = self.store.list_delegations(self.session_id, limit=int(args.get("limit", 20)))
        return ToolResult("ok", f"Found {len(delegations)} delegation batch(es).", {"delegations": [_redacted_mapping(row) for row in delegations]})

    def get_delegation(self, args: dict[str, Any]) -> ToolResult:
        delegation_id = _first_int_arg(args, "id", "delegation_id")
        if delegation_id is None:
            return ToolResult("error", "id is required.")
        delegation = self.store.get_delegation(delegation_id, session_id=self.session_id)
        if not delegation:
            return ToolResult("error", f"Delegation {delegation_id} not found in this session.")
        return ToolResult("ok", f"Delegation {delegation_id} returned.", {"delegation": _redacted_mapping(delegation)})

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

    def guardrail_selftest(self, args: dict[str, Any]) -> ToolResult:
        """Simulate representative guardrail outcomes without executing or touching targets."""

        raw_target = str(args.get("target") or args.get("host") or args.get("url") or "").strip()
        selected_target = raw_target or _first_selftest_scope_target(self.roe.in_scope_targets)
        command_target = _selftest_command_target(selected_target)
        out_of_scope_target = _selftest_out_of_scope_target(self.roe.in_scope_targets)
        safety_mode = (self.roe.safety_mode or "non_destructive").strip().lower().replace("-", "_")
        active_expected = "allow" if safety_mode == "non_destructive" else "confirm"
        case_specs = [
            {
                "name": "read_only_headers",
                "category": "allow",
                "target": selected_target,
                "action_type": "web",
                "purpose": "guardrail self-test read-only header capture",
                "command": f"curl -I https://{command_target}",
                "expected": "allow",
                "why": "In-scope read-only capture should be allowed while still requiring explicit operator execution outside this self-test.",
            },
            {
                "name": "routine_active_enumeration",
                "category": active_expected,
                "target": selected_target,
                "action_type": "service-enumeration",
                "purpose": "guardrail self-test routine version enumeration",
                "command": f"nmap -sV --version-light {command_target}",
                "expected": active_expected,
                "why": "Routine active enumeration is allowed in non_destructive mode and confirmation-gated in standard mode.",
            },
            {
                "name": "state_changing_http",
                "category": "confirm",
                "target": selected_target,
                "action_type": "web",
                "purpose": "guardrail self-test controlled state change",
                "command": f"curl -X POST https://{command_target}/phobos-controlled-test",
                "expected": "confirm",
                "why": "State-changing HTTP methods should queue for human/ROE confirmation.",
            },
            {
                "name": "lockout_sensitive_auth",
                "category": "confirm",
                "target": selected_target,
                "action_type": "auth",
                "purpose": "guardrail self-test password spray against controlled test user",
                "command": f"kerbrute passwordspray --dc {command_target} users.txt '<REDACTED_TEST_PASSWORD>'",
                "expected": "confirm",
                "why": "Lockout-sensitive authentication testing should queue for confirmation.",
            },
            {
                "name": "availability_impacting_pattern",
                "category": "block",
                "target": selected_target,
                "action_type": "web",
                "purpose": "guardrail self-test high-rate availability-impacting pattern",
                "command": f"hping3 --flood {command_target}",
                "expected": "block",
                "why": "High-rate availability-impacting patterns should hard-block.",
            },
            {
                "name": "out_of_scope_target",
                "category": "block",
                "target": out_of_scope_target,
                "action_type": "web",
                "purpose": "guardrail self-test out-of-scope target",
                "command": f"curl -I https://{_selftest_command_target(out_of_scope_target)}",
                "expected": "block",
                "why": "Targets not listed in the ROE must fail closed.",
            },
        ]
        cases: list[dict[str, Any]] = []
        for spec in case_specs:
            request = ActionRequest(
                target=str(spec["target"]),
                action_type=str(spec["action_type"]),
                purpose=str(spec["purpose"]),
                command=str(spec["command"]),
                actor="phobos-guardrail-selftest",
                metadata={"selftest_case": spec["name"], "no_target_activity": True},
            )
            decision = self.harness.guardrails.evaluate(self.roe, request)
            actual = decision.status.value
            expected = str(spec["expected"])
            passed = actual == expected
            cases.append(_redacted_mapping({
                "name": spec["name"],
                "category": spec["category"],
                "expected": expected,
                "actual": actual,
                "status": "pass" if passed else "fail",
                "target": request.target,
                "action_type": request.action_type,
                "purpose": request.purpose,
                "redacted_command": decision.redacted_command,
                "reasons": decision.reasons,
                "required_confirmations": decision.required_confirmations,
                "safer_alternatives": decision.safer_alternatives,
                "why": spec["why"],
            }))
        counts = _preflight_counts(cases)
        readiness = "ready" if counts.get("fail", 0) == 0 else "blocked" if not self.roe.authorized or not self.roe.in_scope_targets else "review"
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "guardrails",
            str(args.get("out") or "").strip(),
            f"guardrail-selftest-{stamp}.md",
            suffix=".md",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_guardrail_selftest_markdown(self.roe.name, readiness, cases, counts, selected_target), encoding="utf-8")
        data = _redacted_mapping({
            "readiness": readiness,
            "counts": counts,
            "safety_mode": self.roe.safety_mode,
            "target": selected_target,
            "cases": cases,
            "path": str(out),
            "no_target_activity": True,
            "executed": False,
            "secret_values_redacted": True,
        })
        self.store.audit(self.session_id, "guardrail_selftest", {"readiness": readiness, "counts": counts, "path": str(out)})
        return ToolResult(
            "ok",
            f"Guardrail self-test {readiness}: {counts.get('fail', 0)} fail, {counts.get('pass', 0)} pass.",
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
        safe_name = _safe_filename(redact_secrets(src.name) or src.name)
        dest = media_dir / f"{digest[:12]}-{safe_name}"
        shutil.copyfile(src, dest)
        media_id = self.store.create_media_artifact(self.session_id, kind, str(src), str(dest), mime_type, digest, len(data), {"original_name": src.name})
        media = self.store.get_media_artifact(media_id, session_id=self.session_id) or {}
        display_dest = redact_secrets(str(dest)) or str(dest)
        return ToolResult("ok", f"Imported media/artifact {media_id}: {display_dest}", {"media": _redacted_mapping(media)}, {"file": display_dest})

    def media_list(self, args: dict[str, Any]) -> ToolResult:
        rows = self.store.list_media_artifacts(self.session_id, limit=int(args.get("limit", 50)))
        return ToolResult("ok", f"Found {len(rows)} media/artifact file(s).", {"media": [_redacted_mapping(row) for row in rows]})

    def media_get(self, args: dict[str, Any]) -> ToolResult:
        media_id = _first_int_arg(args, "id", "media_id")
        if media_id is None:
            return ToolResult("error", "id is required.")
        media = self.store.get_media_artifact(media_id, session_id=self.session_id)
        if not media:
            return ToolResult("error", f"Media/artifact {media_id} not found in this session.")
        data = _redacted_mapping(media)
        data["no_file_content_read"] = True
        return ToolResult("ok", f"Media/artifact {media_id} returned.", {"media": data})

    def resolve_local_ref(self, args: dict[str, Any]) -> ToolResult:
        parsed = _parse_local_ref(args)
        if parsed is None:
            return ToolResult(
                "error",
                "resolve_local_ref requires ref=<kind:id|kind:path> or kind=... plus id/path.",
                {"no_target_activity": True, "secret_values_redacted": True},
            )
        kind, value, display_ref = parsed
        entity_handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "approval": self.get_approval,
            "task": self.get_task,
            "process": self.get_process,
            "finding": self.get_finding,
            "tool-run": self.get_tool_run,
            "job": self.get_job,
            "delegation": self.get_delegation,
            "media": self.media_get,
            "memory": self.get_memory,
            "audit": self.get_audit,
            "context-node": self.context_describe,
        }
        if kind in entity_handlers:
            ident = _coerce_int(value)
            if ident is None:
                return ToolResult("error", f"{kind} refs require an integer id.", {"ref": display_ref, "kind": kind, "no_target_activity": True, "secret_values_redacted": True})
            result = entity_handlers[kind]({"id": ident})
            if result.status != "ok":
                return ToolResult(result.status, f"{display_ref} not resolved: {result.message}", {"ref": display_ref, "kind": kind, "id": ident, "no_target_activity": True, "secret_values_redacted": True})
            return ToolResult(
                "ok",
                f"Resolved {display_ref}.",
                {
                    "ref": display_ref,
                    "kind": kind,
                    "id": ident,
                    "entity": _redacted_mapping(result.data),
                    "no_target_activity": True,
                    "secret_values_redacted": True,
                },
            )
        if kind in {"artifact", "preflight", "manifest", "timeline", "closeout", "briefing", "export", "pack"}:
            max_bytes = _coerce_int(args.get("max_bytes", 50_000_000))
            if max_bytes is None:
                return ToolResult("error", "max_bytes must be an integer.", {"ref": display_ref, "kind": kind, "no_target_activity": True, "secret_values_redacted": True})
            return self._resolve_artifact_ref(kind, value, display_ref, max_bytes=max_bytes)
        return ToolResult("error", f"Unsupported local ref kind: {kind}", {"ref": display_ref, "kind": kind, "no_target_activity": True, "secret_values_redacted": True})

    def _resolve_artifact_ref(self, kind: str, path_value: str, display_ref: str, *, max_bytes: int = 50_000_000) -> ToolResult:
        max_bytes = max(1, min(int(max_bytes), 500_000_000))
        raw_rel = str(path_value or "").strip().replace("\\", "/")
        if not raw_rel:
            return ToolResult("error", "artifact refs require an evidence-root relative path.", {"ref": display_ref, "kind": kind, "no_target_activity": True, "secret_values_redacted": True})
        raw_parts = raw_rel.split("/")
        if raw_rel.startswith("/") or re.match(r"^[A-Za-z]:", raw_rel) or ".." in raw_parts:
            return ToolResult("blocked", "Artifact ref path is not evidence-root relative.", {"ref": redact_secrets(display_ref), "kind": kind, "path": redact_secrets(raw_rel), "no_target_activity": True, "secret_values_redacted": True})
        rel = "/".join(part for part in raw_parts if part not in {"", "."})
        if not rel:
            return ToolResult("error", "artifact refs require a non-empty relative path.", {"ref": display_ref, "kind": kind, "no_target_activity": True, "secret_values_redacted": True})
        root = self.harness.store.root.resolve(strict=False)
        candidate = (root / rel).resolve(strict=False)
        if not _is_relative_to(candidate, root):
            return ToolResult("blocked", "Artifact ref resolves outside the engagement evidence root.", {"ref": redact_secrets(display_ref), "kind": kind, "path": redact_secrets(rel), "no_target_activity": True, "secret_values_redacted": True})
        exists = candidate.exists()
        artifact: dict[str, Any] = {
            "path": rel,
            "kind": kind,
            "exists": bool(exists),
            "category": _artifact_category(rel),
            "no_file_content_emitted": True,
        }
        if exists:
            if candidate.is_dir():
                artifact.update({"type": "directory"})
            elif candidate.is_file():
                stat_result = candidate.stat()
                artifact.update({
                    "type": "file",
                    "bytes": stat_result.st_size,
                    "mime_type": mimetypes.guess_type(rel)[0] or "application/octet-stream",
                    "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat_result.st_mtime)),
                })
                if stat_result.st_size <= max_bytes:
                    artifact["sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
                else:
                    artifact["hash_skipped"] = f"larger than max_bytes ({max_bytes})"
            else:
                artifact.update({"type": "other"})
        return ToolResult(
            "ok",
            f"Resolved {display_ref} as local artifact metadata.",
            {"ref": display_ref, "kind": kind, "artifact": _redacted_mapping(artifact), "no_target_activity": True, "secret_values_redacted": True},
        )

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
        status = str(args.get("status", "pending") or "pending").strip().lower()
        limit = int(args.get("limit", 100))
        rows = self.store.list_approvals(self.session_id, status=status, limit=limit)
        return ToolResult(
            "ok",
            f"Found {len(rows)} approval(s).",
            {"approvals": [_redacted_mapping(row) for row in rows], "status": status, "secret_values_redacted": True},
        )

    def get_approval(self, args: dict[str, Any]) -> ToolResult:
        approval_id = _first_int_arg(args, "id", "approval_id")
        if approval_id is None:
            return ToolResult("error", "Approval id is required.")
        approval = self.store.get_approval(approval_id, session_id=self.session_id)
        if not approval:
            return ToolResult("error", f"Approval {approval_id} not found in this session.")
        return ToolResult(
            "ok",
            f"Approval {approval_id} returned.",
            {"approval": _redacted_mapping(approval), "secret_values_redacted": True},
        )

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
        return ToolResult("ok", f"Found {len(rows)} audit entries.", {"audit": rows, "secret_values_redacted": True})

    def get_audit(self, args: dict[str, Any]) -> ToolResult:
        audit_id = _first_int_arg(args, "id", "audit_id")
        if audit_id is None:
            return ToolResult("error", "Audit id is required.", {"no_target_activity": True, "secret_values_redacted": True})
        row = self.store.get_audit(audit_id, session_id=self.session_id)
        if not row:
            return ToolResult("error", f"Audit entry {audit_id} not found in this session.", {"no_target_activity": True, "secret_values_redacted": True})
        return ToolResult(
            "ok",
            f"Audit entry {audit_id} returned.",
            {"audit": _redacted_mapping(row), "no_target_activity": True, "secret_values_redacted": True},
        )

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

        for approval in self.store.list_approvals(self.session_id, status="all", limit=max(limit, 100)):
            add(
                approval.get("resolved_at") or approval.get("requested_at"),
                "approval",
                f"{approval.get('tool_name')} approval #{approval.get('id')}",
                status=str(approval.get("status") or ""),
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

    def evidence_manifest(self, args: dict[str, Any]) -> ToolResult:
        """Build a read-only chain-of-custody style inventory of evidence files.

        The manifest intentionally records metadata and hashes only. It does not
        emit artifact contents, and it resolves every candidate path before stat
        or read so symlink escapes cannot become host-file reads.
        """

        limit = max(1, min(int(args.get("limit", 1000)), 5000))
        max_bytes = max(1, min(int(args.get("max_bytes", 50_000_000)), 500_000_000))
        include_agent = _truthy_bool(args.get("include_agent", True), default=True)
        evidence_root = self.harness.store.root.resolve(strict=False)
        manifest_dir = (self.harness.store.root / "agent" / "manifests").resolve(strict=False)
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out_json = _scoped_artifact_output_path(
            self.harness.store.root,
            "manifests",
            str(args.get("out") or "").strip(),
            f"evidence-manifest-{stamp}.json",
            suffix=".json",
        )
        out_markdown = out_json.with_suffix(".md")
        if not _is_relative_to(out_markdown.resolve(strict=False), manifest_dir):
            raise ValueError("artifact output path escapes the manifests artifact directory")

        entries: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        total_files_seen = 0
        total_bytes = 0
        counts_by_category: dict[str, int] = {}
        truncated = False

        for path in sorted(evidence_root.rglob("*")):
            try:
                resolved = path.resolve(strict=False)
                rel = path.relative_to(evidence_root).as_posix()
            except (OSError, RuntimeError, ValueError) as exc:
                skipped.append({"path": redact_secrets(str(path)) or str(path), "reason": f"path could not be safely resolved: {exc}"})
                continue
            if not _is_relative_to(resolved, evidence_root):
                skipped.append({"path": redact_secrets(rel) or rel, "reason": "symlink target outside evidence root"})
                continue
            if _is_relative_to(resolved, manifest_dir):
                continue
            if not include_agent and rel.startswith("agent/"):
                continue
            if not resolved.is_file():
                continue
            total_files_seen += 1
            stat_result = resolved.stat()
            if stat_result.st_size > max_bytes:
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"larger than max_bytes ({max_bytes})", "bytes": stat_result.st_size})
                continue
            if len(entries) >= limit:
                truncated = True
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"limit reached ({limit})"})
                continue
            data = resolved.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            category = _artifact_category(rel)
            counts_by_category[category] = counts_by_category.get(category, 0) + 1
            total_bytes += stat_result.st_size
            entries.append(_redacted_mapping({
                "path": rel,
                "category": category,
                "bytes": stat_result.st_size,
                "sha256": digest,
                "mime_type": mimetypes.guess_type(rel)[0] or "application/octet-stream",
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat_result.st_mtime)),
            }))

        counts = {
            "files_hashed": len(entries),
            "files_seen": total_files_seen,
            "bytes_hashed": total_bytes,
            "skipped": len(skipped),
            "by_category": dict(sorted(counts_by_category.items())),
            "truncated": truncated,
        }
        payload = _redacted_mapping({
            "created_at": utc_now(),
            "engagement": self.roe.name,
            "session_id": self.session_id,
            "evidence_root": str(evidence_root),
            "include_agent": include_agent,
            "max_bytes": max_bytes,
            "limit": limit,
            "counts": counts,
            "entries": entries,
            "skipped": skipped,
            "no_target_activity": True,
            "secret_values_redacted": True,
        })
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out_markdown.write_text(_evidence_manifest_markdown(self.roe.name, entries, skipped, counts), encoding="utf-8")
        payload["path"] = str(out_json)
        payload["markdown_path"] = str(out_markdown)
        return ToolResult(
            "ok",
            f"Evidence manifest wrote {len(entries)} file hash(es); skipped {len(skipped)}.",
            payload,
            {"json": str(out_json), "markdown": str(out_markdown)},
        )

    def evidence_manifest_verify(self, args: dict[str, Any]) -> ToolResult:
        """Verify a previously generated evidence manifest against local artifacts.

        This is a read-only chain-of-custody check with respect to the engagement
        target: it only reads files under the evidence root, resolves candidates
        before stat/hash, writes a redacted verification report under
        ``agent/manifests``, and never emits artifact contents.
        """

        max_bytes = max(1, min(int(args.get("max_bytes", 50_000_000)), 500_000_000))
        limit = max(1, min(int(args.get("limit", 1000)), 5000))
        detect_new = _truthy_bool(args.get("detect_new", True), default=True)
        evidence_root = self.harness.store.root.resolve(strict=False)
        manifest_dir = (self.harness.store.root / "agent" / "manifests").resolve(strict=False)
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out_json = _scoped_artifact_output_path(
            self.harness.store.root,
            "manifests",
            str(args.get("out") or "").strip(),
            f"manifest-verification-{stamp}.json",
            suffix=".json",
        )
        out_markdown = out_json.with_suffix(".md")
        if not _is_relative_to(out_markdown.resolve(strict=False), manifest_dir):
            raise ValueError("artifact output path escapes the manifests artifact directory")

        source_path = _resolve_manifest_input_path(evidence_root, str(args.get("path") or args.get("manifest") or "").strip())
        if source_path is None:
            return ToolResult(
                "error",
                "No evidence manifest JSON found under agent/manifests.",
                {"manifest_dir": str(manifest_dir), "no_target_activity": True, "secret_values_redacted": True},
            )
        try:
            manifest = json.loads(source_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return ToolResult(
                "error",
                f"Manifest could not be read or parsed: {exc}",
                {"source_manifest": str(source_path), "no_target_activity": True, "secret_values_redacted": True},
            )
        entries_raw = manifest.get("entries")
        if not isinstance(entries_raw, list):
            return ToolResult(
                "error",
                "Manifest JSON does not contain an entries list.",
                {"source_manifest": str(source_path), "no_target_activity": True, "secret_values_redacted": True},
            )

        expected_by_path: dict[str, dict[str, Any]] = {}
        duplicate_paths: list[dict[str, Any]] = []
        invalid_entries: list[dict[str, Any]] = []
        unsafe: list[dict[str, Any]] = []
        for index, entry in enumerate(entries_raw):
            if not isinstance(entry, dict):
                invalid_entries.append({"index": index, "reason": "entry is not an object"})
                continue
            raw_rel = str(entry.get("path") or "").strip().replace("\\", "/")
            raw_parts = raw_rel.split("/")
            if raw_rel.startswith("/") or re.match(r"^[A-Za-z]:", raw_rel) or ".." in raw_parts:
                unsafe.append({"path": redact_secrets(raw_rel) or raw_rel, "reason": "manifest entry path is not evidence-root relative"})
                continue
            rel = "/".join(part for part in raw_parts if part not in {"", "."})
            if not rel:
                invalid_entries.append({"index": index, "reason": "entry path is empty"})
                continue
            if rel in expected_by_path:
                duplicate_paths.append({"path": redact_secrets(rel) or rel, "reason": "duplicate manifest entry path"})
                continue
            expected_by_path[rel] = entry

        verified: list[dict[str, Any]] = []
        changed: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for rel, expected in sorted(expected_by_path.items()):
            rel_parts = Path(rel).parts
            if Path(rel).is_absolute() or ".." in rel_parts:
                unsafe.append({"path": redact_secrets(rel) or rel, "reason": "manifest entry path is not evidence-root relative"})
                continue
            candidate = evidence_root / rel
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                unsafe.append({"path": redact_secrets(rel) or rel, "reason": f"path could not be safely resolved: {exc}"})
                continue
            if not _is_relative_to(resolved, evidence_root):
                unsafe.append({"path": redact_secrets(rel) or rel, "reason": "symlink target outside evidence root"})
                continue
            if _is_relative_to(resolved, manifest_dir):
                skipped.append({"path": redact_secrets(rel) or rel, "reason": "manifest artifact self-reference skipped"})
                continue
            if not resolved.exists():
                missing.append(_redacted_mapping({"path": rel, "expected_sha256": expected.get("sha256"), "expected_bytes": expected.get("bytes"), "reason": "missing"}))
                continue
            if not resolved.is_file():
                missing.append(_redacted_mapping({"path": rel, "expected_sha256": expected.get("sha256"), "expected_bytes": expected.get("bytes"), "reason": "not a regular file"}))
                continue
            try:
                stat_result = resolved.stat()
            except OSError as exc:
                unsafe.append({"path": redact_secrets(rel) or rel, "reason": f"stat failed: {exc}"})
                continue
            if stat_result.st_size > max_bytes:
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"larger than max_bytes ({max_bytes})", "bytes": stat_result.st_size})
                continue
            try:
                data = resolved.read_bytes()
            except OSError as exc:
                unsafe.append({"path": redact_secrets(rel) or rel, "reason": f"read failed: {exc}"})
                continue
            actual_sha = hashlib.sha256(data).hexdigest()
            actual_bytes = stat_result.st_size
            expected_sha = str(expected.get("sha256") or "").strip().lower()
            expected_bytes_value = expected.get("bytes")
            try:
                expected_bytes = int(expected_bytes_value) if expected_bytes_value is not None else None
            except (TypeError, ValueError):
                expected_bytes = None
            reasons: list[str] = []
            if not expected_sha:
                reasons.append("source manifest entry has no SHA-256")
            elif actual_sha != expected_sha:
                reasons.append("SHA-256 mismatch")
            if expected_bytes is None:
                reasons.append("source manifest entry has no byte count")
            elif actual_bytes != expected_bytes:
                reasons.append("byte count mismatch")
            row = _redacted_mapping({
                "path": rel,
                "category": expected.get("category") or _artifact_category(rel),
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
                "expected_bytes": expected_bytes,
                "actual_bytes": actual_bytes,
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat_result.st_mtime)),
                "reasons": reasons,
            })
            if reasons:
                changed.append(row)
            else:
                verified.append(row)

        include_agent = bool(manifest.get("include_agent", True))
        new_entries: list[dict[str, Any]] = []
        new_truncated = False
        if detect_new:
            expected_paths = set(expected_by_path)
            for path in sorted(evidence_root.rglob("*")):
                try:
                    resolved = path.resolve(strict=False)
                    rel = path.relative_to(evidence_root).as_posix()
                except (OSError, RuntimeError, ValueError) as exc:
                    skipped.append({"path": redact_secrets(str(path)) or str(path), "reason": f"path could not be safely resolved while looking for new artifacts: {exc}"})
                    continue
                if rel in expected_paths:
                    continue
                if _is_relative_to(resolved, manifest_dir):
                    continue
                if not include_agent and rel.startswith("agent/"):
                    continue
                if not _is_relative_to(resolved, evidence_root):
                    skipped.append({"path": redact_secrets(rel) or rel, "reason": "symlink target outside evidence root"})
                    continue
                if not resolved.is_file():
                    continue
                stat_result = resolved.stat()
                if stat_result.st_size > max_bytes:
                    skipped.append({"path": redact_secrets(rel) or rel, "reason": f"new artifact larger than max_bytes ({max_bytes})", "bytes": stat_result.st_size})
                    continue
                if len(new_entries) >= limit:
                    new_truncated = True
                    skipped.append({"path": redact_secrets(rel) or rel, "reason": f"new artifact limit reached ({limit})"})
                    continue
                try:
                    data = resolved.read_bytes()
                except OSError as exc:
                    unsafe.append({"path": redact_secrets(rel) or rel, "reason": f"read failed while hashing new artifact: {exc}"})
                    continue
                new_entries.append(_redacted_mapping({
                    "path": rel,
                    "category": _artifact_category(rel),
                    "bytes": stat_result.st_size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "mime_type": mimetypes.guess_type(rel)[0] or "application/octet-stream",
                    "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat_result.st_mtime)),
                }))

        counts = {
            "expected": len(expected_by_path),
            "verified": len(verified),
            "changed": len(changed),
            "missing": len(missing),
            "unsafe": len(unsafe),
            "new": len(new_entries),
            "skipped": len(skipped),
            "duplicate_paths": len(duplicate_paths),
            "invalid_entries": len(invalid_entries),
            "new_truncated": new_truncated,
        }
        if changed or missing or unsafe:
            verification_status = "changed"
        elif duplicate_paths or invalid_entries or new_entries or skipped:
            verification_status = "review"
        else:
            verification_status = "verified"
        payload = _redacted_mapping({
            "created_at": utc_now(),
            "engagement": self.roe.name,
            "session_id": self.session_id,
            "source_manifest": str(source_path),
            "source_manifest_created_at": manifest.get("created_at"),
            "verification_status": verification_status,
            "counts": counts,
            "verified": verified[: min(len(verified), 200)],
            "changed": changed,
            "missing": missing,
            "unsafe": unsafe,
            "new": new_entries,
            "skipped": skipped,
            "duplicate_paths": duplicate_paths,
            "invalid_entries": invalid_entries,
            "detect_new": detect_new,
            "max_bytes": max_bytes,
            "limit": limit,
            "no_target_activity": True,
            "secret_values_redacted": True,
            "path": str(out_json),
            "markdown_path": str(out_markdown),
        })
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out_markdown.write_text(_evidence_manifest_verification_markdown(self.roe.name, str(source_path), verification_status, counts, changed, missing, unsafe, new_entries, skipped, duplicate_paths, invalid_entries), encoding="utf-8")
        self.store.audit(self.session_id, "evidence_manifest_verified", {"source_manifest": str(source_path), "verification_status": verification_status, "counts": counts, "path": str(out_json)})
        return ToolResult(
            "ok",
            f"Evidence manifest verification {verification_status}: {counts['verified']} verified, {counts['changed']} changed, {counts['missing']} missing, {counts['new']} new.",
            payload,
            {"json": str(out_json), "markdown": str(out_markdown)},
        )

    def evidence_secret_scan(self, args: dict[str, Any]) -> ToolResult:
        """Scan local evidence artifacts for secret-like material without target activity.

        This is a closeout hygiene check, not target validation: it reads only
        files that resolve under the engagement evidence root, skips symlink
        escapes and oversized/binary artifacts, and emits redacted previews only.
        """

        limit = max(1, min(int(args.get("limit", 200)), 5000))
        max_bytes = max(1, min(int(args.get("max_bytes", 2_000_000)), 50_000_000))
        include_agent = _truthy_bool(args.get("include_agent", True), default=True)
        evidence_root = self.harness.store.root.resolve(strict=False)
        scan_dir = (self.harness.store.root / "agent" / "secret-scans").resolve(strict=False)
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out_json = _scoped_artifact_output_path(
            self.harness.store.root,
            "secret-scans",
            str(args.get("out") or "").strip(),
            f"evidence-secret-scan-{stamp}.json",
            suffix=".json",
        )
        out_markdown = out_json.with_suffix(".md")
        if not _is_relative_to(out_markdown.resolve(strict=False), scan_dir):
            raise ValueError("artifact output path escapes the secret-scans artifact directory")

        findings: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        files_with_findings: set[str] = set()
        total_files_seen = 0
        files_scanned = 0
        total_matches = 0
        truncated = False

        for path in sorted(evidence_root.rglob("*")):
            try:
                resolved = path.resolve(strict=False)
                rel = path.relative_to(evidence_root).as_posix()
            except (OSError, RuntimeError, ValueError) as exc:
                skipped.append({"path": redact_secrets(str(path)) or str(path), "reason": f"path could not be safely resolved: {exc}"})
                continue
            if not _is_relative_to(resolved, evidence_root):
                skipped.append({"path": redact_secrets(rel) or rel, "reason": "symlink target outside evidence root"})
                continue
            if _is_relative_to(resolved, scan_dir):
                continue
            if not include_agent and rel.startswith("agent/"):
                continue
            if not resolved.is_file():
                continue
            total_files_seen += 1
            try:
                stat_result = resolved.stat()
            except OSError as exc:
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"stat failed: {exc}"})
                continue
            if stat_result.st_size > max_bytes:
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"larger than max_bytes ({max_bytes})", "bytes": stat_result.st_size})
                continue
            try:
                data = resolved.read_bytes()
            except OSError as exc:
                skipped.append({"path": redact_secrets(rel) or rel, "reason": f"read failed: {exc}"})
                continue
            if _looks_binary_bytes(data):
                skipped.append({"path": redact_secrets(rel) or rel, "reason": "binary-like artifact skipped", "bytes": stat_result.st_size})
                continue
            text = data.decode("utf-8", errors="replace")
            redacted_text = redact_secrets(text) or ""
            if redacted_text == text:
                files_scanned += 1
                continue
            files_scanned += 1
            category = _artifact_category(rel)
            file_matches = 0

            def add_finding(line_no: int | None, match_types: list[str], preview: str) -> None:
                nonlocal total_matches, truncated, file_matches
                total_matches += 1
                file_matches += 1
                files_with_findings.add(rel)
                if len(findings) >= limit:
                    truncated = True
                    return
                findings.append(_redacted_mapping({
                    "path": rel,
                    "category": category,
                    "line": line_no,
                    "match_types": match_types or ["secret_pattern"],
                    "redacted_preview": (preview.strip() or "<REDACTED>")[:500],
                }))

            for line_no, line in enumerate(text.splitlines(), start=1):
                redacted_line = redact_secrets(line) or ""
                if redacted_line == line:
                    continue
                add_finding(line_no, _secret_scan_match_types(line, redacted_line), redacted_line)
            if file_matches == 0 and redacted_text != text:
                first_line = 1
                for idx, line in enumerate(text.splitlines(), start=1):
                    if "private key" in line.lower():
                        first_line = idx
                        break
                add_finding(first_line, ["private_key"], "<REDACTED_PRIVATE_KEY>")

        counts = {
            "files_seen": total_files_seen,
            "files_scanned": files_scanned,
            "files_with_findings": len(files_with_findings),
            "findings_returned": len(findings),
            "total_secret_like_matches": total_matches,
            "skipped": len(skipped),
            "truncated": truncated,
        }
        review_status = "review" if total_matches else "clear"
        payload = _redacted_mapping({
            "created_at": utc_now(),
            "engagement": self.roe.name,
            "session_id": self.session_id,
            "evidence_root": str(evidence_root),
            "review_status": review_status,
            "counts": counts,
            "findings": findings,
            "skipped": skipped[:500],
            "limit": limit,
            "max_bytes": max_bytes,
            "include_agent": include_agent,
            "no_target_activity": True,
            "raw_file_contents_emitted": False,
            "secret_values_redacted": True,
        })
        payload["path"] = str(out_json)
        payload["markdown_path"] = str(out_markdown)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        out_markdown.write_text(_evidence_secret_scan_markdown(self.roe.name, review_status, counts, findings, skipped), encoding="utf-8")
        self.store.audit(self.session_id, "evidence_secret_scan", {"review_status": review_status, "counts": counts, "path": str(out_json)})
        return ToolResult(
            "ok",
            f"Evidence secret scan {review_status}: {total_matches} secret-like match(es) across {len(files_with_findings)} file(s).",
            payload,
            {"json": str(out_json), "markdown": str(out_markdown)},
        )

    def closeout_review(self, args: dict[str, Any]) -> ToolResult:
        """Review whether the local evidence/session state is ready for engagement closeout.

        This is intentionally read-only with respect to targets: it inspects ROE,
        local SQLite state, and local evidence artifact metadata only, then writes
        a redacted Markdown checklist under ``agent/closeout``.
        """

        preflight_checks = _preflight_checks(
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
        preflight_counts = _preflight_counts(preflight_checks)
        pending_approvals = self.store.list_approvals(self.session_id, status="pending")
        tasks = self.store.list_tasks(self.session_id, status="all", limit=500)
        findings = self.store.list_findings(self.session_id, status="all", limit=500)
        processes = self.store.list_processes(self.session_id, limit=500)
        tool_runs = self.store.list_tool_runs(self.session_id, limit=500)
        artifact_inventory = _closeout_artifact_inventory(self.harness.store.root)
        closeout_artifacts = _closeout_artifact_presence(self.harness.store.root)
        checks: list[dict[str, Any]] = []

        def add(
            category: str,
            name: str,
            status: str,
            detail: str,
            recommendation: str = "",
            *,
            related: list[dict[str, Any]] | None = None,
        ) -> None:
            checks.append(_closeout_check(category, name, status, detail, recommendation, related=related))

        preflight_artifact_related = _closeout_artifact_links(closeout_artifacts.get("preflight"), ref_prefix="preflight")
        preflight_review_related = preflight_artifact_related or _closeout_artifact_links(closeout_artifacts.get("preflight"), ref_prefix="preflight", expected_dir="agent/preflight/")
        if preflight_counts.get("fail", 0):
            add(
                "readiness",
                "safety_preflight",
                "fail",
                f"Preflight has {preflight_counts.get('fail', 0)} fail and {preflight_counts.get('warn', 0)} warn check(s).",
                "Run /preflight and resolve fail-level ROE/runtime issues before closeout.",
                related=preflight_review_related,
            )
        elif preflight_counts.get("warn", 0):
            add(
                "readiness",
                "safety_preflight",
                "warn",
                f"Preflight has {preflight_counts.get('warn', 0)} warning(s).",
                "Review /preflight warnings and document accepted limitations before closeout.",
                related=preflight_review_related,
            )
        else:
            add("readiness", "safety_preflight", "pass", "Safety preflight is ready with no fail/warn checks.", related=preflight_artifact_related)

        approval_related = [
            _closeout_entity_link("approval", approval.get("id"), status=approval.get("status") or "pending", title=approval.get("tool_name"))
            for approval in pending_approvals
        ]
        if pending_approvals:
            add(
                "operations",
                "pending_approvals",
                "fail",
                f"{len(pending_approvals)} approval(s) remain pending.",
                "Approve or deny queued state-changing/confirm-level actions before closeout so no ambiguous execution requests remain.",
                related=approval_related,
            )
        else:
            add("operations", "pending_approvals", "pass", "No pending approvals remain.")

        active_processes = [proc for proc in processes if str(proc.get("status") or "") in {"starting", "running"}]
        failed_processes = [proc for proc in processes if str(proc.get("status") or "") == "failed"]
        active_process_related = [
            _closeout_entity_link("process", proc.get("id"), status=proc.get("status"), title=proc.get("purpose"), target=proc.get("target"))
            for proc in active_processes
        ]
        failed_process_related = [
            _closeout_entity_link("process", proc.get("id"), status=proc.get("status"), title=proc.get("purpose"), target=proc.get("target"), exit_code=proc.get("exit_code"))
            for proc in failed_processes
        ]
        if active_processes:
            add(
                "operations",
                "background_processes",
                "fail",
                f"{len(active_processes)} tracked background process(es) are still active.",
                "Wait for, poll, or stop active processes before handing off or exporting closeout evidence.",
                related=active_process_related,
            )
        else:
            add("operations", "background_processes", "pass", f"No active background processes; {len(processes)} process record(s) total.")
        if failed_processes:
            add(
                "operations",
                "failed_processes",
                "warn",
                f"{len(failed_processes)} tracked background process(es) failed.",
                "Review failed process logs and decide whether the failure affects evidence completeness.",
                related=failed_process_related,
            )

        open_tasks = [task for task in tasks if str(task.get("status") or "") not in {"completed", "cancelled"}]
        open_task_related = [
            _closeout_entity_link("task", task.get("id"), status=task.get("status"), title=task.get("content"))
            for task in open_tasks
        ]
        if open_tasks:
            add(
                "workflow",
                "open_tasks",
                "warn",
                f"{len(open_tasks)} task(s) are still pending or in progress.",
                "Complete, cancel, or explicitly carry forward open task-board items in the operator briefing.",
                related=open_task_related,
            )
        else:
            add("workflow", "open_tasks", "pass", "No open task-board items remain.")

        finding_reviews: list[dict[str, Any]] = []
        for finding in findings:
            review = self._build_finding_review(finding)
            score = review.get("score") if isinstance(review.get("score"), dict) else {}
            finding_reviews.append(_redacted_mapping({
                "id": finding.get("id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "status": finding.get("status"),
                "readiness": review.get("readiness"),
                "blocking_gaps": len(review.get("blocking_gaps") or []),
                "advisory_gaps": len(review.get("advisory_gaps") or []),
                "score": score,
            }))
        all_finding_related = [
            _closeout_entity_link("finding", item.get("id"), status=item.get("status"), title=item.get("title"), readiness=item.get("readiness"))
            for item in finding_reviews
        ]
        confirmed_statuses = {"confirmed", "resolved", "accepted-risk"}
        candidate_statuses = {"draft", "needs-evidence"}
        confirmed_with_blocking_gaps = [item for item in finding_reviews if item.get("status") in confirmed_statuses and item.get("readiness") == "needs_evidence"]
        candidate_findings = [item for item in finding_reviews if item.get("status") in candidate_statuses]
        if not findings:
            add(
                "findings",
                "finding_inventory",
                "warn",
                "No findings are recorded in the local DB.",
                "If this was a no-finding engagement, document that explicitly in the operator briefing/report notes.",
                related=_closeout_artifact_links(closeout_artifacts.get("finding_exports"), ref_prefix="artifact", expected_dir="agent/findings/"),
            )
        elif confirmed_with_blocking_gaps:
            related = [
                _closeout_entity_link("finding", item.get("id"), status=item.get("status"), title=item.get("title"), readiness=item.get("readiness"))
                for item in confirmed_with_blocking_gaps
            ]
            add(
                "findings",
                "finding_readiness",
                "fail",
                f"{len(confirmed_with_blocking_gaps)} confirmed/resolved/accepted-risk finding(s) still have blocking evidence gaps.",
                "Run /finding-review on each listed finding and close blocking gaps before client-ready export.",
                related=related,
            )
        elif candidate_findings:
            related = [
                _closeout_entity_link("finding", item.get("id"), status=item.get("status"), title=item.get("title"), readiness=item.get("readiness"))
                for item in candidate_findings
            ]
            add(
                "findings",
                "candidate_findings",
                "warn",
                f"{len(candidate_findings)} draft/needs-evidence finding(s) remain candidate records.",
                "Confirm, resolve, accept risk, or mark false-positive before closeout, or document them as internal-only notes.",
                related=related,
            )
        else:
            add("findings", "finding_readiness", "pass", f"{len(findings)} finding record(s) are in closeout-compatible lifecycle states.", related=all_finding_related)

        if int(artifact_inventory.get("files_seen", 0)) <= 0:
            add(
                "artifacts",
                "evidence_files",
                "warn",
                "No local evidence files were found under the engagement evidence root.",
                "Import or generate evidence artifacts before closeout, or document why the engagement has no local evidence files.",
                related=[_closeout_artifact_link(".", status="missing", title="engagement evidence root")],
            )
        else:
            add("artifacts", "evidence_files", "pass", f"{artifact_inventory.get('files_seen')} local evidence file(s) recorded across {len(artifact_inventory.get('by_category', {}))} category/categories.")
        if int(artifact_inventory.get("skipped", 0)) > 0:
            add(
                "artifacts",
                "skipped_artifacts",
                "warn",
                f"{artifact_inventory.get('skipped')} artifact path(s) were skipped during safe metadata inventory.",
                "Review skipped symlinks/path errors so closeout packaging cannot miss expected evidence.",
                related=[_closeout_artifact_link("agent/", status="review", title="safe inventory skipped path(s)")],
            )

        artifact_expected_dirs = {"manifests": "agent/manifests/", "timelines": "agent/timelines/", "exports": "agent/exports/"}
        for key, label, recommendation in (
            ("manifests", "evidence manifest", "Run /manifest to write a SHA-256 inventory for chain-of-custody review."),
            ("timelines", "evidence timeline", "Run /timeline to write a redacted action/evidence chronology."),
            ("exports", "redacted export pack", "Run /export-pack after final QA to produce a redacted handoff ZIP."),
        ):
            count = int(closeout_artifacts.get(key, {}).get("count", 0)) if isinstance(closeout_artifacts.get(key), dict) else 0
            related = _closeout_artifact_links(closeout_artifacts.get(key), ref_prefix="artifact", expected_dir=artifact_expected_dirs.get(key, "agent/"))
            if count:
                add("artifacts", key, "pass", f"Found {count} {label} artifact(s).", related=related)
            else:
                add("artifacts", key, "warn", f"No {label} artifact found yet.", recommendation, related=related)

        tool_run_related = [
            _closeout_entity_link("tool-run", run.get("id"), status=run.get("status"), title=run.get("tool_name"), target=run.get("target"))
            for run in tool_runs
        ]
        if not tool_runs and findings:
            add(
                "evidence",
                "structured_tool_runs",
                "warn",
                "Findings exist but no structured tool-run records are linked in this session.",
                "Prefer linking scanner/parser evidence or explicit artifact paths so findings are replayable.",
                related=all_finding_related,
            )
        else:
            add("evidence", "structured_tool_runs", "pass", f"{len(tool_runs)} structured tool-run record(s) available.", related=tool_run_related)

        add("limitations", "live_plaintext_db", "info", "Local SQLite/WAL/SHM remain plaintext while the runtime is live; sealed exports/backups are portable protection, not transparent live DB encryption.")
        counts = _preflight_counts(checks)
        readiness = "blocked" if counts.get("fail", 0) else "review" if counts.get("warn", 0) else "ready"
        summary = _redacted_mapping({
            "pending_approvals": len(pending_approvals),
            "open_tasks": len(open_tasks),
            "active_processes": len(active_processes),
            "failed_processes": len(failed_processes),
            "findings": len(findings),
            "candidate_findings": len(candidate_findings),
            "confirmed_findings_with_blocking_gaps": len(confirmed_with_blocking_gaps),
            "tool_runs": len(tool_runs),
            "artifact_inventory": artifact_inventory,
            "closeout_artifacts": closeout_artifacts,
            "drilldown_links": sum(len(check.get("related") or []) for check in checks if check.get("status") in {"fail", "warn"}),
        })
        stamp = utc_now().replace(":", "").replace("+00:00", "Z")
        out = _scoped_artifact_output_path(
            self.harness.store.root,
            "closeout",
            str(args.get("out") or "").strip(),
            f"closeout-review-{stamp}.md",
            suffix=".md",
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        markdown = _closeout_review_markdown(self.roe.name, readiness, checks, counts, summary, finding_reviews)
        out.write_text(markdown, encoding="utf-8")
        payload = _redacted_mapping({
            "readiness": readiness,
            "counts": counts,
            "checks": checks,
            "summary": summary,
            "finding_reviews": finding_reviews,
            "preflight_counts": preflight_counts,
            "path": str(out),
            "no_target_activity": True,
            "secret_values_redacted": True,
            "plaintext_db_caveat": "Local SQLite/WAL/SHM remain plaintext while the runtime is live; use filesystem encryption/SQLCipher or sealed DB backups with runtimes closed for at-rest protection.",
        })
        self.store.audit(self.session_id, "closeout_reviewed", {"readiness": readiness, "counts": counts, "path": str(out)})
        return ToolResult("ok", f"Closeout review {readiness}: {counts.get('fail', 0)} fail, {counts.get('warn', 0)} warn, {counts.get('pass', 0)} pass.", payload, {"markdown": str(out)})

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
            "jobs": [_redacted_mapping(asdict(job)) for job in self.store.list_jobs(self.session_id)],
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
        jobs = [_redacted_mapping(asdict(job)) for job in self.store.list_jobs(self.session_id)]
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
            "jobs": [_redacted_mapping(asdict(job)) for job in self.store.list_jobs(self.session_id)],
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
        return ToolResult("ok", f"Found {len(rows)} task(s).", {"tasks": [_redacted_mapping(row) for row in rows], "secret_values_redacted": True})

    def get_task(self, args: dict[str, Any]) -> ToolResult:
        task_id = _first_int_arg(args, "id", "task_id")
        if task_id is None:
            return ToolResult("error", "task id is required.")
        task = self.store.get_task(task_id, session_id=self.session_id)
        if not task:
            return ToolResult("error", f"Task {task_id} not found in this session.")
        return ToolResult("ok", f"Task {task_id} returned.", {"task": _redacted_mapping(task), "secret_values_redacted": True})

    def add_task(self, args: dict[str, Any]) -> ToolResult:
        content = str(args.get("content") or args.get("task") or "").strip()
        if not content:
            return ToolResult("error", "content is required.")
        status = _normalize_task_status(str(args.get("status", "pending")))
        task_id = self.store.create_task(self.session_id, content, status=status)
        return ToolResult("ok", f"Task {task_id} added.", {"task": _redacted_mapping(self.store.get_task(task_id, session_id=self.session_id) or {}), "secret_values_redacted": True})

    def update_task(self, args: dict[str, Any]) -> ToolResult:
        task_id = _first_int_arg(args, "id", "task_id")
        if task_id is None:
            return ToolResult("error", "task id is required.")
        content = args.get("content")
        status = args.get("status")
        normalized = _normalize_task_status(str(status)) if status is not None else None
        task = self.store.update_task(task_id, session_id=self.session_id, content=str(content) if content is not None else None, status=normalized)
        if not task:
            return ToolResult("error", f"Task {task_id} not found in this session.")
        return ToolResult("ok", f"Task {task_id} updated.", {"task": _redacted_mapping(task), "secret_values_redacted": True})

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
        process = self.store.get_process(process_id, session_id=self.session_id)
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
                self.store.update_process(process_id, session_id=self.session_id, status=status, exit_code=exit_code, ended_at=process.get("ended_at") or utc_now())
        elif process.get("pid") and _pid_running(int(process["pid"])):
            status = "running"
            if process.get("status") != "running":
                self.store.update_process(process_id, session_id=self.session_id, status="running")
        elif process.get("status") in {"running", "starting"}:
            status = "unknown"
            self.store.update_process(process_id, session_id=self.session_id, status="unknown", ended_at=process.get("ended_at") or utc_now())
        return self.store.get_process(process_id, session_id=self.session_id)


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


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_int_arg(args: dict[str, Any], *names: str) -> int | None:
    for name in names:
        parsed = _coerce_int(args.get(name))
        if parsed is not None:
            return parsed
    return None


_LOCAL_REF_KIND_ALIASES = {
    "approvals": "approval",
    "tasks": "task",
    "processes": "process",
    "findings": "finding",
    "tool_run": "tool-run",
    "toolrun": "tool-run",
    "tool-runs": "tool-run",
    "toolruns": "tool-run",
    "run": "tool-run",
    "runs": "tool-run",
    "audits": "audit",
    "audit-log": "audit",
    "audit_event": "audit",
    "audit-event": "audit",
    "jobs": "job",
    "delegations": "delegation",
    "media-artifact": "media",
    "media_detail": "media",
    "media-detail": "media",
    "memory-entry": "memory",
    "memories": "memory",
    "context": "context-node",
    "context_node": "context-node",
    "context-node": "context-node",
    "lcm": "context-node",
    "node": "context-node",
    "evidence": "artifact",
    "artifact-path": "artifact",
    "exports": "export",
    "timelines": "timeline",
    "manifests": "manifest",
    "closeouts": "closeout",
    "briefings": "briefing",
}


def _parse_local_ref(args: dict[str, Any]) -> tuple[str, str, str] | None:
    raw_ref = str(args.get("ref") or args.get("local_ref") or args.get("query") or "").strip()
    if not raw_ref and isinstance(args.get("_positional"), list) and args.get("_positional"):
        raw_ref = str(args.get("_positional", [""])[0]).strip()
    if raw_ref:
        if ":" not in raw_ref:
            return None
        raw_kind, raw_value = raw_ref.split(":", 1)
    else:
        raw_kind = str(args.get("kind") or args.get("type") or "").strip()
        if args.get("id") not in (None, ""):
            raw_value = str(args.get("id"))
        elif args.get("path") not in (None, ""):
            raw_value = str(args.get("path"))
        else:
            raw_value = ""
    kind = raw_kind.strip().lower().replace("_", "-")
    kind = _LOCAL_REF_KIND_ALIASES.get(kind, kind)
    value = str(raw_value or "").strip()
    if not kind or not value:
        return None
    display_ref = redact_secrets(f"{kind}:{value}") or f"{kind}:{value}"
    return kind, value, display_ref


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
        parsed = _coerce_int(part.strip())
        if parsed is not None:
            out.append(parsed)
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


def _finding_report_input(finding: dict[str, Any]) -> FindingInput:
    raw_evidence = finding.get("evidence")
    evidence: list[dict[str, Any]] = [item for item in raw_evidence if isinstance(item, dict)] if isinstance(raw_evidence, list) else []
    evidence_lines = _finding_evidence_lines(evidence)
    affected_assets = sorted({str(item.get("target")) for item in evidence if item.get("target")})
    status = str(finding.get("status") or "draft")
    return FindingInput(
        title=str(finding.get("title") or "Untitled Finding"),
        severity=str(finding.get("severity") or "Informational"),
        impact=str(finding.get("impact") or "Impact should be finalized during QA based on confirmed evidence."),
        description=str(finding.get("description") or ""),
        supporting_evidence=evidence_lines,
        affected_assets=affected_assets,
        recommendation=str(finding.get("recommendation") or ""),
        confirmed=status in {"confirmed", "accepted-risk", "resolved"},
        limitations=[] if status == "confirmed" else [f"Current lifecycle status is {status}; validate evidence before client delivery."],
    )


def _finding_bundle_readme(engagement_name: str, finding_id: Any, finding_title: str) -> str:
    return f"""# Phobos Finding Evidence Bundle

Engagement: {redact_secrets(str(engagement_name))}
Finding: #{finding_id} {redact_secrets(str(finding_title))}

This ZIP was generated locally from Phobos session state for operator QA and handoff.
No target activity was performed while creating it. Generated finding/review files and
linked text evidence are redacted before packaging; binary, oversized, missing, and
out-of-evidence-root artifacts are omitted and listed in `MANIFEST.json`.

Contents:

- `finding/finding.md` — report-style finding draft.
- `finding/review.md` — deterministic readiness/QA checklist.
- `finding/finding.json` — redacted finding and review metadata.
- `evidence/` — redacted linked text evidence artifacts when safe to include.
- `MANIFEST.json` — metadata, redacted paths, byte counts, and SHA-256 hashes of packaged content.
"""


def _zip_manifest_entry(archive_path: str, source: str, text: str) -> dict[str, Any]:
    redacted = redact_secrets(text) or ""
    encoded = redacted.encode("utf-8")
    return _redacted_mapping({
        "archive_path": archive_path,
        "source": source,
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    })


def _zip_redacted_evidence_artifact(
    archive: zipfile.ZipFile,
    evidence_root: Path,
    path_value: str,
    source: str,
    *,
    max_bytes: int,
    seen_resolved: set[Path],
    skip_path: Path | None = None,
) -> dict[str, Any]:
    text_suffixes = {".json", ".jsonl", ".md", ".txt", ".log", ".http", ".csv", ".yaml", ".yml"}
    display_source = redact_secrets(source) or source
    display_path = redact_secrets(path_value) or path_value
    try:
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = evidence_root / candidate
        resolved = candidate.resolve(strict=False)
        if not _is_relative_to(resolved, evidence_root):
            return {"source": display_source, "path": display_path, "reason": "artifact path resolves outside evidence root"}
        if skip_path is not None and resolved == skip_path.resolve(strict=False):
            return {"source": display_source, "path": display_path, "reason": "output bundle skipped"}
        if not resolved.exists():
            return {"source": display_source, "path": display_path, "reason": "artifact missing"}
        if not resolved.is_file():
            return {"source": display_source, "path": display_path, "reason": "artifact is not a regular file"}
        if resolved in seen_resolved:
            return {"source": display_source, "path": display_path, "reason": "duplicate artifact"}
        size = resolved.stat().st_size
        if size > max_bytes:
            return {"source": display_source, "path": display_path, "bytes": size, "reason": f"larger than max_bytes={max_bytes}"}
        if resolved.suffix.lower() not in text_suffixes:
            return {"source": display_source, "path": display_path, "bytes": size, "reason": "non-text artifact omitted from redacted finding bundle"}
        raw = resolved.read_text(encoding="utf-8", errors="replace")
        redacted = redact_secrets(raw) or ""
        rel = resolved.relative_to(evidence_root).as_posix()
        arcname = f"evidence/{rel}"
        archive.writestr(arcname, redacted)
        seen_resolved.add(resolved)
        encoded = redacted.encode("utf-8")
        return _redacted_mapping({
            "archive_path": arcname,
            "source": display_source,
            "source_path": rel,
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })
    except (OSError, RuntimeError, ValueError) as exc:
        return {"source": display_source, "path": display_path, "reason": f"artifact could not be safely packaged: {exc}"}


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


def _closeout_check(
    category: str,
    name: str,
    status: str,
    detail: str,
    recommendation: str = "",
    *,
    related: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    normalized = status.strip().lower().replace("warning", "warn")
    if normalized not in {"pass", "warn", "fail", "info"}:
        normalized = "info"
    payload: dict[str, Any] = {
        "category": category,
        "name": name,
        "status": normalized,
        "detail": detail,
        "recommendation": recommendation,
    }
    links = _closeout_related(related or [])
    if links:
        payload["related"] = links
    return _redacted_mapping(payload)


def _closeout_entity_link(
    kind: str,
    ident: Any,
    *,
    status: Any = "",
    title: Any = "",
    target: Any = "",
    readiness: Any = "",
    exit_code: Any = None,
    note: Any = "",
) -> dict[str, Any]:
    raw_id = str(ident or "").strip()
    if not raw_id:
        return {}
    payload: dict[str, Any] = {"ref": f"{kind}:{raw_id}"}
    for key, value in {
        "status": status,
        "title": title,
        "target": target,
        "readiness": readiness,
        "exit_code": exit_code,
        "note": note,
    }.items():
        if value is None or value == "":
            continue
        payload[key] = value
    return _redacted_mapping(payload)


def _closeout_artifact_link(path_value: Any, *, ref_prefix: str = "artifact", status: Any = "", title: Any = "") -> dict[str, Any]:
    clean = str(path_value or "").strip().replace("\\", "/")
    if not clean:
        return {}
    candidate = Path(clean)
    if candidate.is_absolute() or ".." in candidate.parts:
        clean = candidate.name or "artifact"
    clean = clean.lstrip("/") or "."
    payload: dict[str, Any] = {"ref": f"{ref_prefix}:{clean}", "path": clean}
    if status:
        payload["status"] = status
    if title:
        payload["title"] = title
    return _redacted_mapping(payload)


def _closeout_artifact_links(
    presence: Any,
    *,
    ref_prefix: str = "artifact",
    expected_dir: str = "",
    limit: int = 5,
) -> list[dict[str, Any]]:
    paths: list[Any] = []
    if isinstance(presence, dict) and isinstance(presence.get("paths"), list):
        paths = presence.get("paths", [])
    links = [_closeout_artifact_link(path, ref_prefix=ref_prefix, status="present") for path in paths[:limit]]
    links = [link for link in links if link]
    if links:
        return links
    if expected_dir:
        link = _closeout_artifact_link(expected_dir, ref_prefix=ref_prefix, status="missing", title="expected artifact directory")
        return [link] if link else []
    return []


def _closeout_related(items: list[dict[str, Any]] | None, *, limit: int = 12) -> list[dict[str, Any]]:
    allowed = {"ref", "status", "title", "tool", "target", "readiness", "path", "exit_code", "note"}
    related: list[dict[str, Any]] = []
    for item in items or []:
        if not item:
            continue
        if isinstance(item, str):
            payload: dict[str, Any] = {"ref": item}
        elif isinstance(item, dict):
            payload = {key: value for key, value in item.items() if key in allowed and value not in (None, "")}
        else:
            continue
        ref = str(payload.get("ref") or "").strip()
        if not ref:
            continue
        payload["ref"] = ref[:240]
        for key in ("title", "target", "path", "note"):
            if key in payload:
                payload[key] = str(payload[key])[:240]
        related.append(_redacted_mapping(payload))
        if len(related) >= limit:
            break
    return related


def _closeout_related_refs(items: Any) -> str:
    if not isinstance(items, list):
        return ""
    labels: list[str] = []
    for item in _closeout_related(items):
        ref = str(item.get("ref") or "").strip()
        if not ref:
            continue
        details = [str(item.get(key)) for key in ("status", "readiness", "title", "target") if item.get(key) not in (None, "")]
        labels.append(f"{ref} ({', '.join(details[:3])})" if details else ref)
    return "; ".join(labels[:12])


def _closeout_artifact_inventory(evidence_root: Path) -> dict[str, Any]:
    root = evidence_root.resolve(strict=False)
    files_seen = 0
    bytes_seen = 0
    skipped = 0
    by_category: dict[str, int] = {}
    for path in sorted(root.rglob("*")):
        try:
            resolved = path.resolve(strict=False)
            rel = path.relative_to(root).as_posix()
        except (OSError, RuntimeError, ValueError):
            skipped += 1
            continue
        if not _is_relative_to(resolved, root):
            skipped += 1
            continue
        if not resolved.is_file():
            continue
        try:
            stat_result = resolved.stat()
        except OSError:
            skipped += 1
            continue
        category = _artifact_category(rel)
        by_category[category] = by_category.get(category, 0) + 1
        files_seen += 1
        bytes_seen += stat_result.st_size
    return _redacted_mapping({"files_seen": files_seen, "bytes_seen": bytes_seen, "skipped": skipped, "by_category": dict(sorted(by_category.items()))})


def _closeout_artifact_presence(evidence_root: Path) -> dict[str, Any]:
    root = evidence_root.resolve(strict=False)
    specs = {
        "preflight": ("preflight", ("*.md",)),
        "manifests": ("manifests", ("*.json",)),
        "timelines": ("timelines", ("*.md",)),
        "secret_scans": ("secret-scans", ("*.json", "*.md")),
        "exports": ("exports", ("*.zip",)),
        "briefings": ("briefings", ("*.md",)),
        "finding_exports": ("findings", ("*.md",)),
    }
    presence: dict[str, Any] = {}
    for key, (subdir, patterns) in specs.items():
        base = (evidence_root / "agent" / subdir).resolve(strict=False)
        paths: list[str] = []
        if _is_relative_to(base, root) and base.exists():
            for pattern in patterns:
                for candidate in sorted(base.glob(pattern)):
                    try:
                        resolved = candidate.resolve(strict=False)
                    except (OSError, RuntimeError):
                        continue
                    if not _is_relative_to(resolved, root) or not resolved.is_file():
                        continue
                    try:
                        paths.append(candidate.relative_to(root).as_posix())
                    except ValueError:
                        paths.append(str(candidate))
        presence[key] = {"count": len(paths), "paths": [redact_secrets(path) for path in paths[:10]]}
    return _redacted_mapping(presence)


def _closeout_review_markdown(
    engagement_name: str,
    readiness: str,
    checks: list[dict[str, Any]],
    counts: dict[str, int],
    summary: dict[str, Any],
    finding_reviews: list[dict[str, Any]],
) -> str:
    lines = [
        "# Phobos Closeout Review",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Readiness: `{redact_secrets(readiness)}`",
        f"No target activity: `true`",
        "",
        "## Summary",
        "",
        "```json",
        json.dumps(_redacted_mapping(summary), indent=2, sort_keys=True),
        "```",
        "",
        "## Check counts",
        "",
        "| Status | Count |",
        "|---|---|",
    ]
    for key in ("fail", "warn", "pass", "info"):
        lines.append(f"| {key} | {int(counts.get(key, 0))} |")
    lines += ["", "## Closeout checks", "", "| Category | Check | Status | Detail | Recommendation | Related |", "|---|---|---|---|---|---|"]
    for check in checks:
        lines.append("| " + " | ".join(_md_cell(value) for value in [check.get("category"), check.get("name"), check.get("status"), check.get("detail"), check.get("recommendation"), _closeout_related_refs(check.get("related"))]) + " |")
    lines += ["", "## Finding readiness", "", "| ID | Severity | Status | Readiness | Blocking gaps | Advisory gaps | Title |", "|---|---|---|---|---|---|---|"]
    if finding_reviews:
        for item in finding_reviews:
            lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("id"), item.get("severity"), item.get("status"), item.get("readiness"), item.get("blocking_gaps"), item.get("advisory_gaps"), item.get("title")]) + " |")
    else:
        lines.append("| | | | | | | No findings recorded. |")
    drilldown_checks = [check for check in checks if check.get("status") in {"fail", "warn"} and check.get("related")]
    lines += ["", "## Drill-down", ""]
    if drilldown_checks:
        for check in drilldown_checks[:12]:
            refs = _closeout_related_refs(check.get("related"))
            lines.append(f"- `{_md_cell(check.get('name'))}` ({_md_cell(check.get('status'))}): {redact_secrets(refs)}")
    else:
        lines.append("- No local drill-down links for fail/warn checks.")
    recommendations = [check.get("recommendation") for check in checks if check.get("status") in {"fail", "warn"} and check.get("recommendation")]
    lines += ["", "## Next actions", ""]
    if recommendations:
        for item in recommendations[:12]:
            lines.append(f"- {redact_secrets(str(item))}")
    else:
        lines.append("- No blocking closeout gaps identified; perform final operator/client wording review before delivery.")
    lines += [
        "",
        "## Caveat",
        "",
        "- Local SQLite/WAL/SHM remain plaintext while the runtime is live. Sealed snapshots/backups are portable protection, not transparent live DB encryption.",
    ]
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


def _guardrail_selftest_markdown(
    engagement_name: str,
    readiness: str,
    cases: list[dict[str, Any]],
    counts: dict[str, int],
    selected_target: str,
) -> str:
    lines = [
        "# Phobos Guardrail Self-Test",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Readiness: `{_md_cell(readiness)}`",
        f"Synthetic in-scope target: `{_md_cell(selected_target)}`",
        "No target activity was performed. This report simulates representative guardrail decisions only; no command was executed and no network request was sent.",
        "",
        "## Summary",
        "",
        f"- Pass: {counts.get('pass', 0)}",
        f"- Fail: {counts.get('fail', 0)}",
        "",
        "## Simulated cases",
        "",
        "| Case | Expected | Actual | Status | Target | Redacted command | Reasons |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        reasons = "; ".join(str(item) for item in case.get("reasons", []) if str(item))
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in [
                    case.get("name"),
                    case.get("expected"),
                    case.get("actual"),
                    case.get("status"),
                    case.get("target"),
                    case.get("redacted_command"),
                    reasons,
                ]
            )
            + " |"
        )
    lines += ["", "## Safety notes", ""]
    for case in cases:
        raw_alternatives = case.get("safer_alternatives")
        raw_required = case.get("required_confirmations")
        alternatives = raw_alternatives if isinstance(raw_alternatives, list) else []
        required = raw_required if isinstance(raw_required, list) else []
        notes = "; ".join(str(item) for item in [*required, *alternatives] if str(item))
        if notes:
            lines.append(f"- **{_md_cell(case.get('name'))}:** {_md_cell(notes)}")
    if all(not case.get("safer_alternatives") and not case.get("required_confirmations") for case in cases):
        lines.append("- No confirmation requirements or safer alternatives were emitted by the simulated decisions.")
    return redact_secrets("\n".join(lines) + "\n") or ""


def _first_selftest_scope_target(scope_rules: list[str]) -> str:
    for rule in scope_rules:
        value = str(rule).strip()
        if value and not _looks_broad_scope_target(value):
            return value
    for rule in scope_rules:
        value = str(rule).strip()
        if value:
            return value
    return "phobos-selftest.invalid"


def _selftest_out_of_scope_target(scope_rules: list[str]) -> str:
    candidates = [
        "phobos-selftest-outside.invalid",
        "outside.phobos-selftest.invalid",
        "203.0.113.254",
        "198.51.100.254",
        "[2001:db8:ffff::1]",
    ]
    for candidate in candidates:
        if not target_in_scope(candidate, scope_rules).in_scope:
            return candidate
    return candidates[0]


def _selftest_command_target(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return "phobos-selftest.invalid"
    parsed_host = ""
    parsed_port: int | None = None
    try:
        if "://" in text or text.startswith("//"):
            parsed = urlsplit(text)
            parsed_host = parsed.hostname or ""
            parsed_port = parsed.port
    except ValueError:
        parsed_host = ""
    if parsed_host:
        host = parsed_host.strip("[]").lower()
        if ":" in host:
            host = f"[{host}]"
        return f"{host}:{parsed_port}" if parsed_port else host
    stripped = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in stripped:
        stripped = stripped.rsplit("@", 1)[1]
    stripped = stripped.strip().strip("[]")
    if stripped.startswith("*."):
        stripped = "wildcard." + stripped[2:]
    stripped = stripped.replace("*", "wildcard")
    safe = re.sub(r"[^A-Za-z0-9_.:\[\]-]", "-", stripped).strip(".-")
    return safe or "phobos-selftest.invalid"



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


def _evidence_manifest_markdown(engagement_name: str, entries: list[dict[str, Any]], skipped: list[dict[str, Any]], counts: dict[str, Any]) -> str:
    lines = [
        "# Phobos Evidence Manifest",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        "No target activity was performed. This report records artifact metadata and SHA-256 hashes only; it does not include file contents.",
        "",
        "## Summary",
        "",
        f"- Files hashed: {counts.get('files_hashed', 0)}",
        f"- Files seen: {counts.get('files_seen', 0)}",
        f"- Bytes hashed: {counts.get('bytes_hashed', 0)}",
        f"- Skipped: {counts.get('skipped', 0)}",
        f"- Truncated by limit: {counts.get('truncated', False)}",
        "",
        "## Category counts",
        "",
        "| Category | Files |",
        "|---|---|",
    ]
    by_category = counts.get("by_category") if isinstance(counts.get("by_category"), dict) else {}
    if by_category:
        for category, count in sorted(by_category.items()):
            lines.append(f"| {_md_cell(category)} | {_md_cell(count)} |")
    else:
        lines.append("| none | 0 |")
    lines += [
        "",
        "## Hashed artifacts",
        "",
        "| Path | Category | Bytes | SHA-256 | Modified | MIME |",
        "|---|---|---|---|---|---|",
    ]
    if not entries:
        lines.append("| | | | No files hashed. | | |")
    for entry in entries:
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in [
                    entry.get("path", ""),
                    entry.get("category", ""),
                    entry.get("bytes", ""),
                    entry.get("sha256", ""),
                    entry.get("modified_at", ""),
                    entry.get("mime_type", ""),
                ]
            )
            + " |"
        )
    lines += ["", "## Skipped artifacts", "", "| Path | Reason |", "|---|---|"]
    if not skipped:
        lines.append("| | None |")
    for item in skipped[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("reason", "")]) + " |")
    if len(skipped) > 200:
        lines.append(f"| ... | {len(skipped) - 200} additional skipped artifact(s) omitted from Markdown. |")
    return redact_secrets("\n".join(lines) + "\n") or ""


def _resolve_manifest_input_path(evidence_root: Path, path_arg: str) -> Path | None:
    manifest_dir = (evidence_root / "agent" / "manifests").resolve(strict=False)
    if path_arg:
        candidate = Path(path_arg).expanduser()
        if not candidate.is_absolute():
            candidate = manifest_dir / path_arg
        resolved = candidate.resolve(strict=False)
        if not _is_relative_to(resolved, evidence_root):
            raise ValueError("manifest path escapes the evidence root")
        if not _is_relative_to(resolved, manifest_dir):
            raise ValueError("manifest path must be under agent/manifests")
        if not resolved.exists() or not resolved.is_file():
            raise ValueError("manifest path was not found under agent/manifests")
        return resolved
    candidates: list[Path] = []
    try:
        for candidate in manifest_dir.glob("*.json"):
            resolved = candidate.resolve(strict=False)
            if not _is_relative_to(resolved, manifest_dir):
                continue
            if not resolved.is_file():
                continue
            if "verification" in resolved.name:
                continue
            candidates.append(resolved)
    except OSError:
        return None
    candidates.sort(key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True)
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
            return candidate
    return None


def _looks_binary_bytes(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    control = sum(1 for byte in sample if byte < 32 and byte not in {9, 10, 12, 13})
    return control / max(1, len(sample)) > 0.30


def _secret_scan_match_types(original: str, redacted: str) -> list[str]:
    lower = original.lower()
    types: list[str] = []
    if "private key" in lower or "<redacted_private_key>" in redacted.lower():
        types.append("private_key")
    if "authorization" in lower:
        types.append("authorization")
    if "cookie" in lower or "set-cookie" in lower:
        types.append("cookie")
    labels = [
        ("password", ("password", "passwd", "pwd")),
        ("api_key", ("api_key", "api-key", "x-api-key")),
        ("token", ("token", "session_token", "id_token", "access_token", "refresh_token")),
        ("secret", ("secret", "client_secret", "aws_secret_access_key")),
        ("proxy_authorization", ("proxy_authorization", "proxy-authorization")),
    ]
    for label, needles in labels:
        if any(needle in lower for needle in needles):
            types.append(label)
    if redacted != original and not types:
        types.append("secret_pattern")
    return sorted(set(types))


def _evidence_secret_scan_markdown(
    engagement_name: str,
    review_status: str,
    counts: dict[str, Any],
    findings: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
) -> str:
    lines = [
        "# Phobos Evidence Secret Scan",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Review status: `{_md_cell(review_status)}`",
        "No target activity was performed. This report scans local evidence-root text artifacts and emits metadata plus redacted previews only; raw file contents and raw secret values are not emitted.",
        "",
        "## Summary",
        "",
        f"- Files seen: {counts.get('files_seen', 0)}",
        f"- Files scanned: {counts.get('files_scanned', 0)}",
        f"- Files with findings: {counts.get('files_with_findings', 0)}",
        f"- Secret-like matches: {counts.get('total_secret_like_matches', 0)}",
        f"- Findings returned: {counts.get('findings_returned', 0)}",
        f"- Skipped: {counts.get('skipped', 0)}",
        f"- Truncated by limit: {counts.get('truncated', False)}",
        "",
        "## Secret-like findings",
        "",
        "| Path | Category | Line | Match types | Redacted preview |",
        "|---|---|---|---|---|",
    ]
    if not findings:
        lines.append("| | | | | No secret-like material detected by configured patterns. |")
    for item in findings[:500]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("category", ""), item.get("line", ""), ", ".join(str(kind) for kind in item.get("match_types", [])), item.get("redacted_preview", "")]) + " |")
    if len(findings) > 500:
        lines.append(f"| ... | | | | {len(findings) - 500} additional finding row(s) omitted from Markdown. |")
    lines += ["", "## Skipped artifacts", "", "| Path | Reason |", "|---|---|"]
    if not skipped:
        lines.append("| | None |")
    for item in skipped[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("reason", "")]) + " |")
    if len(skipped) > 200:
        lines.append(f"| ... | {len(skipped) - 200} additional skipped artifact(s) omitted from Markdown. |")
    return redact_secrets("\n".join(lines) + "\n") or ""


def _evidence_manifest_verification_markdown(
    engagement_name: str,
    source_manifest: str,
    verification_status: str,
    counts: dict[str, Any],
    changed: list[dict[str, Any]],
    missing: list[dict[str, Any]],
    unsafe: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    duplicate_paths: list[dict[str, Any]],
    invalid_entries: list[dict[str, Any]],
) -> str:
    lines = [
        "# Phobos Evidence Manifest Verification",
        "",
        f"Generated: {utc_now()}",
        f"Engagement: {redact_secrets(engagement_name)}",
        f"Source manifest: `{_md_cell(source_manifest)}`",
        f"Verification status: `{_md_cell(verification_status)}`",
        "No target activity was performed. This report re-hashes local evidence-root artifacts and records metadata only; it does not include file contents.",
        "",
        "## Summary",
        "",
        f"- Expected artifacts: {counts.get('expected', 0)}",
        f"- Verified unchanged: {counts.get('verified', 0)}",
        f"- Changed: {counts.get('changed', 0)}",
        f"- Missing: {counts.get('missing', 0)}",
        f"- Unsafe path entries: {counts.get('unsafe', 0)}",
        f"- New artifacts: {counts.get('new', 0)}",
        f"- Skipped: {counts.get('skipped', 0)}",
        f"- Duplicate manifest paths: {counts.get('duplicate_paths', 0)}",
        f"- Invalid manifest entries: {counts.get('invalid_entries', 0)}",
        f"- New artifact list truncated: {counts.get('new_truncated', False)}",
        "",
        "## Changed artifacts",
        "",
        "| Path | Reasons | Expected SHA-256 | Actual SHA-256 | Expected bytes | Actual bytes |",
        "|---|---|---|---|---|---|",
    ]
    if not changed:
        lines.append("| | None | | | | |")
    for item in changed[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), "; ".join(str(reason) for reason in item.get("reasons", [])), item.get("expected_sha256", ""), item.get("actual_sha256", ""), item.get("expected_bytes", ""), item.get("actual_bytes", "")]) + " |")
    if len(changed) > 200:
        lines.append(f"| ... | {len(changed) - 200} additional changed artifact(s) omitted from Markdown. | | | | |")
    lines += ["", "## Missing artifacts", "", "| Path | Reason | Expected SHA-256 | Expected bytes |", "|---|---|---|---|"]
    if not missing:
        lines.append("| | None | | |")
    for item in missing[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("reason", ""), item.get("expected_sha256", ""), item.get("expected_bytes", "")]) + " |")
    if len(missing) > 200:
        lines.append(f"| ... | {len(missing) - 200} additional missing artifact(s) omitted from Markdown. | | |")
    lines += ["", "## Unsafe manifest entries", "", "| Path | Reason |", "|---|---|"]
    if not unsafe:
        lines.append("| | None |")
    for item in unsafe[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("reason", "")]) + " |")
    if len(unsafe) > 200:
        lines.append(f"| ... | {len(unsafe) - 200} additional unsafe entry/entries omitted from Markdown. |")
    lines += ["", "## New artifacts", "", "| Path | Category | Bytes | SHA-256 | Modified | MIME |", "|---|---|---|---|---|---|"]
    if not new_entries:
        lines.append("| | None | | | | |")
    for item in new_entries[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", ""), item.get("category", ""), item.get("bytes", ""), item.get("sha256", ""), item.get("modified_at", ""), item.get("mime_type", "")]) + " |")
    if len(new_entries) > 200:
        lines.append(f"| ... | {len(new_entries) - 200} additional new artifact(s) omitted from Markdown. | | | | |")
    lines += ["", "## Skipped and manifest-quality notes", "", "| Path / Index | Reason |", "|---|---|"]
    notes = skipped + duplicate_paths + invalid_entries
    if not notes:
        lines.append("| | None |")
    for item in notes[:200]:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("path", item.get("index", "")), item.get("reason", "")]) + " |")
    if len(notes) > 200:
        lines.append(f"| ... | {len(notes) - 200} additional note(s) omitted from Markdown. |")
    return redact_secrets("\n".join(lines) + "\n") or ""


def _artifact_category(relative_path: str) -> str:
    rel = relative_path.replace("\\", "/").lstrip("/")
    if rel in {"decisions.jsonl", "command-log.md", "evidence-matrix.md"}:
        return "guardrail"
    prefixes = [
        ("plans/", "plan"),
        ("burp/", "burp"),
        ("ad/", "ad"),
        ("cve/", "cve"),
        ("reports/", "finding"),
        ("agent/findings/", "finding"),
        ("agent/tool-runs/", "tool_run"),
        ("agent/processes/", "process"),
        ("agent/context-nodes/", "context"),
        ("agent/delegations/", "delegation"),
        ("agent/preflight/", "preflight"),
        ("agent/guardrails/", "guardrail"),
        ("agent/media/", "media"),
        ("agent/timelines/", "timeline"),
        ("agent/briefings/", "briefing"),
        ("agent/session-exports/", "handoff"),
        ("agent/sealed/", "sealed"),
        ("agent/manifests/", "manifest"),
        ("agent/secret-scans/", "secret_scan"),
        ("agent/exports/", "export"),
        ("agent/workspace/", "workspace"),
    ]
    for prefix, category in prefixes:
        if rel.startswith(prefix):
            return category
    return "evidence"


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


def _contains_redacted_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_redacted_marker(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_redacted_marker(item) for item in value)
    if isinstance(value, str):
        return "<REDACTED>" in value
    return False


def _parse_schema_bool(value: Any) -> tuple[bool, bool]:
    """Return (parsed, ok) for schema-declared boolean values.

    JSON booleans are accepted directly. Common operator strings and 0/1 values
    are normalized so slash/gateway callers can pass form-style payloads without
    Python's non-empty-string truthiness accidentally enabling execution.
    """

    if isinstance(value, bool):
        return value, True
    if isinstance(value, int) and value in {0, 1}:
        return bool(value), True
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True, True
    if text in {"0", "false", "no", "n", "off"}:
        return False, True
    return False, False


def _parse_schema_number(value: Any) -> tuple[float, bool]:
    """Parse a JSON-schema number while rejecting booleans, blanks, NaN, and inf."""

    if value is None or isinstance(value, bool):
        return 0.0, False
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0, False
        try:
            parsed = float(text)
        except ValueError:
            return 0.0, False
    else:
        return 0.0, False
    if not math.isfinite(parsed):
        return 0.0, False
    return parsed, True


def _blank_required_value_is_missing(arg_schema: Any) -> bool:
    """Treat blank required values as missing unless an empty string is intentional."""

    if not isinstance(arg_schema, dict):
        return True
    if arg_schema.get("x-allow-blank-required", False):
        return False
    arg_type = arg_schema.get("type")
    if isinstance(arg_schema.get("enum"), list):
        return True
    return arg_type in {"integer", "number", "boolean", "array", "object"}


def _schema_enum_key(value: Any) -> str:
    return str(value).strip().lower().replace("_", "-")


def _parse_schema_enum(value: Any, enum_values: list[Any], aliases: Any = None) -> tuple[Any, bool]:
    """Return (canonical_value, ok) for schema-declared enum strings."""

    if value is None or isinstance(value, bool):
        return value, False
    key = _schema_enum_key(value)
    alias_map = aliases if isinstance(aliases, dict) else {}
    for alias, canonical in alias_map.items():
        if _schema_enum_key(alias) == key:
            return canonical, True
    for candidate in enum_values:
        if _schema_enum_key(candidate) == key:
            return candidate, True
    return value, False


def _schema_enum_error_values(enum_values: list[Any]) -> str:
    return ", ".join(str(item) for item in enum_values)


def _schema_size_bound(value: Any) -> int | None:
    """Return a non-negative integer JSON-schema size bound, or None.

    Schema metadata is trusted code/plugin configuration rather than operator
    input, so invalid bound shapes are ignored here instead of producing runtime
    errors for otherwise valid tool calls.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _schema_unexpected_args(args: dict[str, Any], properties: dict[str, Any]) -> list[str]:
    """Return non-internal args not declared by a closed object schema."""

    expected = {str(key) for key in properties}
    unexpected: list[str] = []
    for key in args:
        key_text = str(key)
        if key_text.startswith("_"):
            continue
        if key_text not in expected:
            unexpected.append(key_text)
    return sorted(unexpected)


def _schema_unexpected_args_message(unexpected: list[str]) -> str:
    if len(unexpected) == 1:
        return f"{unexpected[0]} is not an allowed argument."
    preview = ", ".join(unexpected[:5])
    if len(unexpected) > 5:
        preview += ", ..."
    return f"Unexpected arguments: {preview}."


def _format_schema_count(noun: str, count: int) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _format_schema_bound(value: int | float) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _truthy_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    parsed, ok = _parse_schema_bool(value)
    if ok:
        return parsed
    return default


def _integer(description: str, *, minimum: int | None = None, maximum: int | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "integer", "description": description}
    if minimum is not None:
        schema["minimum"] = minimum
    if maximum is not None:
        schema["maximum"] = maximum
    return schema


def _string(description: str, *, allow_non_string: bool = False) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "description": description}
    if allow_non_string:
        schema["x-allow-non-string"] = True
    return schema


def _string_enum(description: str, values: tuple[str, ...], aliases: dict[str, str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "description": description, "enum": list(values)}
    if aliases:
        schema["x-aliases"] = dict(aliases)
    return schema


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
