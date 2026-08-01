from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import re
import shlex

from .agent_planner import AgentPlan, PlannedToolCall, plan_agent_actions
from .agent_plugins import load_plugins
from .agent_skills import LocalSkill, discover_skills, load_skill, render_loaded_skills
from .agent_store import AgentStore, utc_now
from .agent_tools import OffSecToolRegistry, ToolResult
from .agent_bridges import BridgeConfig
from .model_adapters import BaseModelAdapter, build_adapter, build_fallback_adapter
from .models import ActionRequest, EngagementROE, redact_secrets


_MODEL_PLANNER_APPROVAL_ACTION_TOOLS = {"approve", "deny"}
_TARGET_AFFECTING_PLANNED_TOOLS = {
    "assess_action",
    "run_command",
    "start_process",
    "nmap_scan",
    "httpx_probe",
    "nuclei_scan",
    "ffuf_scan",
}
_EXECUTION_CAPABLE_TOOLS = {"run_command", "start_process", "nmap_scan", "httpx_probe", "nuclei_scan", "ffuf_scan"}
_ACTUAL_EXECUTION_STATUSES = {"executed", "started", "failed", "timeout"}
_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP = 20
_NATIVE_TOOL_CALL_MILESTONE_CONTRACT = {
    "natural_language_model_planning": True,
    "wrapped_json_plan_extraction": True,
    "provider_native_tool_call_translation": True,
    "responses_api_endpoint_planning": True,
    "single_top_level_tool_call_translation": True,
    "singular_tool_call_alias_translation": True,
    "camel_case_tool_call_alias_translation": True,
    "choice_delta_tool_call_translation": True,
    "choice_delta_fragment_assembly": True,
    "choice_delta_function_call_fragment_assembly": True,
    "choice_delta_tool_use_fragment_assembly": True,
    "tool_calls_nested_alias_translation": True,
    "legacy_function_call_translation": True,
    "responses_output_tool_call_translation": True,
    "single_responses_output_tool_call_translation": True,
    "responses_output_nested_function_call_translation": True,
    "responses_message_tool_call_alias_translation": True,
    "responses_message_tool_calls_camel_alias_translation": True,
    "responses_message_tool_call_singular_alias_translation": True,
    "responses_message_function_calls_alias_translation": True,
    "responses_message_function_calls_snake_alias_translation": True,
    "responses_output_message_alias_translation": True,
    "responses_output_message_typeless_wrapper_translation": True,
    "responses_output_message_typeless_direct_translation": True,
    "responses_output_message_typeless_direct_tool_calls_alias_translation": True,
    "responses_output_message_typeless_direct_tool_calls_camel_alias_translation": True,
    "responses_output_message_typeless_direct_tool_call_singular_alias_translation": True,
    "responses_output_message_typeless_direct_tool_call_camel_alias_translation": True,
    "responses_output_message_typeless_direct_function_call_alias_translation": True,
    "responses_output_message_typeless_direct_function_calls_alias_translation": True,
    "responses_output_message_typeless_direct_function_calls_snake_alias_translation": True,
    "responses_message_content_tool_call_translation": True,
    "responses_message_content_function_call_alias_translation": True,
    "responses_message_content_parts_function_call_translation": True,
    "candidate_function_call_translation": True,
    "single_candidate_part_function_call_translation": True,
    "root_message_wrapper_translation": True,
    "root_message_content_function_call_alias_translation": True,
    "root_function_call_translation": True,
    "root_function_calls_alias_translation": True,
    "root_function_calls_snake_alias_translation": True,
    "root_function_calls_nested_function_call_translation": True,
    "root_function_calls_snake_nested_function_call_translation": True,
    "root_tool_use_alias_translation": True,
    "message_tool_use_alias_translation": True,
    "message_function_call_alias_translation": True,
    "message_function_calls_alias_translation": True,
    "message_function_calls_nested_function_call_translation": True,
    "single_content_block_tool_call_translation": True,
    "top_level_content_block_tool_call_translation": True,
    "content_block_function_call_alias_translation": True,
    "content_block_tool_use_alias_translation": True,
    "content_parts_function_call_translation": True,
    "provider_argument_alias_translation": True,
    "provider_tool_name_alias_translation": True,
    "per_step_model_tool_call_budget": True,
    "schema_validation_before_dispatch": True,
    "runtime_policy_boundary": True,
    "guardrail_preview_before_target_activity": True,
    "approval_queue_direct_replay_boundary": True,
    "explicit_execute_required_for_command_activity": True,
    "scanner_execute_boundary": True,
    "result_feedback_loop": True,
    "cumulative_redacted_feedback": True,
    "followup_prompt_secret_redaction": True,
    "terminal_no_dispatch_stops": True,
    "terminal_approval_block_stops": True,
    "duplicate_plan_stops": True,
    "redacted_transcripts_and_audit": True,
    "execution_ledger_claim_contract": True,
    "provider_tool_call_id_provenance": True,
    "transcript_provider_call_provenance": True,
    "custom_freeform_tool_calls_rejected": True,
    "provider_hosted_tool_calls_rejected": True,
    "gateway_and_bridge_surfaces": True,
}


@dataclass(slots=True)
class AgentRuntimeConfig:
    engagement_path: str
    db_path: str = "data/phobos-agent.db"
    session_name: str = "default"
    operator_name: str = "operator"
    assistant_style: str = "direct, concise, practical, evidence-first"
    provider: str = "heuristic"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    key_env: str = "OPENAI_API_KEY"
    command_template: str | None = None
    workspace_dir: str | None = None
    plugin_dirs: tuple[str, ...] = ()
    max_context_messages: int = 12
    tool_timeout: int = 30
    model_providers: tuple[dict[str, Any], ...] = ()
    auto_execute_natural: bool = False
    auto_model_planning: bool = False
    max_auto_steps: int = 5
    blocked_tools: tuple[str, ...] = ()
    confirm_tools: tuple[str, ...] = ()
    skill_dirs: tuple[str, ...] = ()
    preload_skills: tuple[str, ...] = ()
    skill_bundles: dict[str, tuple[str, ...]] | None = None
    bridges: dict[str, dict[str, Any]] | None = None
    config_path: str | None = None


class OffSecAgentRuntime:
    """Standalone local Phobos Agent runtime.

    This gives the harness a Hermes-like local runtime layer: sessions, memory,
    tool registry/schemas, approvals, background processes, jobs, plugins,
    context compaction, model fallback, a gateway API, subagents, and an
    interactive chat loop. Target-affecting actions remain ROE-gated with the
    user's default non-destructive safety posture.
    """

    def __init__(self, config: AgentRuntimeConfig, adapter: BaseModelAdapter | None = None):
        self.config = config
        self.roe = EngagementROE.load(config.engagement_path)
        self.store = AgentStore(config.db_path)
        self.session_id = self.store.get_or_create_session(config.session_name, config.engagement_path)
        if adapter is not None:
            self.adapter = adapter
        elif config.model_providers:
            self.adapter = build_fallback_adapter(config.model_providers)
        else:
            self.adapter = build_adapter(config.provider, model=config.model, base_url=config.base_url, key_env=config.key_env, command_template=config.command_template)
        self.registry = OffSecToolRegistry(
            self.roe,
            self.store,
            self.session_id,
            self.adapter,
            workspace_dir=config.workspace_dir,
            default_timeout=config.tool_timeout,
            blocked_tools=config.blocked_tools,
            confirm_tools=config.confirm_tools,
            runtime_metadata=_runtime_metadata(config),
        )
        self.plugins = load_plugins(self.registry, config.plugin_dirs)
        self.available_skills = discover_skills(config.skill_dirs)
        self.loaded_skills: dict[str, LocalSkill] = {}
        for skill_name in config.preload_skills:
            try:
                skill = load_skill(skill_name, config.skill_dirs)
                self.loaded_skills[skill.name] = skill
            except (KeyError, ValueError):
                self.store.audit(self.session_id, "skill_preload_failed", {"skill": skill_name})

    def close(self) -> None:
        self.store.close()

    def handle_message(self, message: str) -> str:
        self.store.append_message(self.session_id, "user", message)
        if message.strip().startswith("/"):
            response = self._handle_command(message.strip())
        else:
            response = self._handle_natural(message)
        self.store.append_message(self.session_id, "assistant", response)
        return response

    def render_chat_response(self, response: str, *, message: str = "", platform: str = "chat") -> str:
        """Render a runtime response for chat bridges without changing raw CLI/API output."""
        return _render_chat_response(response, message=message, platform=platform, runtime=self)

    def run_due_jobs(self) -> list[dict[str, Any]]:
        results = []
        for job in self.store.due_jobs(self.session_id):
            response = self.handle_message(job.prompt)
            redacted_response = redact_secrets(response) or ""
            self.store.mark_job_run(job.id, redacted_response, session_id=self.session_id)
            results.append({"job_id": job.id, "name": redact_secrets(job.name), "response": redacted_response})
        return results

    def chat_loop(self) -> None:  # pragma: no cover - interactive convenience
        print("Phobos Agent ready. Type /help or /exit.")
        while True:
            try:
                message = input("offsec> ").strip()
            except EOFError:
                print()
                break
            if message in {"/exit", "/quit"}:
                break
            if not message:
                continue
            print(self.handle_message(message))

    def _handle_natural(self, message: str) -> str:
        if self.config.auto_execute_natural:
            plan = self._plan_actions(message, allow_command_execution=False, use_model=self.config.auto_model_planning)
            if plan.tool_calls:
                return self._execute_plan(plan, apply=True, trigger="natural_auto")
        memories = self.store.recall(message, limit=5)
        recent = self.store.recent_messages(self.session_id, limit=self.config.max_context_messages)
        summary = self.store.latest_context_summary(self.session_id)
        operator_name = (self.config.operator_name or "operator").strip() or "operator"
        context_parts = [
            "Phobos assistant style:\n" + json.dumps(
                {
                    "operator_name": operator_name,
                    "style": self.config.assistant_style,
                    "chat_contract": [
                        "Speak like a senior pentest copilot, not a harness status logger.",
                        "Keep safety/ROE detail visible only when it affects the answer or next step.",
                        "Separate proven facts from hypotheses and recommend evidence-backed validation.",
                        "Do not say a command/tool ran unless it actually ran through the runtime.",
                    ],
                },
                indent=2,
            )
        ]
        if summary:
            context_parts.append("Latest compact session summary:\n" + summary["summary"])
        context_parts.append("Recent messages:\n" + "\n".join(f"{m['role']}: {m['content']}" for m in recent))
        if memories:
            context_parts.append("Relevant local memories:\n" + "\n".join(f"- {m['key']}: {m['value']}" for m in memories))
        loaded_skill_context = render_loaded_skills(self.loaded_skills)
        if loaded_skill_context:
            context_parts.append("Loaded local skills:\n" + loaded_skill_context)
        context_parts.append("Engagement ROE:\n" + json.dumps({
            "name": self.roe.name,
            "scope": self.roe.in_scope_targets,
            "allowed": self.roe.allowed_techniques,
            "prohibited": self.roe.prohibited_techniques,
            "safety_mode": self.roe.safety_mode,
        }, indent=2))
        prompt = (
            "Answer the operator's message as Phobos. Be useful and natural; do not include harness boilerplate. "
            "If the message asks for execution, explain the safe explicit Phobos command path rather than pretending to act.\n\n"
            f"Operator message: {message}"
        )
        draft = (redact_secrets(self.adapter.generate("assistant", prompt, context="\n\n".join(context_parts)).content) or "").strip()
        draft = _strip_natural_boilerplate(draft)
        if _looks_like_execution_request(message) and not _mentions_no_execution(draft):
            draft = draft.rstrip() + "\n\nI didn’t run anything from that message. If you want action, use `/auto apply=true prompt=\"...\"` for a guarded plan or an explicit slash command like `/nmap ... execute=false`."
        self.store.audit(
            self.session_id,
            "natural_response",
            {"operator_name": operator_name, "tools_executed": False, "message_preview": redact_secrets(message[:200])},
        )
        return draft

    def _handle_command(self, message: str) -> str:
        tokens = shlex.split(message)
        if not tokens:
            return HELP_TEXT
        command = tokens[0][1:]
        args = _parse_key_values(tokens[1:])
        if command in {"help", "h"}:
            return HELP_TEXT
        if command == "tools":
            return "Available tools:\n" + "\n".join(f"- {spec.name}: {spec.description}" for spec in self.registry.specs())
        if command in {"schemas", "tool-schema", "tool-schemas"}:
            return _format_result(self.registry.run("tool_schemas", args))
        if command == "plugins":
            return json.dumps({"plugin_dirs": list(self.config.plugin_dirs), "plugins": self.plugins}, indent=2)
        if command in {"skills", "skill-list"}:
            return json.dumps({
                "skill_dirs": list(self.config.skill_dirs),
                "loaded": sorted(self.loaded_skills),
                "skills": [skill.to_dict() for skill in self.available_skills.values()],
                "bundles": {name: list(skills) for name, skills in (self.config.skill_bundles or {}).items()},
            }, indent=2)
        if command in {"skill", "load-skill"}:
            bundle = str(args.get("bundle", "")).strip()
            if bundle:
                names = (self.config.skill_bundles or {}).get(bundle)
                if not names:
                    return f"Skill bundle not found: {bundle}"
                loaded = []
                for name in names:
                    try:
                        loaded.append(self._load_skill(str(name)).name)
                    except (KeyError, ValueError) as exc:
                        return f"Skill load failed: {exc}"
                return json.dumps({"loaded": loaded, "bundle": bundle}, indent=2)
            skill_name = str(args.get("name") or args.get("skill") or args.get("query") or "").strip()
            if not skill_name:
                return "Usage: /skill name=<skill-name> or /skill bundle=<bundle-name>"
            try:
                skill = self._load_skill(skill_name)
            except (KeyError, ValueError) as exc:
                return f"Skill load failed: {exc}"
            return json.dumps(skill.to_dict(include_content=True), indent=2)[:10000]
        if command in self.available_skills:
            try:
                skill = self._load_skill(command)
            except (KeyError, ValueError) as exc:
                return f"Skill load failed: {exc}"
            return f"Loaded skill {skill.name}: {skill.description}"
        if command in {"tool", "call"}:
            tool_name = str(args.get("name") or args.get("tool") or "").strip()
            if not tool_name:
                return "Usage: /tool name=<tool_name> key=value ..."
            tool_args = {key: value for key, value in args.items() if key not in {"name", "tool"}}
            return _format_result(self.registry.run(tool_name, tool_args))
        if command in {"auto", "agent", "do"}:
            prompt = str(args.get("prompt") or args.get("query") or " ".join(args.get("_positional", []))).strip()
            if not prompt:
                return "Usage: /auto prompt=<natural request> apply=false execute=false model=false"
            execute, error = _slash_bool_arg(args, "execute", False)
            if error:
                return error
            use_model, error = _slash_bool_arg(args, "model", self.config.auto_model_planning)
            if error:
                return error
            apply_plan, error = _slash_bool_arg(args, "apply", False)
            if error:
                return error
            plan = self._plan_actions(prompt, allow_command_execution=execute, use_model=use_model)
            return self._execute_plan(plan, apply=apply_plan)
        if command in {"auto-loop", "loop", "task-run"}:
            prompt = str(args.get("prompt") or args.get("query") or " ".join(args.get("_positional", []))).strip()
            if not prompt:
                return "Usage: /auto-loop prompt=<goal> steps=5 execute=false model=false"
            steps, error = _slash_int_arg(args, "steps", self.config.max_auto_steps, minimum=1, maximum=10)
            if error:
                return error
            execute, error = _slash_bool_arg(args, "execute", False)
            if error:
                return error
            use_model, error = _slash_bool_arg(args, "model", self.config.auto_model_planning)
            if error:
                return error
            return self._execute_auto_loop(prompt, steps=steps, execute=execute, use_model=use_model)
        if command == "sessions":
            data = {
                "session_id": self.session_id,
                "sessions": self.store.list_sessions(limit=int(args.get("limit", 20))),
                "recent": self.store.recent_messages(self.session_id, limit=int(args.get("recent", 8))),
            }
            return json.dumps(data, indent=2)
        if command == "run-due":
            return json.dumps({"jobs_run": self.run_due_jobs()}, indent=2)
        mapping = {
            "assess": "assess_action",
            "scope": "scope_check",
            "scope-check": "scope_check",
            "roe-check": "scope_check",
            "run": "run_command",
            "start": "start_process",
            "process-start": "start_process",
            "poll": "poll_process",
            "process-poll": "poll_process",
            "wait": "wait_process",
            "process-wait": "wait_process",
            "log": "process_log",
            "process-log": "process_log",
            "process": "get_process",
            "process-get": "get_process",
            "process-detail": "get_process",
            "kill": "kill_process",
            "process-kill": "kill_process",
            "processes": "list_processes",
            "procs": "list_processes",
            "approve": "approve",
            "deny": "deny",
            "plan": "impact_plan",
            "burp-tab": "burp_tab",
            "bloodhound": "bloodhound_import",
            "bh": "bloodhound_import",
            "cve": "cve_advice",
            "nmap": "nmap_scan",
            "nmap-scan": "nmap_scan",
            "httpx": "httpx_probe",
            "httpx-probe": "httpx_probe",
            "nuclei": "nuclei_scan",
            "nuclei-scan": "nuclei_scan",
            "ffuf": "ffuf_scan",
            "ffuf-scan": "ffuf_scan",
            "tool-runs": "list_tool_runs",
            "tool-run": "get_tool_run",
            "finding": "export_finding",
            "findings": "list_findings",
            "finding-create": "create_finding",
            "finding-update": "update_finding",
            "finding-get": "get_finding",
            "finding-export": "finding_export",
            "finding-review": "finding_review",
            "finding-qa": "finding_review",
            "finding-bundle": "finding_bundle",
            "finding-package": "finding_bundle",
            "remember": "remember",
            "recall": "recall",
            "memories": "list_memories",
            "memory-list": "list_memories",
            "memory": "get_memory",
            "memory-get": "get_memory",
            "forget": "forget_memory",
            "memory-forget": "forget_memory",
            "search": "search_session",
            "search-all": "search_all_sessions",
            "search-sessions": "search_all_sessions",
            "context": "context_snapshot",
            "compact": "compact_context",
            "lcm-compact": "context_compact_node",
            "lcm_compact": "lcm_compact",
            "context-node": "context_compact_node",
            "lcm-describe": "context_describe",
            "lcm_describe": "lcm_describe",
            "context-describe": "context_describe",
            "lcm-expand": "context_expand",
            "lcm_expand": "lcm_expand",
            "context-expand": "context_expand",
            "lcm-query": "context_query",
            "context-query": "context_query",
            "reflect": "reflect_memory",
            "hindsight": "hindsight_reflect",
            "hindsight-retain": "hindsight_retain",
            "hindsight-recall": "hindsight_recall",
            "hindsight-reflect": "hindsight_reflect",
            "hindsight-search": "search_all_sessions",
            "read": "workspace_read",
            "write": "workspace_write",
            "workspace-read": "workspace_read",
            "workspace-write": "workspace_write",
            "workspace-search": "workspace_search",
            "search-files": "workspace_search",
            "patch-file": "workspace_patch",
            "workspace-patch": "workspace_patch",
            "job": "schedule_job",
            "jobs": "list_jobs",
            "job-list": "list_jobs",
            "job-detail": "get_job",
            "job-get": "get_job",
            "job-update": "update_job",
            "job-enable": "enable_job",
            "job-disable": "disable_job",
            "approvals": "list_approvals",
            "approval": "get_approval",
            "approval-get": "get_approval",
            "approval-detail": "get_approval",
            "subagents": "subagent_review",
            "delegate": "delegate_tasks",
            "delegations": "list_delegations",
            "delegation": "get_delegation",
            "delegation-get": "get_delegation",
            "delegation-detail": "get_delegation",
            "auth-status": "auth_status",
            "auth": "auth_status",
            "preflight": "safety_preflight",
            "safety-preflight": "safety_preflight",
            "readiness": "safety_preflight",
            "guardrail-test": "guardrail_selftest",
            "guardrail-selftest": "guardrail_selftest",
            "guardrails-test": "guardrail_selftest",
            "safety-selftest": "guardrail_selftest",
            "media-import": "media_import",
            "media-list": "media_list",
            "media-get": "media_get",
            "media-detail": "media_get",
            "media-artifact": "media_get",
            "sealed-export": "sealed_export",
            "sealed-import": "sealed_import",
            "auto-transcripts": "list_auto_transcripts",
            "auto-transcript-list": "list_auto_transcripts",
            "native-transcripts": "list_auto_transcripts",
            "native-transcript-list": "list_auto_transcripts",
            "tool-call-transcripts": "list_auto_transcripts",
            "auto-transcript": "get_auto_transcript",
            "auto-transcript-detail": "get_auto_transcript",
            "native-transcript": "get_auto_transcript",
            "native-transcript-detail": "get_auto_transcript",
            "tool-call-transcript": "get_auto_transcript",
            "audit": "audit_log",
            "audit-get": "get_audit",
            "audit-detail": "get_audit",
            "audit-event": "get_audit",
            "timeline": "evidence_timeline",
            "evidence-timeline": "evidence_timeline",
            "manifest": "evidence_manifest",
            "evidence-manifest": "evidence_manifest",
            "manifest-verify": "evidence_manifest_verify",
            "manifest-check": "evidence_manifest_verify",
            "evidence-manifest-verify": "evidence_manifest_verify",
            "secret-scan": "evidence_secret_scan",
            "evidence-secret-scan": "evidence_secret_scan",
            "evidence-secrets": "evidence_secret_scan",
            "closeout": "closeout_review",
            "closeout-review": "closeout_review",
            "closeout-readiness": "closeout_review",
            "ref": "resolve_local_ref",
            "detail": "resolve_local_ref",
            "resolve-ref": "resolve_local_ref",
            "local-ref": "resolve_local_ref",
            "status": "runtime_status",
            "export-pack": "export_pack",
            "pack": "export_pack",
            "briefing": "operator_briefing",
            "handoff": "export_session",
            "export-session": "export_session",
            "import-session": "import_session",
            "tasks": "list_tasks",
            "task-list": "list_tasks",
            "task": "get_task",
            "task-get": "get_task",
            "task-detail": "get_task",
            "task-add": "add_task",
            "task-update": "update_task",
        }
        if command not in mapping:
            return f"Unknown command /{command}. Use /help or /tools."
        result = self.registry.run(mapping[command], args)
        return _format_result(result)

    def _execute_plan(self, plan: AgentPlan, *, apply: bool, trigger: str = "slash_auto") -> str:
        payload: dict[str, Any] = _redact_runtime_value(plan.to_dict())
        safe_trigger = str(trigger or "slash_auto").strip() or "slash_auto"
        payload["trigger"] = safe_trigger
        payload["natural_auto_execute"] = safe_trigger == "natural_auto"
        planner_trace = [_auto_loop_planner_trace_entry(1, plan)]
        payload["planner_trace"] = planner_trace
        payload["planner_trace_count"] = len(planner_trace)
        if not apply:
            payload["mode"] = "plan_only"
            payload["next_step"] = "Re-run with /auto apply=true to invoke these tools. Add execute=true only if guarded command execution is intended."
            payload["results"] = []
            payload["execution_ledger"] = []
            payload["execution_summary"] = _native_execution_summary([])
            payload["transcript_artifact_written"] = False
            payload["secret_values_redacted"] = True
            payload["no_tools_executed"] = True
            try:
                artifacts = _write_auto_plan_artifacts(self.registry.harness.store.root, payload)
                payload["artifacts"] = artifacts
                payload["transcript_artifact_written"] = True
            except Exception as exc:  # transcript failure must not create execution claims
                payload["artifact_error"] = redact_secrets(str(exc)) or "auto-plan preview artifact write failed"
            self.store.audit(
                self.session_id,
                "auto_plan_preview",
                {
                    "prompt_preview": redact_secrets(str(plan.prompt or "")[:200]),
                    "tool_count": len(plan.tool_calls),
                    "rejected_tool_count": len(plan.rejected_tool_calls),
                    "trigger": safe_trigger,
                    "natural_auto_execute": payload.get("natural_auto_execute", False),
                    "transcript_artifact_written": payload.get("transcript_artifact_written", False),
                    "artifacts": payload.get("artifacts", {}),
                    "planner_trace_count": len(planner_trace),
                    "planner_providers": [
                        str(item.get("provider") or item.get("selected_provider") or "")
                        for item in planner_trace
                        if isinstance(item, dict) and str(item.get("provider") or item.get("selected_provider") or "").strip()
                    ],
                    "no_tools_executed": True,
                },
            )
            return "Auto plan (no tools executed):\n" + json.dumps(_redact_runtime_value(payload), indent=2)
        results = []
        execution_ledger = []
        for call in plan.tool_calls:
            result = self.registry.run(call.tool, call.args)
            execution = _planned_call_execution_ledger(call, result)
            execution_ledger.append(execution)
            results.append(_redact_runtime_value({"tool": call.tool, "reason": call.reason, "result": result.to_dict(), "execution": execution}))
        payload["mode"] = "applied"
        payload["results"] = results
        payload["execution_ledger"] = _redact_runtime_value(execution_ledger)
        payload["execution_summary"] = _native_execution_summary(execution_ledger)
        payload["transcript_artifact_written"] = False
        payload["secret_values_redacted"] = True
        try:
            artifacts = _write_auto_plan_artifacts(self.registry.harness.store.root, payload)
            payload["artifacts"] = artifacts
            payload["transcript_artifact_written"] = True
        except Exception as exc:  # transcript failure must not change tool execution claims
            payload["artifact_error"] = redact_secrets(str(exc)) or "auto-plan artifact write failed"
        result_counts: dict[str, int] = {}
        for item in results:
            result_obj = item.get("result") if isinstance(item, dict) else None
            status = str(result_obj.get("status") or "unknown") if isinstance(result_obj, dict) else "unknown"
            result_counts[status] = result_counts.get(status, 0) + 1
        self.store.audit(
            self.session_id,
            "auto_plan_apply",
            {
                "prompt_preview": str(plan.prompt or "")[:200],
                "tool_count": len(plan.tool_calls),
                "result_counts": result_counts,
                "trigger": safe_trigger,
                "natural_auto_execute": payload.get("natural_auto_execute", False),
                "transcript_artifact_written": payload.get("transcript_artifact_written", False),
                "artifacts": payload.get("artifacts", {}),
                "planner_trace_count": len(planner_trace),
                "planner_providers": [
                    str(item.get("provider") or item.get("selected_provider") or "")
                    for item in planner_trace
                    if isinstance(item, dict) and str(item.get("provider") or item.get("selected_provider") or "").strip()
                ],
            },
        )
        return "Auto plan applied:\n" + json.dumps(_redact_runtime_value(payload), indent=2)

    def _validate_plan(self, plan: AgentPlan, *, allow_command_execution: bool) -> AgentPlan:
        """Validate planned tool names and JSON-schema args without dispatch.

        Model-generated and deterministic plans both pass through this boundary
        before plan-only display or application, so invalid tool calls cannot be
        shown as runnable steps and cannot create approval rows before the
        operator explicitly applies a validated plan.
        """

        warnings = list(plan.warnings)
        rejected = list(plan.rejected_tool_calls)
        validated_calls: list[PlannedToolCall] = []
        attempted_tool_call_count = len(plan.tool_calls)
        for call in plan.tool_calls:
            tool = str(call.tool or "").strip()
            args = dict(call.args) if isinstance(call.args, dict) else call.args
            reason = str(call.reason or "Planned tool call.")
            if tool in _EXECUTION_CAPABLE_TOOLS and isinstance(args, dict) and not allow_command_execution:
                if bool(args.get("execute", False)):
                    warnings.append(f"{tool} planned with execute=false because command execution was not explicitly enabled.")
                args = dict(args)
                args["execute"] = False
            validation = self.registry.validate_tool_call(tool, args if isinstance(args, dict) else {})
            if validation.status != "ok":
                message = validation.message
                warnings.append(f"Planned tool {tool or '<missing>'} rejected before dispatch: {message}")
                rejected.append(_redact_runtime_value({"tool": tool or None, "reason": message, "args": args if isinstance(args, dict) else {"value_type": type(args).__name__}}))
                continue
            validated_args = validation.data.get("args", args) if isinstance(validation.data, dict) else args
            runtime_policy = "allow"
            if tool in self.registry.blocked_tools and tool not in self.registry._policy_bypass_tools:
                runtime_policy = "blocked"
                warnings.append(f"Planned tool {tool} will be blocked by runtime policy if applied.")
            elif tool in self.registry.confirm_tools and tool not in self.registry._policy_bypass_tools:
                runtime_policy = "confirm_required"
                warnings.append(f"Planned tool {tool} will require approval by runtime policy if applied.")
            validation_payload = dict(call.validation or {})
            guardrail_preview = _guardrail_preview_for_planned_call(self.roe, self.registry, tool, validated_args)
            if guardrail_preview:
                guardrail_status = str(guardrail_preview.get("status") or "unknown")
                validation_payload["guardrail_status"] = guardrail_status
                validation_payload["guardrail_preview"] = guardrail_preview
                if guardrail_status == "confirm":
                    warnings.append(f"Planned tool {tool} will require guardrail approval if applied.")
                elif guardrail_status == "block":
                    warnings.append(f"Planned tool {tool} will be blocked by guardrails if applied.")
            validation_payload.update({"status": "ok", "schema_validated": True, "runtime_policy": runtime_policy})
            call_metadata = _redact_runtime_value(dict(call.metadata or {})) if isinstance(call.metadata, dict) else {}
            validated_calls.append(PlannedToolCall(tool=tool, args=validated_args, reason=reason, validation=validation_payload, metadata=call_metadata))
        metadata = dict(plan.metadata or {})
        if attempted_tool_call_count:
            metadata["attempted_tool_call_count"] = attempted_tool_call_count
            metadata["accepted_tool_call_count"] = len(validated_calls)
            if not validated_calls:
                metadata["all_tool_calls_rejected"] = True
                if metadata.get("planner") == "model" or metadata.get("provider"):
                    metadata["invalid_model_tool_plan"] = True
        return AgentPlan(
            prompt=plan.prompt,
            summary=plan.summary,
            tool_calls=validated_calls,
            warnings=warnings,
            rejected_tool_calls=rejected,
            metadata=metadata,
        )

    def _plan_actions(
        self,
        prompt: str,
        *,
        allow_command_execution: bool,
        use_model: bool,
        allow_deterministic_model_fallback: bool = True,
    ) -> AgentPlan:
        deterministic = plan_agent_actions(prompt, allow_command_execution=allow_command_execution)
        if not use_model:
            return self._validate_plan(deterministic, allow_command_execution=allow_command_execution)
        try:
            model_plan = self._plan_actions_with_model(prompt, allow_command_execution=allow_command_execution)
        except Exception as exc:
            safe_error = redact_secrets(str(exc)) or exc.__class__.__name__
            if not allow_deterministic_model_fallback:
                return self._validate_plan(
                    AgentPlan(
                        prompt=prompt,
                        summary="Model planner failed after tool feedback; native loop stopped before deterministic re-planning.",
                        warnings=[f"Model planner failed after tool feedback; deterministic fallback suppressed: {safe_error}"],
                        metadata={
                            "deterministic_fallback_suppressed": True,
                            "model_planner_failed": True,
                            "model_error": safe_error,
                        },
                    ),
                    allow_command_execution=allow_command_execution,
                )
            deterministic.warnings.append(f"Model planner failed; deterministic planner used: {safe_error}")
            return self._validate_plan(deterministic, allow_command_execution=allow_command_execution)
        if not model_plan.tool_calls:
            if allow_deterministic_model_fallback and deterministic.tool_calls:
                deterministic.warnings.extend(model_plan.warnings)
                deterministic.rejected_tool_calls.extend(model_plan.rejected_tool_calls)
                deterministic.metadata = _merge_plan_metadata(deterministic.metadata, model_plan.metadata)
                return self._validate_plan(deterministic, allow_command_execution=allow_command_execution)
            if not allow_deterministic_model_fallback:
                model_plan.metadata = dict(model_plan.metadata or {})
                model_plan.metadata.update({"deterministic_fallback_suppressed": True, "terminal_no_tool_plan_respected": True})
            return self._validate_plan(model_plan, allow_command_execution=allow_command_execution)
        validated_model = self._validate_plan(model_plan, allow_command_execution=allow_command_execution)
        if not validated_model.tool_calls and allow_deterministic_model_fallback and deterministic.tool_calls:
            deterministic.warnings.extend(validated_model.warnings)
            deterministic.rejected_tool_calls.extend(validated_model.rejected_tool_calls)
            deterministic.metadata = _merge_plan_metadata(deterministic.metadata, validated_model.metadata)
            return self._validate_plan(deterministic, allow_command_execution=allow_command_execution)
        if not validated_model.tool_calls and not allow_deterministic_model_fallback:
            validated_model.metadata = dict(validated_model.metadata or {})
            validated_model.metadata["deterministic_fallback_suppressed"] = True
            if validated_model.metadata.get("all_tool_calls_rejected"):
                validated_model.metadata["invalid_model_tool_plan"] = True
            else:
                validated_model.metadata["terminal_no_tool_plan_respected"] = True
        return validated_model

    def _model_tool_plan_context(self, prompt: str) -> str:
        """Build bounded, redacted runtime context for model/native tool-call planning.

        Tool schemas are passed separately to adapters.  This context gives a
        native planner enough local state to choose useful next tool calls while
        preserving the same safety boundary: no dispatch, approval queueing, or
        target activity happens while this context is assembled.
        """

        try:
            memories = self.store.recall(prompt, limit=5) if prompt.strip() else []
        except Exception:
            memories = []
        try:
            recent_messages = self.store.recent_messages(self.session_id, limit=min(max(int(self.config.max_context_messages), 1), 12))
        except Exception:
            recent_messages = []
        try:
            latest_summary = self.store.latest_context_summary(self.session_id)
        except Exception:
            latest_summary = None
        try:
            tasks = self.store.list_tasks(self.session_id, status="all", limit=12)
        except Exception:
            tasks = []
        try:
            pending_approvals = self.store.list_approvals(self.session_id, status="pending", limit=12)
        except Exception:
            pending_approvals = []
        context_payload: dict[str, Any] = {
            "purpose": (
                "Bounded Phobos runtime context for model tool planning. Tool specs are supplied separately. "
                "Do not claim execution; Phobos revalidates schemas, runtime policy, ROE, and approvals when a plan is applied."
            ),
            "engagement": {
                "name": self.roe.name,
                "authorized": self.roe.authorized,
                "in_scope_targets": list(self.roe.in_scope_targets),
                "allowed_techniques": list(self.roe.allowed_techniques),
                "prohibited_techniques": list(self.roe.prohibited_techniques),
                "testing_window": self.roe.testing_window,
                "stop_conditions": list(self.roe.stop_conditions),
                "safety_mode": self.roe.safety_mode,
                "notes": self.roe.notes,
            },
            "runtime_policy": {
                "blocked_tools": sorted(self.registry.blocked_tools),
                "confirm_tools": sorted(self.registry.confirm_tools),
                "approval_control_tools_omitted_from_model_specs": sorted(_MODEL_PLANNER_APPROVAL_ACTION_TOOLS),
                "command_execution_requires_operator_execute_true": True,
                "max_tool_calls_per_model_step": _MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP,
            },
            "latest_context_summary": latest_summary or {},
            "recent_messages": recent_messages,
            "relevant_memories": memories,
            "tasks": tasks,
            "pending_approvals": pending_approvals,
            "loaded_skills": [
                {"name": skill.name, "description": skill.description}
                for skill in sorted(self.loaded_skills.values(), key=lambda item: item.name)
            ],
        }
        text = json.dumps(_redact_runtime_value(context_payload), indent=2, sort_keys=True, default=str)
        if len(text) > 12000:
            text = text[:12000] + "\n...[model tool-plan context truncated]"
        return "Phobos model tool-call planning context:\n" + text

    def _plan_actions_with_model(self, prompt: str, *, allow_command_execution: bool) -> AgentPlan:
        specs = [spec.to_dict() for spec in self.registry.specs() if spec.name not in _MODEL_PLANNER_APPROVAL_ACTION_TOOLS]
        context = self._model_tool_plan_context(prompt)
        response = self.adapter.generate_tool_plan(prompt, specs, allow_command_execution=allow_command_execution, context=context)
        parsed = _extract_json_object(response.content)
        calls: list[PlannedToolCall] = []
        rejected: list[dict[str, Any]] = []
        warnings = [str(item) for item in parsed.get("warnings", []) if str(item).strip()] if isinstance(parsed.get("warnings", []), list) else []
        if isinstance(parsed.get("rejected_tool_calls", []), list):
            for item in parsed.get("rejected_tool_calls", []):
                if isinstance(item, dict):
                    rejected.append(item)
                else:
                    rejected.append({"tool": None, "reason": "Rejected tool call must be an object.", "args": {"value_type": type(item).__name__}})
        raw_tool_calls = parsed.get("tool_calls", [])
        raw_tool_call_count = len(raw_tool_calls) if isinstance(raw_tool_calls, list) else 0
        budget_excess_count = 0
        if raw_tool_calls in (None, ""):
            raw_tool_calls = []
        elif not isinstance(raw_tool_calls, list):
            warnings.append("Model planner returned tool_calls as a non-list value; skipped before dispatch.")
            rejected.append({
                "tool": None,
                "reason": "tool_calls must be an array.",
                "args": {"value_type": type(raw_tool_calls).__name__},
            })
            raw_tool_calls = []
        elif len(raw_tool_calls) > _MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP:
            budget_excess_count = len(raw_tool_calls) - _MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP
            warnings.append(
                "Model planner returned "
                f"{len(raw_tool_calls)} tool calls; only the first {_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP} "
                f"are accepted per step and {budget_excess_count} were rejected before dispatch."
            )
            for item in raw_tool_calls[_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP:]:
                if isinstance(item, dict):
                    tool = str(item.get("tool") or "").strip() or None
                    tool_args = item.get("args", {})
                    if not isinstance(tool_args, dict):
                        tool_args = {"value_type": type(tool_args).__name__}
                    rejected.append(_redact_runtime_value({
                        "tool": tool,
                        "reason": f"Exceeded per-step model tool-call budget ({_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP}).",
                        "args": tool_args,
                        "metadata": _model_planned_call_metadata(item),
                    }))
                else:
                    rejected.append({
                        "tool": None,
                        "reason": f"Exceeded per-step model tool-call budget ({_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP}).",
                        "args": {"value_type": type(item).__name__},
                    })
            raw_tool_calls = raw_tool_calls[:_MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP]
        for item in raw_tool_calls:
            if not isinstance(item, dict):
                warnings.append("Model planner returned a non-object tool call; skipped.")
                rejected.append({"tool": None, "reason": "tool call must be an object", "args": {"value_type": type(item).__name__}})
                continue
            tool = str(item.get("tool", "")).strip()
            tool_args = item.get("args", {})
            if not isinstance(tool_args, dict):
                warnings.append(f"Model planner args for {tool!r} were not an object; skipped.")
                rejected.append({"tool": tool or None, "reason": "Tool args must be an object.", "args": {"value_type": type(tool_args).__name__}})
                continue
            if tool in _MODEL_PLANNER_APPROVAL_ACTION_TOOLS:
                message = "Approval-control tools require an explicit direct operator command; model planners cannot approve or deny queued actions."
                warnings.append(f"Model planner proposed {tool}; skipped because approval actions require direct operator control.")
                rejected.append(_redact_runtime_value({"tool": tool, "reason": message, "args": tool_args}))
                continue
            if tool in _EXECUTION_CAPABLE_TOOLS and not allow_command_execution:
                tool_args = dict(tool_args)
                tool_args["execute"] = False
                warnings.append(f"{tool} planned with execute=false because command execution was not explicitly enabled.")
            calls.append(
                PlannedToolCall(
                    tool=tool,
                    args=tool_args,
                    reason=str(item.get("reason") or "Model planner selected this tool."),
                    metadata=_model_planned_call_metadata(item),
                )
            )
        metadata = _model_plan_metadata(response)
        metadata.update({
            "context_provided": bool(context),
            "context_chars": len(context),
            "max_model_tool_calls_per_step": _MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP,
            "raw_model_tool_call_count": raw_tool_call_count,
            "tool_call_budget_excess_count": budget_excess_count,
            "tool_call_budget_exhausted": budget_excess_count > 0,
        })
        return AgentPlan(
            prompt=prompt,
            summary=str(parsed.get("summary") or f"Model planned {len(calls)} tool call(s)."),
            tool_calls=calls,
            warnings=warnings,
            rejected_tool_calls=rejected,
            metadata=metadata,
        )

    def _execute_auto_loop(self, prompt: str, *, steps: int, execute: bool, use_model: bool) -> str:
        steps = max(1, min(int(steps), 10))
        current_prompt = prompt
        loop_results: list[dict[str, Any]] = []
        feedback_history: list[dict[str, Any]] = []
        execution_ledger: list[dict[str, Any]] = []
        planner_trace: list[dict[str, Any]] = []
        seen: set[str] = set()
        stop_reason = "max_steps"
        for step in range(1, steps + 1):
            plan = self._plan_actions(
                current_prompt,
                allow_command_execution=execute,
                use_model=use_model,
                allow_deterministic_model_fallback=not feedback_history,
            )
            trace_entry = _auto_loop_planner_trace_entry(step, plan)
            planner_trace.append(trace_entry)
            if not plan.tool_calls:
                metadata = plan.metadata if isinstance(plan.metadata, dict) else {}
                if use_model and metadata.get("model_planner_failed") is True:
                    stop_reason = "model_error"
                    loop_results.append(_redact_runtime_value({
                        "step": step,
                        "mode": "model_error",
                        "plan": plan.to_dict(),
                        "planner_trace": trace_entry,
                        "no_tools_executed": True,
                        "execution_ledger_delta": [],
                    }))
                elif use_model and metadata.get("invalid_model_tool_plan") is True:
                    stop_reason = "invalid_plan"
                    loop_results.append(_redact_runtime_value({
                        "step": step,
                        "mode": "invalid_plan",
                        "plan": plan.to_dict(),
                        "planner_trace": trace_entry,
                        "rejected_tool_call_count": len(plan.rejected_tool_calls),
                        "no_tools_executed": True,
                        "execution_ledger_delta": [],
                    }))
                else:
                    stop_reason = "no_tool_calls"
                    loop_results.append(_redact_runtime_value({
                        "step": step,
                        "mode": "no_plan",
                        "plan": plan.to_dict(),
                        "planner_trace": trace_entry,
                        "no_tools_executed": True,
                        "execution_ledger_delta": [],
                    }))
                break
            signatures = [_planned_call_duplicate_signature(call) for call in plan.tool_calls]
            same_step_seen: set[str] = set()
            same_step_duplicate_signatures: list[str] = []
            for signature in signatures:
                if signature in same_step_seen:
                    same_step_duplicate_signatures.append(signature)
                else:
                    same_step_seen.add(signature)
            prior_duplicate_signatures = [signature for signature in signatures if signature in seen]
            duplicate_signatures = sorted(set(prior_duplicate_signatures + same_step_duplicate_signatures))
            if duplicate_signatures:
                stop_reason = "duplicate_plan"
                if same_step_duplicate_signatures and not prior_duplicate_signatures:
                    duplicate_detection = "tool_args_same_step_repeat"
                elif same_step_duplicate_signatures and prior_duplicate_signatures:
                    duplicate_detection = "tool_args_any_or_same_step_repeat"
                else:
                    duplicate_detection = "tool_args_any_repeat"
                loop_results.append(_redact_runtime_value({
                    "step": step,
                    "mode": "stopped_duplicate_plan",
                    "plan": plan.to_dict(),
                    "planner_trace": trace_entry,
                    "duplicate_tool_call_count": len(duplicate_signatures),
                    "new_tool_call_count": len([signature for signature in set(signatures) if signature not in seen]),
                    "duplicate_detection": duplicate_detection,
                    "no_tools_executed": True,
                    "execution_ledger_delta": [],
                }))
                break
            for signature in signatures:
                seen.add(signature)
            step_results = []
            step_ledger_delta = []
            for call in plan.tool_calls:
                result = self.registry.run(call.tool, call.args)
                execution = _planned_call_execution_ledger(call, result, step=step)
                execution_ledger.append(execution)
                step_ledger_delta.append(execution)
                step_results.append(_redact_runtime_value({"tool": call.tool, "reason": call.reason, "result": result.to_dict(), "execution": execution}))
            step_record = _redact_runtime_value({
                "step": step,
                "mode": "applied",
                "plan": plan.to_dict(),
                "planner_trace": trace_entry,
                "results": step_results,
                "execution_ledger_delta": step_ledger_delta,
            })
            terminal_status_values: list[str] = []
            for item in step_results:
                if not isinstance(item, dict):
                    continue
                result_obj = item.get("result")
                if not isinstance(result_obj, dict):
                    continue
                result_status = str(result_obj.get("status") or "")
                if result_status in {"needs_approval", "blocked"}:
                    terminal_status_values.append(result_status)
            terminal_statuses = sorted(set(terminal_status_values))
            if terminal_statuses and isinstance(step_record, dict):
                step_record["terminal_result_statuses"] = terminal_statuses
            loop_results.append(step_record)
            feedback_history.append(_redact_runtime_value({"step": step, "results": step_results}))
            if terminal_statuses:
                if terminal_statuses == ["needs_approval"]:
                    stop_reason = "approval_required"
                elif terminal_statuses == ["blocked"]:
                    stop_reason = "blocked_result"
                else:
                    stop_reason = "approval_or_blocked_result"
                break
            if not use_model:
                stop_reason = "deterministic_plan_applied"
                break
            current_prompt = _build_auto_loop_feedback_prompt(prompt, feedback_history)
        payload: dict[str, Any] = {
            "prompt": prompt,
            "steps_requested": steps,
            "max_steps_budget": steps,
            "max_steps_budget_exhausted": stop_reason == "max_steps",
            "steps_executed": sum(1 for item in loop_results if item.get("mode") == "applied"),
            "stop_reason": stop_reason,
            "execute": execute,
            "model": use_model,
            "feedback_history_mode": "cumulative_redacted",
            "feedback_history_entries": len(feedback_history),
            "transcript_artifact_written": False,
            "secret_values_redacted": True,
            "execution_ledger": _redact_runtime_value(execution_ledger),
            "execution_summary": _native_execution_summary(execution_ledger),
            "planner_trace": _redact_runtime_value(planner_trace),
            "steps": loop_results,
        }
        if stop_reason == "max_steps":
            payload["next_step"] = (
                "Max-step budget reached. Review the redacted auto-loop transcript before rerunning with a larger explicit steps budget."
            )
        elif stop_reason == "model_error":
            payload["next_step"] = (
                "Model tool planning failed after prior tool feedback. Review the redacted transcript and provider health before rerunning."
            )
        elif stop_reason == "invalid_plan":
            payload["next_step"] = (
                "Model proposed only invalid or rejected tool calls after prior feedback. Review the rejected-call transcript before rerunning."
            )
        try:
            artifacts = _write_auto_loop_artifacts(self.registry.harness.store.root, payload)
            payload["artifacts"] = artifacts
            payload["transcript_artifact_written"] = True
        except Exception as exc:  # artifact failure should be visible but should not misreport tool results
            payload["artifact_error"] = redact_secrets(str(exc)) or "auto-loop artifact write failed"
        self.store.audit(
            self.session_id,
            "auto_loop",
            {
                "prompt_preview": prompt[:200],
                "steps_requested": steps,
                "steps_executed": payload["steps_executed"],
                "stop_reason": stop_reason,
                "execute": execute,
                "model": use_model,
                "artifacts": payload.get("artifacts", {}),
                "transcript_artifact_written": payload.get("transcript_artifact_written", False),
            },
        )
        return "Auto loop completed:\n" + json.dumps(_redact_runtime_value(payload), indent=2)

    def _load_skill(self, name: str) -> LocalSkill:
        skill = load_skill(name, self.config.skill_dirs)
        self.loaded_skills[skill.name] = skill
        self.store.audit(self.session_id, "skill_loaded", {"skill": skill.name, "path": skill.path})
        return skill


def _build_auto_loop_feedback_prompt(original_prompt: str, feedback_history: list[dict[str, Any]], *, limit: int = 8000) -> str:
    """Return the next native-loop prompt with cumulative redacted tool results.

    A model planner needs enough history to recover from earlier errors without
    forgetting later successful local-only actions.  Keep a redacted copy of the
    original operator request in follow-up calls so secret-like prompt fragments
    are not repeatedly re-exposed, then bound/redact the cumulative result
    leaves before the next model/tool-plan call sees them.
    """

    redacted_history = _redact_runtime_value(feedback_history)
    history_items = redacted_history if isinstance(redacted_history, list) else []
    retained = list(history_items)
    history_text = json.dumps(retained, indent=2, sort_keys=True, default=str)
    truncated = False
    if len(history_text) > limit:
        truncated = True
        retained = []
        for item in reversed(history_items):
            candidate = [item] + retained
            candidate_text = json.dumps(candidate, indent=2, sort_keys=True, default=str)
            if retained and len(candidate_text) > limit:
                break
            retained = candidate
            history_text = candidate_text
        if len(history_text) > limit:
            history_text = history_text[:limit] + "\n...[auto-loop feedback truncated]"
        elif len(retained) < len(history_items):
            history_text = "[older auto-loop feedback entries truncated]\n" + history_text
    history_label = "Previous Phobos tool results (cumulative, redacted"
    if truncated:
        history_label += ", bounded"
    history_label += ")"
    safe_original_prompt = redact_secrets(original_prompt) or ""
    return (
        safe_original_prompt
        + f"\n\n{history_label}:\n"
        + history_text
        + "\n\nPlan only any genuinely necessary next tool calls; return an empty tool_calls list if done."
    )


def _auto_loop_planner_trace_entry(step: int, plan: AgentPlan) -> dict[str, Any]:
    """Return bounded, redacted model/planner metadata for one loop step.

    Auto-loop transcripts already store the validated plan and execution ledger.
    This trace is deliberately smaller: it lets operators audit which planner or
    provider produced each step, whether fallback/native tool-call metadata was
    involved, and how many calls were accepted or rejected without embedding raw
    provider payloads, prompts, headers, or secrets.
    """

    metadata = plan.metadata if isinstance(plan.metadata, dict) else {}

    def metadata_int(key: str) -> int:
        value = metadata.get(key)
        if isinstance(value, bool):
            return 0
        if isinstance(value, int):
            return value
        if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
            return int(value.strip())
        return 0

    trace: dict[str, Any] = {
        "step": step,
        "planner": str(metadata.get("planner") or ("model" if metadata else "deterministic")),
        "provider": str(metadata.get("provider") or ""),
        "selected_provider": str(metadata.get("selected_provider") or ""),
        "model": str(metadata.get("model") or ""),
        "tool_call_count": len(plan.tool_calls),
        "rejected_tool_call_count": len(plan.rejected_tool_calls),
        "context_provided": bool(metadata.get("context_provided", False)),
        "context_chars": metadata_int("context_chars"),
        "native_tool_calls": bool(metadata.get("native_tool_calls", False)),
        "native_tool_call_count": metadata_int("native_tool_call_count"),
        "rejected_native_tool_call_count": metadata_int("rejected_native_tool_call_count"),
        "attempted_tool_call_count": metadata_int("attempted_tool_call_count"),
        "accepted_tool_call_count": metadata_int("accepted_tool_call_count"),
        "max_model_tool_calls_per_step": metadata_int("max_model_tool_calls_per_step"),
        "raw_model_tool_call_count": metadata_int("raw_model_tool_call_count"),
        "tool_call_budget_excess_count": metadata_int("tool_call_budget_excess_count"),
        "tool_call_budget_exhausted": bool(metadata.get("tool_call_budget_exhausted", False)),
        "all_tool_calls_rejected": bool(metadata.get("all_tool_calls_rejected", False)),
        "invalid_model_tool_plan": bool(metadata.get("invalid_model_tool_plan", False)),
        "tool_plan_fallback": bool(metadata.get("tool_plan_fallback", False)),
        "model_planner_failed": bool(metadata.get("model_planner_failed", False)),
        "deterministic_fallback_suppressed": bool(metadata.get("deterministic_fallback_suppressed", False)),
        "terminal_no_tool_plan_respected": bool(metadata.get("terminal_no_tool_plan_respected", False)),
    }
    attempts = metadata.get("fallback_attempts")
    if isinstance(attempts, list):
        safe_attempts = []
        for item in attempts[:5]:
            if not isinstance(item, dict):
                continue
            safe_attempts.append({
                "provider": str(item.get("provider") or ""),
                "error": (redact_secrets(str(item.get("error") or "")) or "")[:500],
            })
        trace["fallback_attempt_count"] = len([item for item in attempts if isinstance(item, dict)])
        trace["fallback_attempts"] = safe_attempts
        trace["fallback_attempts_truncated"] = len(attempts) > len(safe_attempts)
    return _redact_runtime_value(trace)


def _planned_call_duplicate_signature(call: PlannedToolCall) -> str:
    """Return a stable duplicate key for a validated planned call.

    Loop duplicate detection is a safety boundary, not a transcript nicety: if a
    model repeats a previously-dispatched tool+args pair with a new reason or as
    part of a larger mixed plan, Phobos must stop before re-dispatching it.
    Exclude free-text reasons and validation metadata so paraphrased repeats do
    not evade the loop guard.
    """

    return json.dumps({"tool": call.tool, "args": call.args}, sort_keys=True, default=str)


def _guardrail_preview_for_planned_call(roe: EngagementROE, registry: OffSecToolRegistry, tool: str, args: Any) -> dict[str, Any] | None:
    """Return a read-only guardrail preview for target-affecting planned calls.

    Native model/tool-call planning must not call registry.run(...) just to label
    a plan: that would write evidence rows, queue approvals, or dispatch tools.
    This helper mirrors the command request shape and evaluates guardrails only,
    so plan-only transcripts can show whether applying a target-affecting call
    would allow, confirm-gate, or block before any side effects are possible.
    """

    if tool not in _TARGET_AFFECTING_PLANNED_TOOLS:
        return None
    if not isinstance(args, dict):
        return {"status": "error", "error": "tool args were not an object"}
    try:
        request = ActionRequest(
            target=str(args.get("target", "")),
            action_type=str(args.get("action_type") or args.get("type") or "host"),
            purpose=str(args.get("purpose", "")),
            command=args.get("command"),
            actor=str(args.get("actor", "operator")),
        )
        decision = registry.harness.guardrails.evaluate(roe, request)
        data = _redact_runtime_value(decision.to_dict())
        if not isinstance(data, dict):
            return {"status": "error", "error": "guardrail preview could not be serialized"}
        return {
            "status": data.get("status"),
            "reasons": list(data.get("reasons") or [])[:6],
            "required_confirmations": list(data.get("required_confirmations") or [])[:6],
            "safer_alternatives": list(data.get("safer_alternatives") or [])[:6],
            "redacted_command": data.get("redacted_command"),
            "no_target_activity": True,
            "evidence_written": False,
            "approval_queued": False,
        }
    except Exception as exc:  # defensive preview boundary; execution path still revalidates
        return {"status": "error", "error": redact_secrets(str(exc)) or "guardrail preview failed"}


def _model_planned_call_metadata(item: dict[str, Any]) -> dict[str, Any]:
    """Extract bounded, redacted per-call native planner provenance.

    Provider-native tool calls often carry an opaque call id that operators need
    to correlate plan previews, applied results, and feedback-loop transcripts.
    Preserve only that correlation metadata, not arbitrary raw provider payloads
    or model-controlled blobs.
    """

    metadata: dict[str, Any] = {}
    raw = item.get("metadata") if isinstance(item, dict) else None
    if isinstance(raw, dict):
        for key in ("provider_tool_call_id", "tool_call_id", "call_id", "id"):
            value = raw.get(key)
            if value not in (None, ""):
                metadata["provider_tool_call_id"] = _bounded_metadata_string(value, 200)
                break
        source = raw.get("native_tool_call_source") or raw.get("source")
        if source not in (None, ""):
            metadata["native_tool_call_source"] = _bounded_metadata_string(source, 120)
        if "native_tool_call_index" in raw:
            index = _safe_int(raw.get("native_tool_call_index"))
            if index is not None:
                metadata["native_tool_call_index"] = index
    for key in ("provider_tool_call_id", "tool_call_id", "call_id", "id"):
        value = item.get(key)
        if value not in (None, ""):
            metadata["provider_tool_call_id"] = _bounded_metadata_string(value, 200)
            break
    source = item.get("native_tool_call_source") or item.get("source")
    if source not in (None, ""):
        metadata["native_tool_call_source"] = _bounded_metadata_string(source, 120)
    if "native_tool_call_index" in item:
        index = _safe_int(item.get("native_tool_call_index"))
        if index is not None:
            metadata["native_tool_call_index"] = index
    return _redact_runtime_value(metadata) if metadata else {}


def _bounded_metadata_string(value: Any, limit: int) -> str:
    text = redact_secrets(str(value)) or ""
    return text[:limit]


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value.strip())
    return None


def _model_plan_metadata(response: Any) -> dict[str, Any]:
    """Return redacted model-planner metadata safe for auto transcripts.

    This intentionally whitelists provider/fallback/native-tool-call metadata
    rather than embedding an adapter's arbitrary raw response.  Base URLs,
    request headers, prompt bodies, and provider payloads stay out of transcripts.
    """

    raw = response.raw if isinstance(getattr(response, "raw", None), dict) else {}
    metadata: dict[str, Any] = {"planner": "model", "provider": str(getattr(response, "provider", ""))}
    for key in (
        "selected_provider",
        "tool_plan_fallback",
        "native_tool_calls",
        "native_tool_call_count",
        "rejected_native_tool_call_count",
        "model",
    ):
        if key in raw:
            metadata[key] = raw.get(key)
    attempts = raw.get("fallback_attempts")
    if isinstance(attempts, list):
        safe_attempts = []
        for item in attempts[:8]:
            if not isinstance(item, dict):
                continue
            safe_attempts.append({
                "provider": str(item.get("provider") or ""),
                "error": redact_secrets(str(item.get("error") or "")) or "",
            })
        metadata["fallback_attempts"] = safe_attempts
    return _redact_runtime_value(metadata)


def _merge_plan_metadata(base: dict[str, Any] | None, extra: dict[str, Any] | None) -> dict[str, Any]:
    if not base:
        return dict(extra or {})
    merged = dict(base)
    if extra:
        merged["model_planner"] = dict(extra)
    return merged



def _runtime_metadata(config: AgentRuntimeConfig) -> dict[str, Any]:
    bridge_keys = {
        "enabled",
        "token_env",
        "bot_token_env",
        "app_token_env",
        "allowed_channel_ids",
        "allowed_user_ids",
        "command_prefix",
        "mention_required",
        "allow_all",
        "allow_approval_actions",
        "ignore_bots",
        "max_response_chars",
        "max_message_chars",
    }
    bridges: dict[str, dict[str, Any]] = {}
    for name, data in (config.bridges or {}).items():
        if isinstance(data, dict):
            try:
                normalized = BridgeConfig.from_dict(str(name), data).to_dict()
            except ValueError:
                normalized = dict(data)
            bridges[str(name)] = {key: normalized.get(key) for key in bridge_keys if key in normalized}
    providers = []
    for provider in config.model_providers:
        if isinstance(provider, dict):
            providers.append({
                "provider": provider.get("provider"),
                "model": provider.get("model"),
                "key_env": provider.get("key_env"),
                "base_url": _redact_url_userinfo(str(provider.get("base_url") or "")),
            })
    return {
        "config_path": config.config_path,
        "db_path": config.db_path,
        "workspace_dir": config.workspace_dir,
        "plugin_dirs": list(config.plugin_dirs),
        "skill_dirs": list(config.skill_dirs),
        "preload_skills": list(config.preload_skills),
        "tool_timeout": config.tool_timeout,
        "auto_execute_natural": config.auto_execute_natural,
        "auto_model_planning": config.auto_model_planning,
        "max_auto_steps": config.max_auto_steps,
        "provider": config.provider,
        "model": config.model,
        "key_env": config.key_env,
        "base_url": _redact_url_userinfo(config.base_url or ""),
        "model_providers": providers,
        "bridges": bridges,
        "native_tool_calling": {
            "milestone": "native_model_tool_calling_loop",
            "milestone_contract": dict(_NATIVE_TOOL_CALL_MILESTONE_CONTRACT),
            "milestone_contract_complete": all(_NATIVE_TOOL_CALL_MILESTONE_CONTRACT.values()),
            "model_planning_enabled": bool(config.auto_model_planning),
            "wrapped_json_plan_extraction": True,
            "natural_auto_execute_enabled": bool(config.auto_execute_natural),
            "max_auto_steps": int(config.max_auto_steps),
            "max_model_tool_calls_per_step": _MAX_NATIVE_MODEL_TOOL_CALLS_PER_STEP,
            "per_step_model_tool_call_budget_enforced": True,
            "plan_only_default": True,
            "execution_requires_operator_execute_true": True,
            "per_step_execution_ledger_delta": True,
            "per_step_planner_trace": True,
            "one_shot_planner_trace": True,
            "planner_trace_redacted": True,
            "followup_feedback_prompt_redacted": True,
            "execution_summary_contract": True,
            "provider_tool_call_id_provenance": True,
            "transcript_provider_call_provenance": True,
            "max_steps_budget_stop_enforced": True,
            "duplicate_plan_stop_enforced": True,
            "partial_duplicate_plan_stop_enforced": True,
            "same_step_duplicate_plan_stop_enforced": True,
            "model_error_stop_enforced": True,
            "invalid_plan_stop_enforced": True,
            "terminal_no_tool_no_dispatch_step": True,
            "provider_native_tool_call_variants": [
                "openai_tool_calls",
                "openai_responses_api",
                "single_top_level_tool_call",
                "singular_tool_call_alias",
                "camel_case_tool_call_alias",
                "choice_delta_tool_calls",
                "choice_delta_tool_call_fragments",
                "choice_delta_function_call_fragments",
                "choice_delta_tool_use_fragments",
                "tool_calls_nested_functionCall",
                "tool_calls_nested_toolUse",
                "flat_tool_calls",
                "content_block_tool_use",
                "content_block_toolUse",
                "content_block_function_call",
                "content_block_functionCall",
                "content_parts_toolUse",
                "content_parts_functionCall",
                "single_content_block_tool_call",
                "top_level_content_block_tool_use",
                "responses_output_function_call",
                "single_responses_output_function_call",
                "responses_output_nested_function",
                "responses_output_nested_functionCall",
                "responses_message_tool_calls",
                "responses_message_toolCalls",
                "responses_message_tool_call",
                "responses_message_toolCall",
                "responses_message_tool_use",
                "responses_message_toolUse",
                "responses_message_tool_uses",
                "responses_message_toolUses",
                "responses_message_function_call",
                "responses_message_functionCall",
                "responses_message_functionCalls",
                "responses_message_function_calls",
                "responses_output_message_tool_calls",
                "responses_output_message_toolCalls",
                "responses_output_message_tool_call",
                "responses_output_message_toolCall",
                "responses_output_message_tool_use",
                "responses_output_message_toolUse",
                "responses_output_message_tool_uses",
                "responses_output_message_toolUses",
                "responses_output_message_functionCall",
                "responses_output_message_functionCalls",
                "responses_output_message_function_calls",
                "responses_output_message_content_functionCall",
                "responses_output_message_content_parts_functionCall",
                "responses_output_message_typeless_wrapper",
                "responses_output_message_typeless_direct",
                "responses_output_message_typeless_direct_tool_calls",
                "responses_output_message_typeless_direct_toolCalls",
                "responses_output_message_typeless_direct_tool_call",
                "responses_output_message_typeless_direct_toolCall",
                "responses_output_message_typeless_direct_tool_use",
                "responses_output_message_typeless_direct_toolUse",
                "responses_output_message_typeless_direct_tool_uses",
                "responses_output_message_typeless_direct_toolUses",
                "responses_output_message_typeless_direct_function_call",
                "responses_output_message_typeless_direct_functionCall",
                "responses_output_message_typeless_direct_functionCalls",
                "responses_output_message_typeless_direct_function_calls",
                "responses_output_message_typeless_direct_content_parts_functionCall",
                "responses_message_content_function_call",
                "responses_message_content_functionCall",
                "responses_message_content_parts_functionCall",
                "responses_message_content_tool_use",
                "candidate_function_call",
                "single_candidate_part_function_call",
                "root_message_tool_calls",
                "root_message_toolCalls",
                "root_message_tool_call",
                "root_message_toolCall",
                "root_message_tool_use",
                "root_message_toolUse",
                "root_message_tool_uses",
                "root_message_toolUses",
                "root_message_functionCall",
                "root_message_functionCalls",
                "root_message_function_calls",
                "root_message_content_functionCall",
                "root_message_content_parts_functionCall",
                "root_functionCall",
                "root_functionCalls",
                "root_functionCalls_nested_functionCall",
                "root_function_calls",
                "root_function_calls_nested_functionCall",
                "root_tool_use",
                "root_toolUse",
                "root_tool_uses",
                "root_toolUses",
                "message_tool_use",
                "message_toolUse",
                "message_tool_uses",
                "message_toolUses",
                "message_functionCall",
                "message_functionCalls",
                "message_function_calls",
                "message_function_calls_nested_functionCall",
                "legacy_function_call",
            ],
            "provider_tool_call_id_aliases": ["id", "call_id", "tool_call_id", "tool_use_id", "callId", "toolCallId", "toolUseId"],
            "provider_tool_name_aliases": ["name", "tool", "tool_name", "toolName", "function_name", "functionName"],
            "provider_argument_aliases": [
                "arguments_json",
                "argumentsJson",
                "args_json",
                "argsJson",
                "input_json",
                "inputJson",
                "parameters_json",
                "parametersJson",
                "params_json",
                "paramsJson",
            ],
            "provider_tool_result_echo_ignored": True,
            "provider_tool_result_block_types_ignored": [
                "tool_result",
                "function_result",
                "function_call_output",
                "functionResponse",
                "function_response",
            ],
            "provider_unsupported_tool_call_types_rejected": [
                "custom_tool_call",
                "computer_call",
                "web_search_call",
                "code_interpreter_call",
                "server_tool_use",
                "mcp_tool_use",
            ],
            "approval_control_tools_hidden_from_model": sorted(_MODEL_PLANNER_APPROVAL_ACTION_TOOLS),
            "execution_capable_tools": sorted(_EXECUTION_CAPABLE_TOOLS),
            "target_affecting_tools": sorted(_TARGET_AFFECTING_PLANNED_TOOLS),
            "transcript_dirs": ["agent/auto-plans", "agent/auto-loops"],
        },
    }


def _redact_url_userinfo(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"(https?://)[^/@\s]+@", r"\1<redacted>@", value)


def _render_chat_response(response: str, *, message: str, platform: str, runtime: OffSecAgentRuntime) -> str:
    command = _command_name(message)
    if command in {"status"}:
        data = _extract_data_json(response)
        if isinstance(data, dict):
            return _render_status_chat(data)
    if command in {"tools"}:
        return _render_tools_chat(runtime)
    if command in {"approvals"}:
        data = _extract_data_json(response)
        if isinstance(data, dict):
            return _render_approvals_chat(data)
    if command in {"tasks", "task-list"}:
        data = _extract_data_json(response)
        if isinstance(data, dict):
            return _render_tasks_chat(data)
    if command in {"findings"}:
        data = _extract_data_json(response)
        if isinstance(data, dict):
            return _render_findings_chat(data)
    if command in {"tool-runs", "processes"}:
        data = _extract_data_json(response)
        if isinstance(data, dict):
            return _render_count_list_chat(response, data, command)
    if response.startswith("Auto plan (no tools executed):"):
        return _render_auto_plan_chat(response)
    if response.startswith("Auto plan applied:"):
        return _render_auto_apply_chat(response)
    if response.startswith("Auto loop completed:"):
        return _render_auto_loop_chat(response)
    parsed = _parse_formatted_tool_response(response)
    if parsed and command not in {"schemas", "tool-schema", "tool-schemas", "skill", "load-skill"}:
        rendered = _render_generic_tool_chat(parsed)
        if rendered:
            return rendered
    return _strip_natural_boilerplate(response)


def _command_name(message: str) -> str:
    try:
        tokens = shlex.split(message.strip())
    except ValueError:
        return ""
    if not tokens or not tokens[0].startswith("/"):
        return ""
    return tokens[0][1:].strip().lower()


def _extract_data_json(response: str) -> Any:
    marker = "\nData:\n"
    if marker not in response:
        return None
    raw = response.split(marker, 1)[1].strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _parse_formatted_tool_response(response: str) -> dict[str, Any] | None:
    lines = response.splitlines()
    if not lines:
        return None
    match = re.match(r"^\[([^\]]+)\]\s*(.*)$", lines[0])
    if not match:
        return None
    artifacts: list[str] = []
    in_artifacts = False
    for line in lines[1:]:
        if line == "Data:":
            break
        if line == "Artifacts:":
            in_artifacts = True
            continue
        if in_artifacts and line.startswith("- "):
            artifacts.append(line[2:])
    return {"status": match.group(1), "message": match.group(2), "data": _extract_data_json(response), "artifacts": artifacts}


def _render_status_chat(data: dict[str, Any]) -> str:
    engagement = data.get("engagement") if isinstance(data.get("engagement"), dict) else {}
    policy = data.get("policy") if isinstance(data.get("policy"), dict) else {}
    scope = _short_list(engagement.get("in_scope_targets") or [], limit=4)
    lines = [
        f"Phobos is up for **{engagement.get('name') or 'this engagement'}**.",
        f"- Safety: `{engagement.get('safety_mode') or 'unknown'}` | Scope: {scope or 'not set'}",
        f"- Open: {data.get('open_tasks', 0)} task(s), {data.get('pending_approvals', 0)} approval(s), {data.get('open_findings', 0)} finding(s)",
        f"- Tools: {data.get('tools', 0)} registered | Evidence: `{data.get('evidence_root', 'not set')}`",
    ]
    confirm = _short_list(policy.get("confirm_tools") or [], limit=4)
    blocked = _short_list(policy.get("blocked_tools") or [], limit=4)
    if confirm or blocked:
        lines.append(f"- Runtime policy: confirm {confirm or 'none'}; blocked {blocked or 'none'}")
    return "\n".join(lines)


def _render_tools_chat(runtime: OffSecAgentRuntime) -> str:
    specs = runtime.registry.specs()
    lines = [
        f"{len(specs)} Phobos tools are registered. Useful starting points:",
        "- `/status` — engagement, scope, approvals, tasks, findings.",
        "- `/nmap target=<host> ports=80,443 execute=false` — safe service-enum wrapper.",
        "- `/httpx url=<url> execute=false` / `/nuclei url=<url> template=<path> execute=false` — web evidence wrappers.",
        "- `/finding-create ...`, `/finding-review id=<id>`, `/finding-bundle id=<id>`, and `/findings status=all` — finding lifecycle, QA, and handoff packaging.",
        "- `/timeline`, `/manifest`, and `/closeout` — redacted chronology, SHA-256 inventory, and closeout readiness review for handoff/report reconstruction.",
        "- `/briefing` — operator handoff with tasks, approvals, evidence, and context.",
        "- `/approvals` — pending confirm-gated actions.",
        "Use `/schemas name=<tool>` for exact arguments. Target-affecting tools still go through ROE and runtime policy.",
    ]
    return "\n".join(lines)


def _render_approvals_chat(data: dict[str, Any]) -> str:
    approvals = data.get("approvals") if isinstance(data.get("approvals"), list) else []
    if not approvals:
        return "No pending approvals."
    lines = [f"{len(approvals)} approval(s) pending:"]
    for approval in approvals[:8]:
        lines.append(f"- #{approval.get('id')} `{approval.get('tool_name')}` requested {approval.get('requested_at', '')}")
    if len(approvals) > 8:
        lines.append(f"- ...and {len(approvals) - 8} more.")
    lines.append("Use `/approval id=<id>` to inspect redacted detail. Use the local gateway/CLI for approvals unless this bridge was deliberately enabled for `/approve` and `/deny`.")
    return "\n".join(lines)


def _render_tasks_chat(data: dict[str, Any]) -> str:
    tasks = data.get("tasks") if isinstance(data.get("tasks"), list) else []
    if not tasks:
        return "No tasks are recorded for this Phobos session."
    lines = [f"{len(tasks)} task(s):"]
    for task in tasks[:10]:
        content = redact_secrets(str(task.get("content", ""))).replace("\n", " ")[:160]
        lines.append(f"- [{task.get('status')}] #{task.get('id')} {content}")
    if len(tasks) > 10:
        lines.append(f"- ...and {len(tasks) - 10} more.")
    return "\n".join(lines)


def _render_findings_chat(data: dict[str, Any]) -> str:
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    if not findings:
        return "No findings are recorded yet. Use `/finding-create ...` when evidence is ready."
    lines = [f"{len(findings)} finding(s):"]
    for finding in findings[:10]:
        title = redact_secrets(str(finding.get("title", ""))).replace("\n", " ")[:140]
        lines.append(f"- [{finding.get('status')}] #{finding.get('id')} {finding.get('severity', '')} — {title}")
    if len(findings) > 10:
        lines.append(f"- ...and {len(findings) - 10} more.")
    return "\n".join(lines)


def _render_count_list_chat(response: str, data: dict[str, Any], command: str) -> str:
    parsed = _parse_formatted_tool_response(response)
    label = "tool run" if command == "tool-runs" else "process"
    rows = data.get("runs") if command == "tool-runs" else data.get("processes")
    rows = rows if isinstance(rows, list) else []
    if not rows:
        return f"No {label}s recorded."
    lines = [parsed.get("message") if parsed else f"Found {len(rows)} {label}(s)."]
    for row in rows[:8]:
        if command == "tool-runs":
            lines.append(f"- #{row.get('id')} `{row.get('tool_name')}` {row.get('status')} target={row.get('target', '')}")
        else:
            lines.append(f"- #{row.get('id')} `{row.get('status')}` {redact_secrets(str(row.get('purpose', '')))[:100]}")
    if len(rows) > 8:
        lines.append(f"- ...and {len(rows) - 8} more.")
    return "\n".join(lines)


def _render_auto_plan_chat(response: str) -> str:
    raw = response.split("\n", 1)[1] if "\n" in response else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return response
    calls = data.get("tool_calls") if isinstance(data.get("tool_calls"), list) else []
    lines = ["I drafted a guarded plan. No tools ran."]
    summary = str(data.get("summary") or "").strip()
    if summary:
        lines.append(summary)
    for call in calls[:8]:
        lines.append(f"- `{call.get('tool')}` — {call.get('reason', 'planned step')}")
    if calls:
        lines.append("Run it with `/auto apply=true ...`; add `execute=true` only when guarded command execution is intended.")
    return "\n".join(lines)


def _render_auto_apply_chat(response: str) -> str:
    raw = response.split("\n", 1)[1] if "\n" in response else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return response
    calls = data.get("tool_calls") if isinstance(data.get("tool_calls"), list) else []
    results = data.get("results") if isinstance(data.get("results"), list) else []
    ledger = data.get("execution_ledger") if isinstance(data.get("execution_ledger"), list) else []
    planned = [str(call.get("tool") or "").strip() for call in calls if isinstance(call, dict) and str(call.get("tool") or "").strip()]
    counts: dict[str, int] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        raw_result = item.get("result")
        result_obj = raw_result if isinstance(raw_result, dict) else {}
        status = str(result_obj.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    lines = ["Auto plan applied through the guarded registry boundary."]
    if planned:
        lines.append("- Planned tools: " + ", ".join(f"`{tool}`" for tool in planned[:8]))
    if counts:
        lines.append("- Actual results: " + ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))
    execution_summary = data.get("execution_summary") if isinstance(data.get("execution_summary"), dict) else {}
    if execution_summary:
        lines.append(
            "- Execution ledger summary: "
            f"actual_command_or_process_activity={execution_summary.get('actual_command_or_process_activity', 0)}, "
            f"approval_queued={execution_summary.get('approval_queued', 0)}, "
            f"blocked={execution_summary.get('blocked', 0)}, dry_run={execution_summary.get('dry_run', 0)}, "
            f"claimable_tool_runs={execution_summary.get('claimable_tool_runs', 0)}, "
            f"claimable_command_executions={execution_summary.get('claimable_command_executions', 0)}"
        )
    elif ledger:
        actual_activity = sum(1 for item in ledger if isinstance(item, dict) and item.get("actual_command_or_process_activity") is True)
        queued = sum(1 for item in ledger if isinstance(item, dict) and item.get("approval_queued") is True)
        blocked = sum(1 for item in ledger if isinstance(item, dict) and item.get("blocked") is True)
        dry_runs = sum(1 for item in ledger if isinstance(item, dict) and item.get("dry_run") is True)
        lines.append(f"- Execution ledger: actual_command_or_process_activity={actual_activity}, approval_queued={queued}, blocked={blocked}, dry_run={dry_runs}")
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    if data.get("transcript_artifact_written") and artifacts:
        md_path = artifacts.get("markdown") or artifacts.get("json")
        if md_path:
            lines.append(f"- Redacted transcript: `{md_path}`")
    if data.get("artifact_error"):
        lines.append(f"- Transcript artifact warning: {data.get('artifact_error')}")
    lines.append("No confirm-gated, blocked, or dry-run action is treated as executed unless the registry result proves it ran.")
    return "\n".join(lines)


def _render_auto_loop_chat(response: str) -> str:
    raw = response.split("\n", 1)[1] if "\n" in response else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return response
    steps = data.get("steps") if isinstance(data.get("steps"), list) else []
    ledger = data.get("execution_ledger") if isinstance(data.get("execution_ledger"), list) else []
    counts: dict[str, int] = {}
    planned: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        plan = step.get("plan") if isinstance(step.get("plan"), dict) else {}
        plan_calls = plan.get("tool_calls") if isinstance(plan, dict) else []
        if isinstance(plan_calls, list):
            for call in plan_calls:
                if not isinstance(call, dict):
                    continue
                tool = str(call.get("tool") or "").strip()
                if tool and tool not in planned:
                    planned.append(tool)
        result_items = step.get("results")
        if isinstance(result_items, list):
            for item in result_items:
                result_obj = item.get("result") if isinstance(item, dict) else None
                result = result_obj if isinstance(result_obj, dict) else {}
                status = str(result.get("status") or "unknown")
                counts[status] = counts.get(status, 0) + 1
    stop_reason = str(data.get("stop_reason") or "unknown")
    executed = int(data.get("steps_executed") or 0)
    requested = int(data.get("steps_requested") or executed or 0)
    lines = [f"Native tool loop stopped: `{stop_reason}` after {executed}/{requested} applied step(s)."]
    if data.get("max_steps_budget_exhausted") is True:
        lines.append("- Max-step budget exhausted; review the redacted transcript before rerunning with a larger explicit steps budget.")
    next_step = str(data.get("next_step") or "").strip()
    if next_step and data.get("max_steps_budget_exhausted") is not True:
        lines.append(f"- Next: {next_step}")
    if planned:
        lines.append("- Planned tools: " + ", ".join(f"`{tool}`" for tool in planned[:8]))
    planner_trace = data.get("planner_trace") if isinstance(data.get("planner_trace"), list) else []
    providers = []
    for item in planner_trace:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider") or item.get("selected_provider") or "").strip()
        if provider and provider not in providers:
            providers.append(provider)
    if providers:
        lines.append("- Planner trace: " + ", ".join(f"`{provider}`" for provider in providers[:4]))
    if counts:
        lines.append("- Actual results: " + ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))
    execution_summary = data.get("execution_summary") if isinstance(data.get("execution_summary"), dict) else {}
    if execution_summary:
        lines.append(
            "- Execution ledger summary: "
            f"actual_command_or_process_activity={execution_summary.get('actual_command_or_process_activity', 0)}, "
            f"approval_queued={execution_summary.get('approval_queued', 0)}, "
            f"blocked={execution_summary.get('blocked', 0)}, dry_run={execution_summary.get('dry_run', 0)}, "
            f"claimable_tool_runs={execution_summary.get('claimable_tool_runs', 0)}, "
            f"claimable_command_executions={execution_summary.get('claimable_command_executions', 0)}"
        )
    elif ledger:
        actual_activity = sum(1 for item in ledger if isinstance(item, dict) and item.get("actual_command_or_process_activity") is True)
        queued = sum(1 for item in ledger if isinstance(item, dict) and item.get("approval_queued") is True)
        blocked = sum(1 for item in ledger if isinstance(item, dict) and item.get("blocked") is True)
        dry_runs = sum(1 for item in ledger if isinstance(item, dict) and item.get("dry_run") is True)
        lines.append(f"- Execution ledger: actual_command_or_process_activity={actual_activity}, approval_queued={queued}, blocked={blocked}, dry_run={dry_runs}")
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    if data.get("transcript_artifact_written") and artifacts:
        md_path = artifacts.get("markdown") or artifacts.get("json")
        if md_path:
            lines.append(f"- Redacted transcript: `{md_path}`")
    if data.get("artifact_error"):
        lines.append(f"- Transcript artifact warning: {data.get('artifact_error')}")
    lines.append("No confirm-gated, blocked, dry-run, handler-error, or no-dispatch terminal step is treated as executed unless the registry returned an executed result.")
    return "\n".join(lines)


def _render_generic_tool_chat(parsed: dict[str, Any]) -> str:
    status = str(parsed.get("status") or "")
    message = str(parsed.get("message") or "")
    data = parsed.get("data") if isinstance(parsed.get("data"), dict) else {}
    prefix = {
        "ok": "Done",
        "executed": "Executed",
        "parsed": "Parsed",
        "dry_run": "Allowed but not executed",
        "needs_approval": "Needs approval",
        "blocked": "Blocked",
        "error": "Error",
    }.get(status, status or "Result")
    lines = [f"{prefix}: {message}".strip()]
    decision = data.get("decision") if isinstance(data.get("decision"), dict) else None
    if decision:
        reasons = decision.get("reasons") if isinstance(decision.get("reasons"), list) else []
        alternatives = decision.get("safer_alternatives") if isinstance(decision.get("safer_alternatives"), list) else []
        for reason in reasons[:3]:
            lines.append(f"- Reason: {reason}")
        for alt in alternatives[:2]:
            lines.append(f"- Safer path: {alt}")
    if data.get("approval_id"):
        lines.append(f"- Approval ID: {data.get('approval_id')}")
    if data.get("answer"):
        lines.append(str(data.get("answer"))[:1800])
    artifacts = parsed.get("artifacts") if isinstance(parsed.get("artifacts"), list) else []
    if artifacts:
        lines.append("Artifacts: " + "; ".join(str(item) for item in artifacts[:4]))
    return "\n".join(line for line in lines if line)


def _short_list(values: Any, *, limit: int = 4) -> str:
    if not isinstance(values, list | tuple):
        return ""
    shown = [str(item) for item in values[:limit] if str(item)]
    suffix = f", +{len(values) - limit} more" if len(values) > limit else ""
    return ", ".join(shown) + suffix


def _strip_natural_boilerplate(text: str) -> str:
    cleaned = text.strip()
    prefixes = [
        "Phobos Agent response (no tool executed):",
        "Phobos Agent response:",
    ]
    for prefix in prefixes:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].lstrip()
    footer = "Use /auto apply=true for guarded natural-language tool planning, or /tools for explicit actions. Commands stay ROE-gated, non-destructive by default, and evidence-logged."
    cleaned = cleaned.replace("\n\n" + footer, "").replace(footer, "").strip()
    return cleaned or text


_EXECUTION_INTENT_RE = re.compile(r"\b(run|execute|scan|test|enumerate|probe|launch|start|nmap|httpx|nuclei|ffuf|curl|spray|brute\s*force|exploit)\b", re.IGNORECASE)


def _looks_like_execution_request(message: str) -> bool:
    return bool(_EXECUTION_INTENT_RE.search(message))


def _mentions_no_execution(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in ["didn't run", "did not run", "no tools ran", "nothing was executed", "not executed"])


def _extract_json_object(text: str) -> dict[str, Any]:
    """Extract the first plausible model tool-plan JSON object.

    Real model adapters do not always obey the ``Return ONLY JSON`` prompt: some
    wrap the object in a fenced ``json`` block, add a prose preface with brace
    examples, or append trailing notes.  Native tool-call planning still needs a
    strict local boundary, so scan bounded text for balanced JSON objects,
    prefer objects that actually look like Phobos tool plans, and never dispatch
    anything until the normal schema/runtime-policy/ROE validation path accepts
    the parsed plan.
    """

    if not isinstance(text, str):
        raise ValueError("model did not return text containing a JSON object")
    parsed_objects: list[dict[str, Any]] = []
    last_error = "model did not return a JSON object"
    for candidate in _json_plan_candidate_texts(text):
        for raw_object in _balanced_json_object_strings(candidate):
            try:
                parsed = json.loads(raw_object)
            except json.JSONDecodeError as exc:
                last_error = exc.msg
                continue
            if isinstance(parsed, dict):
                parsed_objects.append(parsed)
            else:
                last_error = "model JSON response was not an object"
    if not parsed_objects:
        raise ValueError(last_error)
    for parsed in parsed_objects:
        if isinstance(parsed.get("tool_calls"), list):
            return parsed
    for parsed in parsed_objects:
        if any(key in parsed for key in ("summary", "warnings", "rejected_tool_calls")):
            return parsed
    return parsed_objects[0]


def _json_plan_candidate_texts(text: str) -> list[str]:
    candidates: list[str] = []
    for match in re.finditer(r"```[A-Za-z0-9_-]*\s*(.*?)```", text, flags=re.DOTALL):
        block = match.group(1).strip()
        if block and "{" in block:
            candidates.append(block)
    stripped = text.strip()
    if stripped and stripped not in candidates:
        candidates.append(stripped)
    return candidates


def _balanced_json_object_strings(text: str) -> list[str]:
    objects: list[str] = []
    length = len(text)
    index = 0
    while index < length:
        if text[index] != "{":
            index += 1
            continue
        depth = 0
        in_string = False
        escaped = False
        end_index: int | None = None
        for cursor in range(index, length):
            char = text[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_index = cursor + 1
                    break
        if end_index is None:
            index += 1
            continue
        objects.append(text[index:end_index])
        index = end_index
    return objects


def _slash_bool_arg(args: dict[str, Any], name: str, default: bool) -> tuple[bool, str | None]:
    """Parse safety-critical slash booleans without Python truthiness.

    Native /auto and /auto-loop flags control model planning and command/process
    execution.  Strings such as ``off`` or ``maybe`` must never become truthy
    just because they are non-empty.
    """

    if name not in args or args.get(name) is None:
        return bool(default), None
    value = args.get(name)
    if isinstance(value, bool):
        return value, None
    if isinstance(value, int) and not isinstance(value, bool):
        if value in {0, 1}:
            return bool(value), None
        return bool(default), f"{name} must be a boolean."
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "on", "1"}:
            return True, None
        if lowered in {"false", "no", "off", "0"}:
            return False, None
    return bool(default), f"{name} must be a boolean."


def _slash_int_arg(args: dict[str, Any], name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> tuple[int, str | None]:
    """Parse bounded slash integers with clean operator errors."""

    if name not in args or args.get(name) is None:
        value = int(default)
    else:
        raw = args.get(name)
        if isinstance(raw, bool):
            return int(default), f"{name} must be an integer."
        if isinstance(raw, int):
            value = raw
        elif isinstance(raw, str) and re.fullmatch(r"[+-]?\d+", raw.strip()):
            value = int(raw.strip())
        else:
            return int(default), f"{name} must be an integer."
    if minimum is not None and value < minimum:
        return value, f"{name} must be at least {minimum}."
    if maximum is not None and value > maximum:
        return value, f"{name} must be at most {maximum}."
    return value, None


def _parse_key_values(tokens: list[str]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    positional: list[str] = []
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            args[key.replace("-", "_")] = _coerce(value)
        else:
            positional.append(token)
    if positional:
        # Helpful defaults for terse forms: /remember key value...; /recall query...; /approve 1
        args.setdefault("_positional", positional)
        if "id" not in args and positional[0].isdigit():
            args["id"] = int(positional[0])
        if "query" not in args:
            args["query"] = " ".join(positional)
        if "finding" not in args:
            args["finding"] = " ".join(positional)
        if len(positional) >= 2 and "key" not in args and "value" not in args:
            args["key"] = positional[0]
            args["value"] = " ".join(positional[1:])
    return args


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered.isdigit():
        return int(lowered)
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _planned_call_execution_ledger(call: PlannedToolCall, result: ToolResult, *, step: int | None = None) -> dict[str, Any]:
    """Summarize what actually happened after applying a planned tool call.

    Native model/tool-call loops must not overclaim execution.  This ledger is a
    compact, redacted contract for transcripts and chat summaries: dry-runs,
    guardrail/policy approvals, and blocked calls are explicitly marked as not
    target activity even though the registry boundary was invoked to make that
    decision.
    """

    args = call.args if isinstance(call.args, dict) else {}
    data = result.data if isinstance(result.data, dict) else {}
    decision = data.get("decision") if isinstance(data.get("decision"), dict) else {}
    planned_validation = call.validation if isinstance(call.validation, dict) else {}
    call_metadata = call.metadata if isinstance(call.metadata, dict) else {}
    guardrail_status = decision.get("status") if isinstance(decision, dict) else None
    if not guardrail_status:
        guardrail_status = planned_validation.get("guardrail_status")
    runtime_policy = str(planned_validation.get("runtime_policy") or "unknown")
    status = str(result.status or "unknown")
    tool = str(call.tool or "")
    execution_requested = bool(args.get("execute", False)) if tool in _EXECUTION_CAPABLE_TOOLS else False
    actual_command_or_process_activity = bool(tool in _EXECUTION_CAPABLE_TOOLS and execution_requested and status in _ACTUAL_EXECUTION_STATUSES)
    approval_queued = bool(status == "needs_approval" and data.get("approval_id"))
    blocked = status == "blocked"
    dry_run = status == "dry_run"
    runtime_policy_enforced = bool((runtime_policy == "confirm_required" and approval_queued) or (runtime_policy == "blocked" and blocked))
    if actual_command_or_process_activity:
        execution_state = "executed_or_started"
    elif approval_queued:
        execution_state = "queued_for_approval"
    elif blocked:
        execution_state = "blocked"
    elif dry_run:
        execution_state = "dry_run_not_executed"
    elif status == "error":
        execution_state = "handler_error_no_target_execution_claimed"
    elif status in {"ok", "parsed", "completed", "approved", "denied"}:
        execution_state = "completed_without_command_execution"
    else:
        execution_state = "completed_status_not_command_execution"
    tool_completed_or_executed = bool(status in {"ok", "parsed", "completed"} or actual_command_or_process_activity)
    ledger: dict[str, Any] = {
        "tool": tool,
        "result_status": status,
        "execution_state": execution_state,
        "dispatch_attempted": True,
        "target_affecting_tool": tool in _TARGET_AFFECTING_PLANNED_TOOLS,
        "command_execution_requested": execution_requested,
        "actual_command_or_process_activity": actual_command_or_process_activity,
        "approval_queued": approval_queued,
        "blocked": blocked,
        "dry_run": dry_run,
        "runtime_policy": runtime_policy,
        "runtime_policy_enforced": runtime_policy_enforced,
        "safe_to_claim_tool_ran": tool_completed_or_executed,
        "safe_to_claim_command_executed": actual_command_or_process_activity,
    }
    provider_tool_call_id = call_metadata.get("provider_tool_call_id") or call_metadata.get("tool_call_id") or call_metadata.get("call_id")
    if provider_tool_call_id not in (None, ""):
        ledger["provider_tool_call_id"] = _bounded_metadata_string(provider_tool_call_id, 200)
    native_tool_call_source = call_metadata.get("native_tool_call_source") or call_metadata.get("source")
    if native_tool_call_source not in (None, ""):
        ledger["native_tool_call_source"] = _bounded_metadata_string(native_tool_call_source, 120)
    if "native_tool_call_index" in call_metadata:
        native_index = _safe_int(call_metadata.get("native_tool_call_index"))
        if native_index is not None:
            ledger["native_tool_call_index"] = native_index
    if step is not None:
        ledger["step"] = step
    if data.get("approval_id"):
        ledger["approval_id"] = data.get("approval_id")
    if guardrail_status:
        ledger["guardrail_status"] = guardrail_status
    if result.artifacts:
        ledger["artifacts"] = result.artifacts
    return _redact_runtime_value(ledger)


def _native_execution_summary(ledger: Any) -> dict[str, Any]:
    """Return machine-readable execution-claim counts for native /auto payloads.

    The execution ledger remains the authoritative per-call record.  This
    compact summary gives chat, gateway, and transcript consumers a stable way
    to distinguish actual command/process activity from dry-runs, approval
    queues, blocks, handler errors, and local-only registry completions without
    scanning raw results or overclaiming what happened.
    """

    entries = [item for item in ledger if isinstance(item, dict)] if isinstance(ledger, list) else []

    def count_flag(name: str) -> int:
        return sum(1 for item in entries if item.get(name) is True)

    def count_state(prefix: str) -> int:
        return sum(1 for item in entries if str(item.get("execution_state") or "").startswith(prefix))

    def counted_values(key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in entries:
            value = str(item.get(key) or "unknown")
            counts[value] = counts.get(value, 0) + 1
        return counts

    actual = count_flag("actual_command_or_process_activity")
    claimable_tools = count_flag("safe_to_claim_tool_ran")
    claimable_commands = count_flag("safe_to_claim_command_executed")
    summary = {
        "ledger_entries": len(entries),
        "dispatch_attempted": count_flag("dispatch_attempted"),
        "target_affecting_tool_calls": count_flag("target_affecting_tool"),
        "actual_command_or_process_activity": actual,
        "approval_queued": count_flag("approval_queued"),
        "blocked": count_flag("blocked"),
        "dry_run": count_flag("dry_run"),
        "handler_error": count_state("handler_error"),
        "local_only_completion": count_state("completed_without_command_execution"),
        "claimable_tool_runs": claimable_tools,
        "claimable_command_executions": claimable_commands,
        "non_claimable_results": max(0, len(entries) - claimable_tools),
        "result_status_counts": counted_values("result_status"),
        "execution_state_counts": counted_values("execution_state"),
        "runtime_policy_counts": counted_values("runtime_policy"),
        "guardrail_status_counts": counted_values("guardrail_status"),
        "claim_rule": "Only entries with safe_to_claim_command_executed=true / actual_command_or_process_activity=true may be described as command or process execution; dry-run, approval, blocked, and handler-error entries are non-claimable.",
    }
    return _redact_runtime_value(summary)


def _redact_runtime_value(value: Any) -> Any:
    """Recursively redact string leaves while preserving JSON structure."""

    if isinstance(value, str):
        return redact_secrets(value) or ""
    if isinstance(value, dict):
        return {str(_redact_runtime_value(key)): _redact_runtime_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_runtime_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_runtime_value(item) for item in value]
    return value


def _write_auto_plan_artifacts(evidence_root: Path, payload: dict[str, Any]) -> dict[str, str]:
    """Persist a redacted one-shot native /auto plan or application transcript."""

    root = evidence_root.resolve(strict=False)
    out_dir = (evidence_root / "agent" / "auto-plans").resolve(strict=False)
    if not _runtime_path_is_relative_to(out_dir, root):
        raise ValueError("auto-plan artifact directory escapes the engagement evidence root")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("+00:00", "Z")
    json_path = out_dir / f"auto-plan-{stamp}.json"
    markdown_path = out_dir / f"auto-plan-{stamp}.md"
    artifacts = {"json": str(json_path), "markdown": str(markdown_path)}
    redacted_payload = _redact_runtime_value({**payload, "artifacts": artifacts})
    json_path.write_text(json.dumps(redacted_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_auto_plan_apply_markdown(redacted_payload), encoding="utf-8")
    return artifacts


def _native_call_provenance_markdown(metadata: Any) -> str:
    """Return bounded provider/native call provenance safe for Markdown summaries."""

    if not isinstance(metadata, dict):
        return ""
    parts: list[str] = []
    source = metadata.get("native_tool_call_source") or metadata.get("source")
    if source not in (None, ""):
        parts.append(f"source=`{_markdown_metadata_value(source, 120)}`")
    provider_id = metadata.get("provider_tool_call_id") or metadata.get("tool_call_id") or metadata.get("call_id")
    if provider_id not in (None, ""):
        parts.append(f"provider_call_id=`{_markdown_metadata_value(provider_id, 200)}`")
    if "native_tool_call_index" in metadata:
        index = _safe_int(metadata.get("native_tool_call_index"))
        if index is not None:
            parts.append(f"native_index=`{index}`")
    return (", " + ", ".join(parts)) if parts else ""


def _markdown_metadata_value(value: Any, limit: int) -> str:
    return _bounded_metadata_string(value, limit).replace("`", "'").replace("\n", " ").replace("\r", " ")


def _auto_plan_apply_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Phobos Native Tool-Calling Auto Plan",
        "",
        f"Generated: {utc_now()}",
        f"Mode: `{payload.get('mode', 'unknown')}`",
        f"Trigger: `{payload.get('trigger', 'slash_auto')}`",
        f"Natural auto-execute: `{payload.get('natural_auto_execute', False)}`",
        "Secret-like values redacted: `true`",
        "",
        "## Operator prompt",
        "",
        str(payload.get("prompt") or ""),
        "",
        "## Planner trace",
        "",
    ]
    raw_trace = payload.get("planner_trace")
    planner_trace: list[Any] = raw_trace if isinstance(raw_trace, list) else []
    if not planner_trace:
        lines.append("- No planner trace entries were recorded.")
    for item in planner_trace:
        if not isinstance(item, dict):
            continue
        fallback_note = ""
        if item.get("fallback_attempt_count") is not None:
            fallback_note = f", fallback_attempts=`{item.get('fallback_attempt_count')}`"
        lines.append(
            f"- step=`{item.get('step')}` planner=`{item.get('planner')}` provider=`{item.get('provider')}` "
            f"selected_provider=`{item.get('selected_provider')}` tool_calls=`{item.get('tool_call_count')}` "
            f"rejected=`{item.get('rejected_tool_call_count')}` context_chars=`{item.get('context_chars', 0)}`{fallback_note}"
        )
    raw_summary = payload.get("execution_summary")
    execution_summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    if execution_summary:
        lines.extend([
            "",
            "## Execution summary",
            "",
            f"- Ledger entries: `{execution_summary.get('ledger_entries', 0)}`",
            f"- Actual command/process activity: `{execution_summary.get('actual_command_or_process_activity', 0)}`",
            f"- Approval queued: `{execution_summary.get('approval_queued', 0)}`; blocked: `{execution_summary.get('blocked', 0)}`; dry-run: `{execution_summary.get('dry_run', 0)}`",
            f"- Claimable tool runs: `{execution_summary.get('claimable_tool_runs', 0)}`; claimable command executions: `{execution_summary.get('claimable_command_executions', 0)}`",
            f"- Claim rule: {execution_summary.get('claim_rule', '')}",
        ])
    lines.extend([
        "",
        "## Execution ledger",
        "",
    ])
    raw_ledger = payload.get("execution_ledger")
    ledger: list[Any] = raw_ledger if isinstance(raw_ledger, list) else []
    if not ledger:
        lines.append("- No tool calls were dispatched.")
    for item in ledger:
        if not isinstance(item, dict):
            continue
        provenance = _native_call_provenance_markdown(item)
        lines.append(
            f"- `{item.get('tool')}`: state=`{item.get('execution_state')}`, "
            f"result=`{item.get('result_status')}`, "
            f"actual_command_or_process_activity=`{item.get('actual_command_or_process_activity', False)}`, "
            f"approval_queued=`{item.get('approval_queued', False)}`, "
            f"blocked=`{item.get('blocked', False)}`, dry_run=`{item.get('dry_run', False)}`{provenance}"
        )
    lines.extend(["", "## Planned calls", ""])
    raw_calls = payload.get("tool_calls")
    calls: list[Any] = raw_calls if isinstance(raw_calls, list) else []
    if not calls:
        lines.append("- No planned calls were accepted.")
    for call in calls:
        if not isinstance(call, dict):
            continue
        raw_validation = call.get("validation")
        validation = raw_validation if isinstance(raw_validation, dict) else {}
        raw_metadata = call.get("metadata")
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        provenance = _native_call_provenance_markdown(metadata)
        lines.append(
            f"- `{call.get('tool')}` — {call.get('reason', 'planned step')} "
            f"(schema_validated={validation.get('schema_validated', False)}, runtime_policy={validation.get('runtime_policy', 'unknown')}{provenance})"
        )
    raw_rejected = payload.get("rejected_tool_calls")
    rejected: list[Any] = raw_rejected if isinstance(raw_rejected, list) else []
    if rejected:
        lines.extend(["", "## Rejected calls", ""])
        for item in rejected:
            if isinstance(item, dict):
                lines.append(f"- `{item.get('tool')}` — {item.get('reason')}")
    lines.extend(["", "## Tool results", ""])
    raw_results = payload.get("results")
    results: list[Any] = raw_results if isinstance(raw_results, list) else []
    if not results:
        lines.append("- No registry results were recorded.")
    for item in results:
        if not isinstance(item, dict):
            continue
        raw_result = item.get("result")
        result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
        lines.append(f"- `{item.get('tool')}` -> `{result.get('status', 'unknown')}`: {result.get('message', '')}")
    lines.extend([
        "",
        "## Safety note",
        "",
        "Confirm-gated, blocked, and dry-run results are not treated as executed unless the registry result and execution ledger prove command/process activity occurred.",
    ])
    return "\n".join(lines).rstrip() + "\n"


def _write_auto_loop_artifacts(evidence_root: Path, payload: dict[str, Any]) -> dict[str, str]:
    """Persist a redacted native tool-calling loop transcript under evidence/agent."""

    root = evidence_root.resolve(strict=False)
    out_dir = (evidence_root / "agent" / "auto-loops").resolve(strict=False)
    if not _runtime_path_is_relative_to(out_dir, root):
        raise ValueError("auto-loop artifact directory escapes the engagement evidence root")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("+00:00", "Z")
    json_path = out_dir / f"auto-loop-{stamp}.json"
    markdown_path = out_dir / f"auto-loop-{stamp}.md"
    artifacts = {"json": str(json_path), "markdown": str(markdown_path)}
    redacted_payload = _redact_runtime_value({**payload, "artifacts": artifacts})
    json_path.write_text(json.dumps(redacted_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_auto_loop_markdown(redacted_payload), encoding="utf-8")
    return artifacts


def _auto_loop_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Phobos Native Tool-Calling Auto Loop",
        "",
        f"Generated: {utc_now()}",
        f"Stop reason: `{payload.get('stop_reason', 'unknown')}`",
        f"Steps executed: {payload.get('steps_executed', 0)} / {payload.get('steps_requested', 0)}",
        f"Max-step budget exhausted: `{payload.get('max_steps_budget_exhausted', False)}`",
        f"Model planning: `{payload.get('model', False)}`",
        f"Command execution enabled for loop: `{payload.get('execute', False)}`",
        "Secret-like values redacted: `true`",
        "",
    ]
    next_step = str(payload.get("next_step") or "").strip()
    if next_step:
        lines.extend(["Next step: " + next_step, ""])
    lines.extend([
        "## Operator prompt",
        "",
        str(payload.get("prompt") or ""),
        "",
        "## Planner trace",
        "",
    ])
    raw_trace = payload.get("planner_trace")
    planner_trace: list[Any] = raw_trace if isinstance(raw_trace, list) else []
    if not planner_trace:
        lines.append("- No planner trace entries were recorded.")
    for item in planner_trace:
        if not isinstance(item, dict):
            continue
        fallback_note = ""
        if item.get("fallback_attempt_count") is not None:
            fallback_note = f", fallback_attempts=`{item.get('fallback_attempt_count')}`"
        lines.append(
            f"- step=`{item.get('step')}` planner=`{item.get('planner')}` provider=`{item.get('provider')}` "
            f"selected_provider=`{item.get('selected_provider')}` tool_calls=`{item.get('tool_call_count')}` "
            f"rejected=`{item.get('rejected_tool_call_count')}` context_chars=`{item.get('context_chars', 0)}`{fallback_note}"
        )
    raw_summary = payload.get("execution_summary")
    execution_summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    if execution_summary:
        lines.extend([
            "",
            "## Execution summary",
            "",
            f"- Ledger entries: `{execution_summary.get('ledger_entries', 0)}`",
            f"- Actual command/process activity: `{execution_summary.get('actual_command_or_process_activity', 0)}`",
            f"- Approval queued: `{execution_summary.get('approval_queued', 0)}`; blocked: `{execution_summary.get('blocked', 0)}`; dry-run: `{execution_summary.get('dry_run', 0)}`",
            f"- Claimable tool runs: `{execution_summary.get('claimable_tool_runs', 0)}`; claimable command executions: `{execution_summary.get('claimable_command_executions', 0)}`",
            f"- Claim rule: {execution_summary.get('claim_rule', '')}",
        ])
    lines.extend([
        "",
        "## Execution ledger",
        "",
    ])
    raw_ledger = payload.get("execution_ledger")
    ledger: list[Any] = raw_ledger if isinstance(raw_ledger, list) else []
    if not ledger:
        lines.append("- No tool calls were dispatched.")
    for item in ledger:
        if not isinstance(item, dict):
            continue
        step = f" step={item.get('step')}" if item.get("step") is not None else ""
        provenance = _native_call_provenance_markdown(item)
        lines.append(
            f"- `{item.get('tool')}`{step}: state=`{item.get('execution_state')}`, "
            f"result=`{item.get('result_status')}`, "
            f"actual_command_or_process_activity=`{item.get('actual_command_or_process_activity', False)}`, "
            f"approval_queued=`{item.get('approval_queued', False)}`, "
            f"blocked=`{item.get('blocked', False)}`, dry_run=`{item.get('dry_run', False)}`{provenance}"
        )
    lines.extend([
        "",
        "## Step transcript",
        "",
    ])
    raw_steps = payload.get("steps")
    steps: list[Any] = raw_steps if isinstance(raw_steps, list) else []
    if not steps:
        lines.append("- No steps were recorded.")
    for step in steps:
        if not isinstance(step, dict):
            continue
        lines.extend([f"### Step {step.get('step', '?')} — {step.get('mode', 'unknown')}", ""])
        raw_plan = step.get("plan")
        plan: dict[str, Any] = raw_plan if isinstance(raw_plan, dict) else {}
        summary = str(plan.get("summary") or "").strip()
        if summary:
            lines.extend([f"Plan summary: {summary}", ""])
        if step.get("mode") == "stopped_duplicate_plan":
            detection = step.get("duplicate_detection", "tool_args_any_repeat")
            lines.extend([
                f"Duplicate plan stop ({detection}): {step.get('duplicate_tool_call_count', 0)} repeated tool+args call(s); "
                f"new calls withheld={step.get('new_tool_call_count', 0)}; no tools were dispatched for this step.",
                "",
            ])
        if step.get("mode") == "invalid_plan":
            lines.extend([
                f"Invalid plan stop: {step.get('rejected_tool_call_count', 0)} model-proposed call(s) were rejected before dispatch; no tools were dispatched for this step.",
                "",
            ])
        if step.get("no_tools_executed") is True and step.get("mode") not in {"stopped_duplicate_plan", "invalid_plan"}:
            lines.extend([
                "No-dispatch step: no tools were dispatched for this step.",
                "",
            ])
        raw_calls = plan.get("tool_calls")
        calls: list[Any] = raw_calls if isinstance(raw_calls, list) else []
        if calls:
            lines.append("Planned calls:")
            for call in calls:
                if isinstance(call, dict):
                    raw_validation = call.get("validation")
                    validation: dict[str, Any] = raw_validation if isinstance(raw_validation, dict) else {}
                    raw_metadata = call.get("metadata")
                    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
                    provenance = _native_call_provenance_markdown(metadata)
                    lines.append(
                        f"- `{call.get('tool')}` — {call.get('reason', 'planned step')} "
                        f"(schema_validated={validation.get('schema_validated', False)}, runtime_policy={validation.get('runtime_policy', 'unknown')}{provenance})"
                    )
            lines.append("")
        raw_rejected = plan.get("rejected_tool_calls")
        rejected: list[Any] = raw_rejected if isinstance(raw_rejected, list) else []
        if rejected:
            lines.append("Rejected calls:")
            for item in rejected:
                if isinstance(item, dict):
                    lines.append(f"- `{item.get('tool')}` — {item.get('reason')}")
            lines.append("")
        raw_results = step.get("results")
        results: list[Any] = raw_results if isinstance(raw_results, list) else []
        raw_delta = step.get("execution_ledger_delta")
        delta: list[Any] = raw_delta if isinstance(raw_delta, list) else []
        if delta:
            lines.append("Execution ledger delta:")
            for item in delta:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    f"- `{item.get('tool')}`: state=`{item.get('execution_state')}`, "
                    f"result=`{item.get('result_status')}`, "
                    f"actual_command_or_process_activity=`{item.get('actual_command_or_process_activity', False)}`{_native_call_provenance_markdown(item)}"
                )
            lines.append("")
        if results:
            lines.append("Tool results:")
            for item in results:
                if not isinstance(item, dict):
                    continue
                raw_result = item.get("result")
                result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
                lines.append(f"- `{item.get('tool')}` -> `{result.get('status', 'unknown')}`: {result.get('message', '')}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _runtime_path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _format_result(result: ToolResult) -> str:
    lines = [f"[{result.status}] {result.message}"]
    if result.artifacts:
        lines.append("Artifacts:")
        lines.extend(f"- {key}: {value}" for key, value in result.artifacts.items())
    if result.data:
        lines.append("Data:")
        # Keep slash/gateway raw responses machine-parseable as features grow.
        # Chat bridges and transcript detail renderers perform their own bounded
        # summaries; truncating JSON here can break status/schema/native-loop
        # contract parsing and cause bridge summaries to fall back to generic text.
        lines.append(json.dumps(result.data, indent=2))
    return "\n".join(lines)


HELP_TEXT = """Phobos Agent commands:

/help
/tools
/schemas name=<optional-tool>
/tool name=<tool_name> key=value ...
/auto prompt=<natural request> apply=false execute=false model=false
/auto-loop prompt=<goal> steps=5 execute=false model=false
/auto-transcripts kind=all limit=50
/auto-transcript path=<agent/auto-plans-or-auto-loops/file.json> max_ledger=20
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
/memories query=<optional> limit=50
/memory id=<memory-id> or key=<name>
/forget id=<memory-id> or key=<name>
/reflect query=<question>
/hindsight-retain content=<fact> context=<label> tags=<tags>
/hindsight-recall query=<text>
/hindsight-reflect query=<question>
/search query=<text>
/search-all query=<text>
/context query=<optional> limit=8
/compact limit=40
/lcm-compact limit=60 parent=false
/lcm-describe id=<optional-node-id>
/lcm-expand id=<node-id>
/lcm-query query=<question>
/read path=<workspace-relative-file>
/write path=<workspace-relative-file> content=<text> append=false
/workspace-search query=<regex> glob="**/*.md"
/patch-file path=<file> old=<text> new=<text> replace_all=false
/scope target=<optional-host-or-url>
/guardrail-test target=<optional-host-or-url> out=<optional.md>
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/process-detail id=<process-id>
/poll id=<process-id>
/wait id=<process-id> timeout=30
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals status=pending|all
/approval id=<approval-id>
/approve id=<approval-id>
/deny id=<approval-id> reason=<why>
/plan finding=<observed weakness>
/burp-tab target=<host> tab_name=<name> request_file=<path> mcp_url=<url> create=false
/bloodhound input=<json|dir|zip> principal=<USER@DOMAIN>
/cve component=<product> version=<version> catalog=<catalog.json> online=false
/nmap target=<host> ports=80,443 stdout=<optional-captured-output> execute=false
/httpx url=<url> stdout=<optional-jsonl-output> execute=false
/nuclei url=<url> stdout=<optional-jsonl-output> execute=false
/ffuf url=<url/FUZZ> wordlist=<path> stdout=<optional-json-output> execute=false
/tool-runs limit=20 tool_name=<optional>
/finding finding_file=<finding.json>
/findings status=all
/finding-create title=<title> severity=Medium status=draft tool_run_ids=1,2
/finding-update id=<finding-id> status=confirmed append_evidence=true
/finding-get id=<finding-id>
/finding-export id=<finding-id> out=<optional.md>
/finding-review id=<finding-id> out=<optional.md>
/finding-bundle id=<finding-id> out=<optional.zip>
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/delegate prompt=<task> roles=scope,safety,report
/delegations limit=20
/delegation id=<delegation-id>
/auth-status
/preflight out=<optional.md>
/media-import path=<local-file> kind=<optional>
/media-list
/media-get id=<media-id>
/sealed-export passphrase_env=<ENV_NAME> out=<optional.sealed.json>
/sealed-import path=<sealed.json> passphrase_env=<ENV_NAME>
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/jobs
/job-detail id=<job-id>
/job-update id=<job-id> enabled=false schedule=<optional> prompt=<optional>
/job-enable id=<job-id>
/job-disable id=<job-id>
/run-due
/status
/briefing query=<optional> out=<optional.md>
/timeline limit=100 category=<optional> include_audit=true out=<optional.md>
/manifest limit=1000 max_bytes=50000000 include_agent=true out=<optional.json>
/manifest-verify path=<manifest.json> out=<optional.json>
/secret-scan limit=200 max_bytes=2000000 include_agent=true out=<optional.json>
/closeout out=<optional.md>
/ref ref=<task:1|finding:1|tool-run:1|auto-transcript:agent/auto-loops/file.json|artifact:agent/path>
/tasks status=all
/task-detail id=<task-id>
/task-add content=<task> status=pending
/task-update id=<task-id> status=completed content=<optional>
/handoff out=<optional.json>
/export-session out=<optional.json>
/import-session path=<handoff.json> merge_memories=false
/export-pack out=<optional.zip>
/audit limit=50

Target-affecting commands are ROE-gated, evidence-logged, and non-destructive by default. Confirm-level actions require /approve before execution/start. Runtime policy can also block or require approval for any named tool.
"""
