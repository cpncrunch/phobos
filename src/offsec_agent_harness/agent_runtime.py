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
from .agent_store import AgentStore
from .agent_tools import OffSecToolRegistry, ToolResult
from .model_adapters import BaseModelAdapter, build_adapter, build_fallback_adapter
from .models import EngagementROE, redact_secrets


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
            self.store.mark_job_run(job.id, response)
            results.append({"job_id": job.id, "name": job.name, "response": response})
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
                return self._execute_plan(plan, apply=True)
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
            plan = self._plan_actions(prompt, allow_command_execution=bool(args.get("execute", False)), use_model=bool(args.get("model", self.config.auto_model_planning)))
            return self._execute_plan(plan, apply=bool(args.get("apply", False)))
        if command in {"auto-loop", "loop", "task-run"}:
            prompt = str(args.get("prompt") or args.get("query") or " ".join(args.get("_positional", []))).strip()
            if not prompt:
                return "Usage: /auto-loop prompt=<goal> steps=5 execute=false model=false"
            return self._execute_auto_loop(prompt, steps=int(args.get("steps", self.config.max_auto_steps)), execute=bool(args.get("execute", False)), use_model=bool(args.get("model", self.config.auto_model_planning)))
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
            "run": "run_command",
            "start": "start_process",
            "process-start": "start_process",
            "poll": "poll_process",
            "process-poll": "poll_process",
            "wait": "wait_process",
            "process-wait": "wait_process",
            "log": "process_log",
            "process-log": "process_log",
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
            "remember": "remember",
            "recall": "recall",
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
            "approvals": "list_approvals",
            "subagents": "subagent_review",
            "delegate": "delegate_tasks",
            "delegations": "list_delegations",
            "auth-status": "auth_status",
            "auth": "auth_status",
            "media-import": "media_import",
            "media-list": "media_list",
            "sealed-export": "sealed_export",
            "sealed-import": "sealed_import",
            "audit": "audit_log",
            "timeline": "evidence_timeline",
            "evidence-timeline": "evidence_timeline",
            "status": "runtime_status",
            "export-pack": "export_pack",
            "pack": "export_pack",
            "briefing": "operator_briefing",
            "handoff": "export_session",
            "export-session": "export_session",
            "import-session": "import_session",
            "tasks": "list_tasks",
            "task-list": "list_tasks",
            "task-add": "add_task",
            "task-update": "update_task",
        }
        if command not in mapping:
            return f"Unknown command /{command}. Use /help or /tools."
        result = self.registry.run(mapping[command], args)
        return _format_result(result)

    def _execute_plan(self, plan: AgentPlan, *, apply: bool) -> str:
        payload: dict[str, Any] = plan.to_dict()
        if not apply:
            payload["mode"] = "plan_only"
            payload["next_step"] = "Re-run with /auto apply=true to invoke these tools. Add execute=true only if guarded command execution is intended."
            return "Auto plan (no tools executed):\n" + json.dumps(payload, indent=2)
        results = []
        for call in plan.tool_calls:
            result = self.registry.run(call.tool, call.args)
            results.append({"tool": call.tool, "reason": call.reason, "result": result.to_dict()})
        payload["mode"] = "applied"
        payload["results"] = results
        return "Auto plan applied:\n" + json.dumps(payload, indent=2)[:10000]

    def _plan_actions(self, prompt: str, *, allow_command_execution: bool, use_model: bool) -> AgentPlan:
        deterministic = plan_agent_actions(prompt, allow_command_execution=allow_command_execution)
        if not use_model:
            return deterministic
        try:
            model_plan = self._plan_actions_with_model(prompt, allow_command_execution=allow_command_execution)
        except Exception as exc:
            deterministic.warnings.append(f"Model planner failed; deterministic planner used: {exc}")
            return deterministic
        if not model_plan.tool_calls:
            if deterministic.tool_calls:
                deterministic.warnings.extend(model_plan.warnings)
                return deterministic
            return model_plan
        return model_plan

    def _plan_actions_with_model(self, prompt: str, *, allow_command_execution: bool) -> AgentPlan:
        specs = [spec.to_dict() for spec in self.registry.specs()]
        planner_prompt = (
            "You are planning Phobos Agent tool calls. Return ONLY JSON with keys summary, tool_calls, warnings. "
            "tool_calls must be a list of {tool, args, reason}. Use only registered tools. Do not invent tools. "
            "Target-affecting tools still go through ROE guardrails. If command execution is not explicitly allowed, set execute=false.\n\n"
            f"Command execution allowed: {allow_command_execution}\n"
            f"Operator request: {prompt}\n\n"
            f"Registered tools: {json.dumps(specs[:80], indent=2)[:30000]}"
        )
        raw = self.adapter.generate("impact", planner_prompt).content
        parsed = _extract_json_object(raw)
        calls: list[PlannedToolCall] = []
        warnings = [str(item) for item in parsed.get("warnings", []) if str(item).strip()] if isinstance(parsed.get("warnings", []), list) else []
        for item in parsed.get("tool_calls", []):
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", "")).strip()
            if tool not in self.registry.tools:
                warnings.append(f"Model planner requested unknown tool {tool!r}; skipped.")
                continue
            tool_args = item.get("args", {})
            if not isinstance(tool_args, dict):
                warnings.append(f"Model planner args for {tool!r} were not an object; skipped.")
                continue
            if tool in {"run_command", "start_process"} and not allow_command_execution:
                tool_args = dict(tool_args)
                tool_args["execute"] = False
                warnings.append(f"{tool} planned with execute=false because command execution was not explicitly enabled.")
            calls.append(PlannedToolCall(tool=tool, args=tool_args, reason=str(item.get("reason") or "Model planner selected this tool.")))
        return AgentPlan(prompt=prompt, summary=str(parsed.get("summary") or f"Model planned {len(calls)} tool call(s)."), tool_calls=calls, warnings=warnings)

    def _execute_auto_loop(self, prompt: str, *, steps: int, execute: bool, use_model: bool) -> str:
        steps = max(1, min(int(steps), 10))
        current_prompt = prompt
        loop_results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for step in range(1, steps + 1):
            plan = self._plan_actions(current_prompt, allow_command_execution=execute, use_model=use_model)
            if not plan.tool_calls:
                loop_results.append({"step": step, "mode": "no_plan", "plan": plan.to_dict()})
                break
            signatures = [json.dumps(call.to_dict(), sort_keys=True, default=str) for call in plan.tool_calls]
            if all(signature in seen for signature in signatures):
                loop_results.append({"step": step, "mode": "stopped_duplicate_plan", "plan": plan.to_dict()})
                break
            for signature in signatures:
                seen.add(signature)
            step_results = []
            for call in plan.tool_calls:
                result = self.registry.run(call.tool, call.args)
                step_results.append({"tool": call.tool, "reason": call.reason, "result": result.to_dict()})
            loop_results.append({"step": step, "mode": "applied", "plan": plan.to_dict(), "results": step_results})
            if not use_model:
                break
            current_prompt = prompt + "\n\nPrevious Phobos tool results:\n" + json.dumps(step_results, indent=2)[:8000] + "\n\nPlan only any genuinely necessary next tool calls; return an empty tool_calls list if done."
        return "Auto loop completed:\n" + json.dumps({"prompt": prompt, "steps_requested": steps, "execute": execute, "model": use_model, "steps": loop_results}, indent=2)[:12000]

    def _load_skill(self, name: str) -> LocalSkill:
        skill = load_skill(name, self.config.skill_dirs)
        self.loaded_skills[skill.name] = skill
        self.store.audit(self.session_id, "skill_loaded", {"skill": skill.name, "path": skill.path})
        return skill


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
        "- `/finding-create ...` and `/findings status=all` — finding lifecycle.",
        "- `/timeline` — redacted evidence/action timeline for handoff and report reconstruction.",
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
    lines.append("Use the local gateway/CLI for approvals unless this bridge was deliberately enabled for `/approve` and `/deny`.")
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
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("model did not return a JSON object")
    parsed = json.loads(text[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("model JSON response was not an object")
    return parsed


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
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    if lowered.isdigit():
        return int(lowered)
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _format_result(result: ToolResult) -> str:
    lines = [f"[{result.status}] {result.message}"]
    if result.artifacts:
        lines.append("Artifacts:")
        lines.extend(f"- {key}: {value}" for key, value in result.artifacts.items())
    if result.data:
        lines.append("Data:")
        lines.append(json.dumps(result.data, indent=2)[:6000])
    return "\n".join(lines)


HELP_TEXT = """Phobos Agent commands:

/help
/tools
/schemas name=<optional-tool>
/tool name=<tool_name> key=value ...
/auto prompt=<natural request> apply=false execute=false model=false
/auto-loop prompt=<goal> steps=5 execute=false model=false
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
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
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/poll id=<process-id>
/wait id=<process-id> timeout=30
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals
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
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/delegate prompt=<task> roles=scope,safety,report
/delegations limit=20
/auth-status
/media-import path=<local-file> kind=<optional>
/media-list
/sealed-export passphrase_env=<ENV_NAME> out=<optional.sealed.json>
/sealed-import path=<sealed.json> passphrase_env=<ENV_NAME>
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/run-due
/status
/briefing query=<optional> out=<optional.md>
/timeline limit=100 category=<optional> include_audit=true out=<optional.md>
/tasks status=all
/task-add content=<task> status=pending
/task-update id=<task-id> status=completed content=<optional>
/handoff out=<optional.json>
/export-session out=<optional.json>
/import-session path=<handoff.json> merge_memories=false
/export-pack out=<optional.zip>
/audit limit=50

Target-affecting commands are ROE-gated, evidence-logged, and non-destructive by default. Confirm-level actions require /approve before execution/start. Runtime policy can also block or require approval for any named tool.
"""
