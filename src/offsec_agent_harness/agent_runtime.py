from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import shlex

from .agent_planner import AgentPlan, plan_agent_actions
from .agent_plugins import load_plugins
from .agent_skills import LocalSkill, discover_skills, load_skill, render_loaded_skills
from .agent_store import AgentStore
from .agent_tools import OffSecToolRegistry, ToolResult
from .model_adapters import BaseModelAdapter, build_adapter, build_fallback_adapter
from .models import EngagementROE


@dataclass(slots=True)
class AgentRuntimeConfig:
    engagement_path: str
    db_path: str = "data/phobos-agent.db"
    session_name: str = "default"
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
    blocked_tools: tuple[str, ...] = ()
    confirm_tools: tuple[str, ...] = ()
    skill_dirs: tuple[str, ...] = ()
    preload_skills: tuple[str, ...] = ()
    skill_bundles: dict[str, tuple[str, ...]] | None = None
    bridges: dict[str, dict[str, Any]] | None = None


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
            plan = plan_agent_actions(message, allow_command_execution=False)
            if plan.tool_calls:
                return self._execute_plan(plan, apply=True)
        memories = self.store.recall(message, limit=5)
        recent = self.store.recent_messages(self.session_id, limit=self.config.max_context_messages)
        summary = self.store.latest_context_summary(self.session_id)
        context_parts = []
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
        draft = self.adapter.generate("impact", message, context="\n\n".join(context_parts)).content
        return (
            "Phobos Agent response (no tool executed):\n"
            f"{draft}\n\n"
            "Use /auto apply=true for guarded natural-language tool planning, or /tools for explicit actions. Commands stay ROE-gated, non-destructive by default, and evidence-logged."
        )

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
                return "Usage: /auto prompt=<natural request> apply=false execute=false"
            plan = plan_agent_actions(prompt, allow_command_execution=bool(args.get("execute", False)))
            return self._execute_plan(plan, apply=bool(args.get("apply", False)))
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
            "finding": "export_finding",
            "remember": "remember",
            "recall": "recall",
            "search": "search_session",
            "context": "context_snapshot",
            "compact": "compact_context",
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
            "audit": "audit_log",
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

    def _load_skill(self, name: str) -> LocalSkill:
        skill = load_skill(name, self.config.skill_dirs)
        self.loaded_skills[skill.name] = skill
        self.store.audit(self.session_id, "skill_loaded", {"skill": skill.name, "path": skill.path})
        return skill


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
/auto prompt=<natural request> apply=false execute=false
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
/search query=<text>
/context query=<optional> limit=8
/compact limit=40
/read path=<workspace-relative-file>
/write path=<workspace-relative-file> content=<text> append=false
/workspace-search query=<regex> glob="**/*.md"
/patch-file path=<file> old=<text> new=<text> replace_all=false
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/poll id=<process-id>
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals
/approve id=<approval-id>
/deny id=<approval-id> reason=<why>
/plan finding=<observed weakness>
/burp-tab target=<host> tab_name=<name> request_file=<path> mcp_url=<url> create=false
/bloodhound input=<json|dir|zip> principal=<USER@DOMAIN>
/cve component=<product> version=<version> catalog=<catalog.json> online=false
/finding finding_file=<finding.json>
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/run-due
/status
/briefing query=<optional> out=<optional.md>
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
