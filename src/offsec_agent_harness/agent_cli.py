from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent_config import AgentAppConfig
from .agent_gateway import AgentGateway
from .agent_runtime import AgentRuntimeConfig, OffSecAgentRuntime
from .agent_store import AgentStore
from .models import EngagementROE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone Phobos Agent runtime")
    parser.add_argument("--db", default="data/phobos-agent.db", help="SQLite runtime DB path")
    parser.add_argument("--session", default="default", help="Session name")
    parser.add_argument("--config", help="Agent runtime JSON config with provider fallback, workspace, and plugin settings")
    parser.add_argument("--workspace-dir", help="Engagement workspace directory for local file tools")
    parser.add_argument("--plugin-dir", action="append", default=[], help="Directory of Python plugins exposing register(registry)")
    parser.add_argument("--provider", default="heuristic", choices=["heuristic", "openai", "openai-compatible", "local", "ollama", "hermes", "hermes-cli"])
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--base-url")
    parser.add_argument("--key-env", default="OPENAI_API_KEY")
    parser.add_argument("--command-template")
    parser.add_argument("--auto-execute-natural", action="store_true", help="Allow natural-language messages to invoke recognized non-command tools automatically; command execution still requires explicit slash/tool args")
    parser.add_argument("--block-tool", action="append", default=[], help="Block a registered tool by name at runtime policy level")
    parser.add_argument("--confirm-tool", action="append", default=[], help="Queue a registered tool for approval before execution")
    parser.add_argument("--skill-dir", action="append", default=[], help="Directory containing local Hermes-style SKILL.md files")
    parser.add_argument("--preload-skill", action="append", default=[], help="Local skill name to load at runtime startup")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    config_init = sub.add_parser("config-init", help="Write a default agent runtime config JSON")
    config_init.add_argument("--out", default="agent.config.json")

    init = sub.add_parser("init", help="Initialize an agent DB/session for an engagement")
    init.add_argument("--engagement", required=True)

    once = sub.add_parser("once", help="Handle a single message")
    once.add_argument("--engagement", required=True)
    once.add_argument("--message", required=True)

    chat = sub.add_parser("chat", help="Interactive local chat loop")
    chat.add_argument("--engagement", required=True)

    tools = sub.add_parser("tools", help="List runtime tools")
    tools.add_argument("--engagement", required=True)

    schema = sub.add_parser("schema", help="Print one tool schema or all schemas")
    schema.add_argument("--engagement", required=True)
    schema.add_argument("--name")

    tool = sub.add_parser("tool", help="Invoke a registered tool with --arg key=value pairs")
    tool.add_argument("--engagement", required=True)
    tool.add_argument("--name", required=True)
    tool.add_argument("--arg", action="append", default=[])

    status = sub.add_parser("status", help="Print runtime status and schema information")
    status.add_argument("--engagement", required=True)

    export_pack = sub.add_parser("export-pack", help="Create a redacted engagement pack ZIP")
    export_pack.add_argument("--engagement", required=True)
    export_pack.add_argument("--out")

    jobs = sub.add_parser("run-due", help="Run due jobs for the session")
    jobs.add_argument("--engagement", required=True)

    serve = sub.add_parser("serve", help="Run a local HTTP gateway for the agent")
    serve.add_argument("--engagement", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    return parser


def _config(args: argparse.Namespace) -> AgentRuntimeConfig:
    if args.config:
        cfg = AgentAppConfig.load(args.config).to_runtime_config(args.engagement, args.db, args.session)
    else:
        cfg = AgentRuntimeConfig(
            engagement_path=args.engagement,
            db_path=args.db,
            session_name=args.session,
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            key_env=args.key_env,
            command_template=args.command_template,
        )
    if args.workspace_dir:
        cfg.workspace_dir = args.workspace_dir
    if args.plugin_dir:
        cfg.plugin_dirs = tuple(list(cfg.plugin_dirs) + list(args.plugin_dir))
    if args.auto_execute_natural:
        cfg.auto_execute_natural = True
    if args.block_tool:
        cfg.blocked_tools = tuple(list(cfg.blocked_tools) + list(args.block_tool))
    if args.confirm_tool:
        cfg.confirm_tools = tuple(list(cfg.confirm_tools) + list(args.confirm_tool))
    if args.skill_dir:
        cfg.skill_dirs = tuple(list(cfg.skill_dirs) + list(args.skill_dir))
    if args.preload_skill:
        cfg.preload_skills = tuple(list(cfg.preload_skills) + list(args.preload_skill))
    return cfg


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.subcommand == "config-init":
        path = AgentAppConfig.default().save(args.out)
        print(json.dumps({"config": str(path), "status": "written"}, indent=2))
        return 0

    if args.subcommand == "init":
        roe = EngagementROE.load(args.engagement)
        cfg = _config(args)
        store = AgentStore(args.db)
        session_id = store.get_or_create_session(args.session, args.engagement)
        store.audit(session_id, "agent_init", {"engagement": roe.name, "scope": roe.in_scope_targets, "safety_mode": roe.safety_mode, "workspace_dir": cfg.workspace_dir, "plugin_dirs": list(cfg.plugin_dirs), "blocked_tools": list(cfg.blocked_tools), "confirm_tools": list(cfg.confirm_tools), "skill_dirs": list(cfg.skill_dirs), "preload_skills": list(cfg.preload_skills)})
        store.close()
        print(json.dumps({"db": args.db, "session_id": session_id, "engagement": roe.to_dict(), "runtime": {"workspace_dir": cfg.workspace_dir, "plugin_dirs": list(cfg.plugin_dirs), "blocked_tools": list(cfg.blocked_tools), "confirm_tools": list(cfg.confirm_tools), "skill_dirs": list(cfg.skill_dirs), "preload_skills": list(cfg.preload_skills), "skill_bundles": {name: list(skills) for name, skills in (cfg.skill_bundles or {}).items()}, "provider_chain": list(cfg.model_providers) or [{"provider": cfg.provider, "model": cfg.model}]}}, indent=2))
        return 0

    runtime = OffSecAgentRuntime(_config(args))
    try:
        if args.subcommand == "once":
            print(runtime.handle_message(args.message))
            return 0
        if args.subcommand == "chat":
            runtime.chat_loop()
            return 0
        if args.subcommand == "tools":
            print(runtime.handle_message("/tools"))
            return 0
        if args.subcommand == "schema":
            suffix = f" name={args.name}" if args.name else ""
            print(runtime.handle_message("/schemas" + suffix))
            return 0
        if args.subcommand == "tool":
            result = runtime.registry.run(args.name, _parse_cli_args(args.arg))
            print(json.dumps(result.to_dict(), indent=2))
            return 0
        if args.subcommand == "status":
            result = runtime.registry.run("runtime_status", {})
            print(json.dumps(result.to_dict(), indent=2))
            return 0
        if args.subcommand == "export-pack":
            tool_args = {"out": args.out} if args.out else {}
            result = runtime.registry.run("export_pack", tool_args)
            print(json.dumps(result.to_dict(), indent=2))
            return 0
        if args.subcommand == "run-due":
            print(json.dumps({"jobs_run": runtime.run_due_jobs()}, indent=2))
            return 0
        if args.subcommand == "serve":
            gateway = AgentGateway(runtime, host=args.host, port=args.port)
            host, port = gateway.server_address
            print(json.dumps({"status": "listening", "host": host, "port": port, "session_id": runtime.session_id}, indent=2), flush=True)
            try:
                gateway.serve_forever()
            finally:
                gateway.shutdown()
            return 0
    finally:
        runtime.close()
    return 1


def _parse_cli_args(items: list[str]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--arg must be key=value, got: {item}")
        key, value = item.split("=", 1)
        parsed[key.replace("-", "_")] = _coerce(value)
    return parsed


def _coerce(value: str) -> object:
    lowered = value.lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    if lowered.isdigit():
        return int(lowered)
    if value.startswith("{") or value.startswith("["):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


if __name__ == "__main__":
    raise SystemExit(main())
