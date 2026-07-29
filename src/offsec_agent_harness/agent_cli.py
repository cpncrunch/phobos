from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path

from .agent_config import AgentAppConfig
from .agent_bridges import BridgeConfig, BridgeMessage, handle_bridge_message, run_bridge
from .agent_crypto import MAGIC as SEALED_MAGIC, seal_bytes, unseal_bytes
from .agent_gateway import AgentGateway
from .agent_runtime import AgentRuntimeConfig, OffSecAgentRuntime
from .agent_store import AgentStore
from .models import EngagementROE


DEFAULT_DB = "data/phobos-agent.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone Phobos Agent runtime")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite runtime DB path")
    parser.add_argument("--profile", help="Use/create a named local profile under ~/.phobos/profiles/<name>")
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
    parser.add_argument("--auto-model-planning", action="store_true", help="Allow /auto model=true or configured natural planning to ask the configured model for JSON tool plans; registry policy and ROE still apply")
    parser.add_argument("--max-auto-steps", type=int, help="Maximum bounded /auto-loop steps")
    parser.add_argument("--block-tool", action="append", default=[], help="Block a registered tool by name at runtime policy level")
    parser.add_argument("--confirm-tool", action="append", default=[], help="Queue a registered tool for approval before execution")
    parser.add_argument("--skill-dir", action="append", default=[], help="Directory containing local Hermes-style SKILL.md files")
    parser.add_argument("--preload-skill", action="append", default=[], help="Local skill name to load at runtime startup")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    config_init = sub.add_parser("config-init", help="Write a default agent runtime config JSON")
    config_init.add_argument("--out", default="agent.config.json")

    profile_init = sub.add_parser("profile-init", help="Create a named local Phobos profile under ~/.phobos/profiles")
    profile_init.add_argument("--name", required=True)

    sub.add_parser("profiles", help="List local Phobos profiles")

    sub.add_parser("db-status", help="Show plaintext DB/WAL/SHM file presence and sizes without reading secrets")

    db_seal = sub.add_parser("db-seal", help="Seal a SQLite DB file into an authenticated encrypted at-rest backup using a passphrase env var")
    db_seal.add_argument("--out", required=True, help="Output sealed DB JSON file")
    db_seal.add_argument("--passphrase-env", required=True, help="Environment variable containing the sealing passphrase")
    db_seal.add_argument("--remove-plaintext", action="store_true", help="After successful seal, remove plaintext DB/WAL/SHM files; use only after closing runtimes")

    seal_db = sub.add_parser("seal-db", help="Alias for db-seal")
    seal_db.add_argument("--out", required=True, help="Output sealed DB JSON file")
    seal_db.add_argument("--passphrase-env", required=True, help="Environment variable containing the sealing passphrase")
    seal_db.add_argument("--remove-plaintext", action="store_true", help="After successful seal, remove plaintext DB/WAL/SHM files; use only after closing runtimes")

    db_unseal = sub.add_parser("db-unseal", help="Unseal an encrypted DB backup into a SQLite DB file using a passphrase env var")
    db_unseal.add_argument("--in", dest="sealed_path", required=True, help="Input sealed DB JSON file")
    db_unseal.add_argument("--out", help="Output DB path; defaults to --db")
    db_unseal.add_argument("--passphrase-env", required=True, help="Environment variable containing the sealing passphrase")
    db_unseal.add_argument("--overwrite", action="store_true", help="Overwrite output DB if it already exists")

    unseal_db = sub.add_parser("unseal-db", help="Alias for db-unseal")
    unseal_db.add_argument("--in", dest="sealed_path", required=True, help="Input sealed DB JSON file")
    unseal_db.add_argument("--out", help="Output DB path; defaults to --db")
    unseal_db.add_argument("--passphrase-env", required=True, help="Environment variable containing the sealing passphrase")
    unseal_db.add_argument("--overwrite", action="store_true", help="Overwrite output DB if it already exists")

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

    auth_status = sub.add_parser("auth-status", help="Check configured auth/token environment variables without revealing values")
    auth_status.add_argument("--engagement", required=True)

    export_pack = sub.add_parser("export-pack", help="Create a redacted engagement pack ZIP")
    export_pack.add_argument("--engagement", required=True)
    export_pack.add_argument("--out")

    jobs = sub.add_parser("run-due", help="Run due jobs for the session")
    jobs.add_argument("--engagement", required=True)

    serve = sub.add_parser("serve", help="Run a local HTTP gateway for the agent")
    serve.add_argument("--engagement", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    discord = sub.add_parser("discord", help="Run a Discord bot bridge for an allowlisted channel/thread or DM")
    discord.add_argument("--engagement", required=True)
    _add_bridge_args(discord, token=True)

    slack = sub.add_parser("slack", help="Run a Slack Socket Mode bridge for an allowlisted channel or DM")
    slack.add_argument("--engagement", required=True)
    _add_bridge_args(slack, slack=True)

    telegram = sub.add_parser("telegram", help="Run a Telegram long-polling bridge for an allowlisted chat or private DM")
    telegram.add_argument("--engagement", required=True)
    _add_bridge_args(telegram, token=True)

    bridge_test = sub.add_parser("bridge-test", help="Offline-test bridge filtering and runtime dispatch without platform network access")
    bridge_test.add_argument("--engagement", required=True)
    bridge_test.add_argument("--platform", required=True, choices=["discord", "slack", "telegram"])
    bridge_test.add_argument("--message", required=True)
    bridge_test.add_argument("--channel-id", required=True)
    bridge_test.add_argument("--user-id", required=True)
    bridge_test.add_argument("--message-id", default="offline-test")
    bridge_test.add_argument("--bot-user-id", default="")
    bridge_test.add_argument("--private", action="store_true", help="Treat the test message as a DM/private chat")
    bridge_test.add_argument("--bot", action="store_true", help="Treat the test sender as a bot")
    bridge_test.add_argument("--attachment-local-path", action="append", default=[], help="Offline bridge-test attachment local path to import as media evidence; repeatable")
    bridge_test.add_argument("--attachment-url", action="append", default=[], help="Offline bridge-test remote attachment URL metadata to record; repeatable")
    bridge_test.add_argument("--attachment-mime", default="application/octet-stream", help="MIME type for offline bridge-test attachments")
    bridge_test.add_argument("--attachment-kind", default="", help="Optional kind for offline bridge-test attachments: image/audio/video/file")
    _add_bridge_args(bridge_test, token=True, slack=True)

    return parser


def _add_bridge_args(parser: argparse.ArgumentParser, *, token: bool = False, slack: bool = False) -> None:
    parser.add_argument("--allow-channel", action="append", default=[], help="Allow a platform channel/thread/chat ID; repeatable")
    parser.add_argument("--allow-user", action="append", default=[], help="Allow a platform user ID; repeatable")
    parser.add_argument("--allow-all", action="store_true", help="Accept messages from any channel/user; unsafe outside a private deployment")
    parser.add_argument("--allow-approval-actions", action="store_true", help="Allow /approve and /deny through this bridge; disabled by default")
    parser.add_argument("--prefix", help="Require and strip a command prefix, e.g. !phobos")
    parser.add_argument("--mention-required", action="store_true", help="Require a bot mention outside private messages")
    parser.add_argument("--max-response-chars", type=int, help="Per-message response chunk size")
    parser.add_argument("--max-message-chars", type=int, help="Maximum incoming message length to process")
    if token:
        parser.add_argument("--token-env", help="Environment variable containing the platform bot token")
    if slack:
        parser.add_argument("--bot-token-env", help="Environment variable containing the Slack bot token (xoxb-...)")
        parser.add_argument("--app-token-env", help="Environment variable containing the Slack app-level Socket Mode token (xapp-...)")


def _profiles_root() -> Path:
    return Path.home() / ".phobos" / "profiles"


def _profile_dir(name: str) -> Path:
    cleaned = str(name).strip()
    if not cleaned:
        raise SystemExit("profile name is required")
    if any(part in {"", ".", ".."} for part in Path(cleaned).parts) or any(sep in cleaned for sep in ("/", "\\")):
        raise SystemExit("profile names must be simple names, not paths")
    return _profiles_root() / cleaned


def _config(args: argparse.Namespace) -> AgentRuntimeConfig:
    profile_dir = _profile_dir(args.profile) if getattr(args, "profile", None) else None
    config_path = args.config
    db_path = args.db
    if profile_dir is not None:
        if db_path == DEFAULT_DB:
            db_path = str(profile_dir / "phobos-agent.db")
        if not config_path and (profile_dir / "agent.config.json").exists():
            config_path = str(profile_dir / "agent.config.json")
    if config_path:
        cfg = AgentAppConfig.load(config_path).to_runtime_config(args.engagement, db_path, args.session)
    else:
        cfg = AgentRuntimeConfig(
            engagement_path=args.engagement,
            db_path=db_path,
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
    if args.auto_model_planning:
        cfg.auto_model_planning = True
    if args.max_auto_steps is not None:
        cfg.max_auto_steps = args.max_auto_steps
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
    if args.subcommand == "profile-init":
        profile_dir = _profile_dir(args.name)
        profile_dir.mkdir(parents=True, exist_ok=True)
        config_path = profile_dir / "agent.config.json"
        if not config_path.exists():
            AgentAppConfig.default().save(config_path)
        print(json.dumps({"status": "written", "profile": args.name, "dir": str(profile_dir), "config": str(config_path), "db": str(profile_dir / "phobos-agent.db")}, indent=2))
        return 0
    if args.subcommand == "profiles":
        root = _profiles_root()
        profiles = []
        if root.exists():
            for path in sorted(item for item in root.iterdir() if item.is_dir()):
                profiles.append({"name": path.name, "dir": str(path), "config_exists": (path / "agent.config.json").exists(), "db_exists": (path / "phobos-agent.db").exists()})
        print(json.dumps({"profiles_root": str(root), "profiles": profiles}, indent=2))
        return 0
    if args.subcommand == "db-status":
        return _db_status(args)
    if args.subcommand in {"db-seal", "seal-db"}:
        return _db_seal(args)
    if args.subcommand in {"db-unseal", "unseal-db"}:
        return _db_unseal(args)

    if args.subcommand == "init":
        roe = EngagementROE.load(args.engagement)
        cfg = _config(args)
        store = AgentStore(cfg.db_path)
        session_id = store.get_or_create_session(args.session, args.engagement)
        bridge_configs = {name: BridgeConfig.from_dict(name, data).sanitized() for name, data in (cfg.bridges or {}).items()}
        store.audit(session_id, "agent_init", {"engagement": roe.name, "scope": roe.in_scope_targets, "safety_mode": roe.safety_mode, "workspace_dir": cfg.workspace_dir, "plugin_dirs": list(cfg.plugin_dirs), "blocked_tools": list(cfg.blocked_tools), "confirm_tools": list(cfg.confirm_tools), "skill_dirs": list(cfg.skill_dirs), "preload_skills": list(cfg.preload_skills), "bridges": bridge_configs})
        store.close()
        print(json.dumps({"db": cfg.db_path, "session_id": session_id, "engagement": roe.to_dict(), "runtime": {"workspace_dir": cfg.workspace_dir, "plugin_dirs": list(cfg.plugin_dirs), "blocked_tools": list(cfg.blocked_tools), "confirm_tools": list(cfg.confirm_tools), "skill_dirs": list(cfg.skill_dirs), "preload_skills": list(cfg.preload_skills), "skill_bundles": {name: list(skills) for name, skills in (cfg.skill_bundles or {}).items()}, "bridges": bridge_configs, "provider_chain": list(cfg.model_providers) or [{"provider": cfg.provider, "model": cfg.model}]}}, indent=2))
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
        if args.subcommand == "auth-status":
            result = runtime.registry.run("auth_status", {})
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
        if args.subcommand in {"discord", "slack", "telegram"}:
            bridge_config = _bridge_config(args, runtime.config, args.subcommand)
            print(json.dumps({"status": "bridge-starting", "platform": args.subcommand, "session_id": runtime.session_id, "bridge": bridge_config.sanitized()}, indent=2), flush=True)
            run_bridge(args.subcommand, runtime, bridge_config)
            return 0
        if args.subcommand == "bridge-test":
            bridge_config = _bridge_config(args, runtime.config, args.platform)
            attachments = []
            for path in getattr(args, "attachment_local_path", []) or []:
                attachments.append({"local_path": str(path), "mime_type": args.attachment_mime, "kind": args.attachment_kind or None, "name": Path(str(path)).name})
            for url in getattr(args, "attachment_url", []) or []:
                attachments.append({"url": str(url), "mime_type": args.attachment_mime, "kind": args.attachment_kind or None, "name": Path(str(url)).name or "remote-attachment"})
            message = BridgeMessage(
                platform=args.platform,
                text=args.message,
                channel_id=str(args.channel_id),
                user_id=str(args.user_id),
                message_id=str(args.message_id),
                is_bot=bool(args.bot),
                is_private=bool(args.private),
                attachments=attachments,
            )
            result = handle_bridge_message(runtime, message, bridge_config, bot_user_id=args.bot_user_id or None)
            print(json.dumps({"bridge": bridge_config.sanitized(), "result": result.to_dict()}, indent=2))
            return 0
    finally:
        runtime.close()
    return 1


def _db_seal(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    passphrase = os.environ.get(str(args.passphrase_env), "")
    if not passphrase:
        raise SystemExit("passphrase env var is not set; secret values must be supplied through the environment")
    if not db_path.exists() or not db_path.is_file():
        raise SystemExit(f"DB file not found: {db_path}")
    _checkpoint_sqlite(db_path)
    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    sealed = seal_bytes(db_path.read_bytes(), passphrase, aad=b"phobos-agent-sealed-db")
    out.write_bytes(sealed)
    removed = []
    if getattr(args, "remove_plaintext", False):
        for path in _db_plaintext_paths(db_path):
            if path.exists():
                path.unlink()
                removed.append(str(path))
    print(json.dumps({"status": "sealed", "db": str(db_path), "sealed": str(out), "format": SEALED_MAGIC, "passphrase_env": str(args.passphrase_env), "plaintext_db_still_exists": db_path.exists(), "removed_plaintext": removed}, indent=2))
    return 0


def _db_unseal(args: argparse.Namespace) -> int:
    passphrase = os.environ.get(str(args.passphrase_env), "")
    if not passphrase:
        raise SystemExit("passphrase env var is not set; secret values must be supplied through the environment")
    sealed_path = Path(args.sealed_path).expanduser()
    if not sealed_path.exists() or not sealed_path.is_file():
        raise SystemExit(f"Sealed DB file not found: {sealed_path}")
    out = Path(args.out or args.db).expanduser()
    if out.exists() and not args.overwrite:
        raise SystemExit(f"Output DB already exists: {out}; pass --overwrite to replace it")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(unseal_bytes(sealed_path.read_bytes(), passphrase, aad=b"phobos-agent-sealed-db"))
    print(json.dumps({"status": "unsealed", "sealed": str(sealed_path), "db": str(out), "passphrase_env": str(args.passphrase_env)}, indent=2))
    return 0


def _db_status(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    files = []
    for path in _db_plaintext_paths(db_path):
        files.append({"path": str(path), "exists": path.exists(), "bytes": path.stat().st_size if path.exists() else 0})
    print(json.dumps({"db": str(db_path), "plaintext_files": files}, indent=2))
    return 0


def _db_plaintext_paths(db_path: Path) -> list[Path]:
    return [db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")]


def _checkpoint_sqlite(db_path: Path) -> None:
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        # If checkpointing fails, sealing the main DB is still useful; callers can
        # re-run with the runtime closed or inspect db-status for leftover WAL.
        return


def _bridge_config(args: argparse.Namespace, runtime_config: AgentRuntimeConfig, platform: str) -> BridgeConfig:
    bridges = runtime_config.bridges or {}
    data = dict(bridges.get(platform, {})) if isinstance(bridges, dict) else {}
    if getattr(args, "allow_channel", None):
        data["allowed_channel_ids"] = list(data.get("allowed_channel_ids", [])) + [str(item) for item in args.allow_channel]
    if getattr(args, "allow_user", None):
        data["allowed_user_ids"] = list(data.get("allowed_user_ids", [])) + [str(item) for item in args.allow_user]
    if getattr(args, "allow_all", False):
        data["allow_all"] = True
    if getattr(args, "allow_approval_actions", False):
        data["allow_approval_actions"] = True
    if getattr(args, "prefix", None) is not None:
        data["command_prefix"] = args.prefix
    if getattr(args, "mention_required", False):
        data["mention_required"] = True
    if getattr(args, "token_env", None):
        data["token_env"] = args.token_env
    if getattr(args, "bot_token_env", None):
        data["bot_token_env"] = args.bot_token_env
    if getattr(args, "app_token_env", None):
        data["app_token_env"] = args.app_token_env
    if getattr(args, "max_response_chars", None):
        data["max_response_chars"] = args.max_response_chars
    if getattr(args, "max_message_chars", None):
        data["max_message_chars"] = args.max_message_chars
    return BridgeConfig.from_dict(platform, data)


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
