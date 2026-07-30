from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

from .agent_config import AgentAppConfig
from .agent_bridges import BridgeConfig, BridgeMessage, bridge_doctor, handle_bridge_message, run_bridge
from .agent_crypto import MAGIC as SEALED_MAGIC, seal_bytes, unseal_bytes
from .agent_gateway import AgentGateway, remote_client_html
from .agent_runtime import AgentRuntimeConfig, OffSecAgentRuntime
from .agent_store import AgentStore
from .models import EngagementROE


DEFAULT_DB = "data/phobos-agent.db"
_SAFE_SYSTEMD_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,96}$")
_SAFE_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}\$?$")
_SAFE_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]+$")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _validate_hostname(value: str) -> str:
    hostname = str(value).strip().rstrip(".")
    if not hostname or len(hostname) > 253 or any(ch.isspace() or ord(ch) < 32 for ch in hostname) or "/" in hostname:
        raise SystemExit("--domain must be a single hostname")
    labels = hostname.split(".")
    if any(not _HOST_LABEL_RE.match(label) for label in labels):
        raise SystemExit("--domain must contain only DNS hostname labels")
    return hostname


def _validate_systemd_name(value: str) -> str:
    service_name = str(value).strip()
    if not _SAFE_SYSTEMD_NAME_RE.match(service_name) or service_name.startswith("-") or service_name in {".", ".."}:
        raise SystemExit("--service-name may contain only letters, numbers, '.', '_', '@', and '-' and must not start with '-'")
    return service_name


def _validate_user(value: str) -> str:
    user = str(value).strip()
    if not _SAFE_USER_RE.match(user):
        raise SystemExit("--user must be a simple local service account name")
    return user


def _validate_env_name(value: str) -> str:
    env_name = str(value).strip()
    if not _SAFE_ENV_RE.match(env_name):
        raise SystemExit("--token-env must be a shell-safe environment variable name")
    return env_name


def _validate_install_dir(value: str) -> str:
    install_dir = str(value).strip().rstrip("/") or "/opt/phobos-agent"
    if not _SAFE_ABS_PATH_RE.match(install_dir) or "//" in install_dir:
        raise SystemExit("--install-dir must be an absolute path without whitespace or shell metacharacters")
    return install_dir


def _validate_port(value: int) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise SystemExit("--port must be between 1 and 65535")
    return port


def _validate_http_url(value: str, flag: str, *, allow_wildcard: bool = False, origin_only: bool = False) -> str:
    url = str(value).strip()
    if allow_wildcard and url == "*":
        return url
    if not url or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise SystemExit(f"{flag} must be an http(s) URL without whitespace")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise SystemExit(f"{flag} must be an http(s) URL without credentials")
    if parsed.query or parsed.fragment:
        raise SystemExit(f"{flag} must not include query strings or fragments")
    if origin_only and parsed.path not in {"", "/"}:
        raise SystemExit(f"{flag} must be an origin only, for example https://ui.example.com")
    if origin_only:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url.rstrip("/")


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

    preflight = sub.add_parser("preflight", help="Run a read-only Phobos safety/runtime readiness preflight")
    preflight.add_argument("--engagement", required=True)
    preflight.add_argument("--out", help="Optional Markdown output path under the engagement agent/preflight artifacts directory")

    evidence_manifest = sub.add_parser("evidence-manifest", help="Write a read-only SHA-256 evidence artifact inventory")
    evidence_manifest.add_argument("--engagement", required=True)
    evidence_manifest.add_argument("--out", help="Optional JSON output path under the engagement agent/manifests artifacts directory")
    evidence_manifest.add_argument("--limit", type=int, default=1000)
    evidence_manifest.add_argument("--max-bytes", type=int, default=50_000_000)
    evidence_manifest.add_argument("--exclude-agent", action="store_true", help="Exclude agent-generated artifacts from the inventory")

    closeout = sub.add_parser("closeout", help="Run a read-only closeout readiness review and write a redacted Markdown checklist")
    closeout.add_argument("--engagement", required=True)
    closeout.add_argument("--out", help="Optional Markdown output path under the engagement agent/closeout artifacts directory")

    export_pack = sub.add_parser("export-pack", help="Create a redacted engagement pack ZIP")
    export_pack.add_argument("--engagement", required=True)
    export_pack.add_argument("--out")

    jobs = sub.add_parser("run-due", help="Run due jobs for the session")
    jobs.add_argument("--engagement", required=True)

    serve = sub.add_parser("serve", help="Run a local or authenticated remote HTTP gateway for the agent")
    serve.add_argument("--engagement", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--token-env", help="Environment variable containing the gateway bearer token; required for non-local binds unless --unsafe-no-auth is used")
    serve.add_argument("--allow-origin", action="append", default=[], help="CORS origin allowed to call this gateway, e.g. https://ui.example.com or *; repeatable")
    serve.add_argument("--unsafe-no-auth", action="store_true", help="Allow a non-local bind without bearer auth; only for isolated throwaway test networks")

    ui_client = sub.add_parser("ui-client", help="Write a standalone browser UI that can connect to a local or VPS-hosted Phobos gateway")
    ui_client.add_argument("--out", default="phobos-remote-ui.html")
    ui_client.add_argument("--agent-url", default="", help="Optional default gateway URL to prefill, e.g. https://agent.example.com")

    bridge_doctor_parser = sub.add_parser("bridge-doctor", help="Check live bridge token/auth readiness without sending messages")
    bridge_doctor_parser.add_argument("--platform", action="append", choices=["all", "discord", "slack", "telegram"], default=[], help="Platform to check; repeatable; default all")
    bridge_doctor_parser.add_argument("--timeout", type=float, default=15.0, help="Per-platform auth-check timeout in seconds")

    deploy = sub.add_parser("deploy-kit", help="Write systemd/nginx/env/firewall templates for a token-authenticated VPS deployment")
    deploy.add_argument("--out", required=True, help="Output directory for deployment templates")
    deploy.add_argument("--domain", required=True, help="Public HTTPS hostname, e.g. phobos.example.com")
    deploy.add_argument("--user", default="phobos", help="Service user on the VPS")
    deploy.add_argument("--install-dir", default="/opt/phobos-agent", help="Project checkout/install directory on the VPS")
    deploy.add_argument("--service-name", default="phobos-agent", help="systemd service name")
    deploy.add_argument("--port", type=int, default=8765, help="Local gateway port behind reverse proxy")
    deploy.add_argument("--token-env", default="PHOBOS_GATEWAY_TOKEN", help="Environment variable name used by the service for bearer auth")
    deploy.add_argument("--allow-origin", action="append", default=[], help="Allowed browser UI origin; repeatable; defaults to https://<domain>")
    deploy.add_argument("--agent-url", help="URL prefilled in generated browser client; defaults to https://<domain>")

    discord = sub.add_parser("discord", help="Run a Discord bot bridge for an allowlisted channel/thread or DM")
    discord.add_argument("--engagement", required=True)
    _add_bridge_args(discord, token=True, discord=True)

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
    _add_bridge_args(bridge_test, token=True, slack=True, discord=True)

    return parser


def _add_bridge_args(parser: argparse.ArgumentParser, *, token: bool = False, slack: bool = False, discord: bool = False) -> None:
    parser.add_argument("--allow-channel", action="append", default=[], help="Allow a platform channel/thread/chat ID; repeatable")
    parser.add_argument("--allow-user", action="append", default=[], help="Allow a platform user ID; repeatable")
    parser.add_argument("--allow-all", action="store_true", help="Accept messages from any channel/user; unsafe outside a private deployment")
    parser.add_argument("--allow-approval-actions", action="store_true", help="Allow /approve and /deny through this bridge; disabled by default")
    parser.add_argument("--prefix", help="Require and strip a command prefix, e.g. !phobos")
    parser.add_argument("--mention-required", action="store_true", help="Require a bot mention outside private messages")
    parser.add_argument("--max-response-chars", type=int, help="Per-message response chunk size")
    parser.add_argument("--max-message-chars", type=int, help="Maximum incoming message length to process")
    parser.add_argument("--no-response-polish", action="store_true", help="Send raw runtime output instead of concise chat-polished bridge responses")
    if discord:
        parser.add_argument("--discord-thread-mode", choices=["off", "per-message", "hermes"], help="Discord-only: create a response thread for each top-level allowlisted message")
        parser.add_argument("--discord-thread-name-prefix", help="Discord-only: prefix for auto-created thread names")
        parser.add_argument("--discord-thread-auto-archive-duration", type=int, choices=[60, 1440, 4320, 10080], help="Discord-only: auto-archive duration for created threads")
        parser.add_argument("--no-discord-thread-continuation", action="store_true", help="Discord-only: require prefix/mention even inside bridge-created/parent-allowlisted threads")
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
        cfg = AgentAppConfig.load(config_path).to_runtime_config(args.engagement, db_path, args.session, config_path=str(config_path))
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
    if args.subcommand == "ui-client":
        out = Path(args.out).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(remote_client_html(default_base_url=args.agent_url), encoding="utf-8")
        print(json.dumps({"status": "written", "ui": str(out), "agent_url_prefilled": bool(args.agent_url)}, indent=2))
        return 0
    if args.subcommand == "bridge-doctor":
        result = bridge_doctor(args.platform or None, timeout=float(args.timeout))
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 2
    if args.subcommand == "deploy-kit":
        return _write_deploy_kit(args)

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
        if args.subcommand == "preflight":
            tool_args = {"out": args.out} if args.out else {}
            result = runtime.registry.run("safety_preflight", tool_args)
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.status == "ok" else 2
        if args.subcommand == "evidence-manifest":
            result = runtime.registry.run("evidence_manifest", {
                "out": args.out or "",
                "limit": args.limit,
                "max_bytes": args.max_bytes,
                "include_agent": not args.exclude_agent,
            })
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.status == "ok" else 2
        if args.subcommand == "closeout":
            tool_args = {"out": args.out} if args.out else {}
            result = runtime.registry.run("closeout_review", tool_args)
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.status == "ok" else 2
        if args.subcommand == "export-pack":
            tool_args = {"out": args.out} if args.out else {}
            result = runtime.registry.run("export_pack", tool_args)
            print(json.dumps(result.to_dict(), indent=2))
            return 0
        if args.subcommand == "run-due":
            print(json.dumps({"jobs_run": runtime.run_due_jobs()}, indent=2))
            return 0
        if args.subcommand == "serve":
            gateway = AgentGateway(runtime, host=args.host, port=args.port, token_env=args.token_env, allow_origins=tuple(args.allow_origin or ()), unsafe_no_auth=bool(args.unsafe_no_auth))
            host, port = gateway.server_address
            print(json.dumps({"status": "listening", "host": host, "port": port, "session_id": runtime.session_id, "auth_required": gateway.auth_required, "token_env": args.token_env or "", "allow_origins": list(args.allow_origin or ()), "ui_client": f"http://{host}:{port}/ui-client"}, indent=2), flush=True)
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
    if getattr(args, "no_response_polish", False):
        data["response_polish"] = False
    if getattr(args, "discord_thread_mode", None):
        data["discord_thread_mode"] = args.discord_thread_mode
    if getattr(args, "discord_thread_name_prefix", None):
        data["discord_thread_name_prefix"] = args.discord_thread_name_prefix
    if getattr(args, "discord_thread_auto_archive_duration", None):
        data["discord_thread_auto_archive_duration"] = args.discord_thread_auto_archive_duration
    if getattr(args, "no_discord_thread_continuation", False):
        data["discord_thread_continue_without_trigger"] = False
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


def _write_deploy_kit(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser()
    domain = _validate_hostname(args.domain)
    service_name = _validate_systemd_name(args.service_name or "phobos-agent")
    user = _validate_user(args.user or "phobos")
    install_dir = _validate_install_dir(args.install_dir or "/opt/phobos-agent")
    port = _validate_port(args.port)
    token_env = _validate_env_name(args.token_env or "PHOBOS_GATEWAY_TOKEN")
    origins = [_validate_http_url(origin, "--allow-origin", allow_wildcard=True, origin_only=True) for origin in (args.allow_origin or [])]
    if not origins:
        origins = [f"https://{domain}"]
    agent_url = _validate_http_url(str(args.agent_url or f"https://{domain}"), "--agent-url")
    out.mkdir(parents=True, exist_ok=True)
    origin_flags = " ".join(f"--allow-origin {origin}" for origin in origins)
    files: dict[str, str] = {}
    files[f"{service_name}.service"] = f"""[Unit]
Description=Phobos Agent authenticated gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={install_dir}
EnvironmentFile=/etc/phobos-agent/{service_name}.env
ExecStart={install_dir}/.venv/bin/phobos-agent --db /var/lib/phobos-agent/phobos-agent.db --config /etc/phobos-agent/agent.config.json serve --engagement /etc/phobos-agent/engagement.json --host 127.0.0.1 --port {port} --token-env {token_env} {origin_flags}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/phobos-agent /var/log/phobos-agent

[Install]
WantedBy=multi-user.target
"""
    files["nginx-phobos-agent.conf"] = f"""server {{
    listen 443 ssl http2;
    server_name {domain};

    # Install certificates with certbot/acme.sh or your existing TLS workflow.
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}

server {{
    listen 80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}
"""
    files[f"{service_name}.env.template"] = f"""# Copy to /etc/phobos-agent/{service_name}.env with mode 0600 and set a long random secret.
{token_env}=REPLACE_WITH_LONG_RANDOM_SECRET
"""
    files["ufw-commands.sh"] = f"""#!/usr/bin/env bash
set -euo pipefail
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny {port}/tcp || true
ufw status verbose
"""
    files["ssh-tunnel-example.sh"] = f"""#!/usr/bin/env bash
set -euo pipefail
# Alternative to public reverse-proxy access: keep Phobos bound to 127.0.0.1 on the VPS
# and tunnel the gateway to your workstation.
ssh -L {port}:127.0.0.1:{port} {user}@{domain}
"""
    files["phobos-remote-ui.html"] = remote_client_html(default_base_url=agent_url)
    files["README.md"] = f"""# Phobos Agent VPS Deployment Kit

This kit keeps Phobos local-first while allowing an authenticated browser UI to connect to a VPS-hosted agent.

## Files

- `{service_name}.service` — hardened-ish systemd unit that binds Phobos to `127.0.0.1:{port}` and requires bearer auth from `{token_env}`.
- `nginx-phobos-agent.conf` — TLS reverse-proxy example for `{domain}`.
- `{service_name}.env.template` — token env template; replace the placeholder on the VPS, never commit the real value.
- `ufw-commands.sh` — firewall sketch: expose SSH/HTTP/HTTPS only; deny direct gateway port access.
- `ssh-tunnel-example.sh` — VPN/SSH-tunnel alternative.
- `phobos-remote-ui.html` — standalone browser client prefilled with `{agent_url}`.

## Security posture

- Do not expose the stdlib gateway directly to the internet.
- Keep Phobos bound to `127.0.0.1` behind nginx/Caddy/Traefik or access it over VPN/SSH tunnel.
- Use HTTPS, a long random `{token_env}`, firewall rules, and least-privilege service user permissions.
- The UI is single-operator/minimal; it is not a multi-user RBAC console.
"""
    written = []
    for rel, content in files.items():
        path = out / rel
        path.write_text(content, encoding="utf-8")
        if path.suffix == ".sh":
            path.chmod(0o755)
        written.append(str(path))
    print(json.dumps({"status": "written", "dir": str(out), "files": written, "token_value_written": False, "auth_required": True, "bind_host": "127.0.0.1", "agent_url": agent_url, "allow_origins": origins}, indent=2))
    return 0
