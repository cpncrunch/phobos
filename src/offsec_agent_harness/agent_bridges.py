from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
import base64
import hashlib
import json
import os
import random
import re
import socket
import ssl
import struct
import time

from .models import redact_secrets

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from .agent_runtime import OffSecAgentRuntime


BRIDGE_DEFAULTS: dict[str, dict[str, Any]] = {
    "discord": {
        "enabled": False,
        "token_env": "PHOBOS_DISCORD_TOKEN",
        "allowed_channel_ids": [],
        "allowed_user_ids": [],
        "command_prefix": "",
        "mention_required": False,
        "allow_all": False,
        "allow_approval_actions": False,
        "import_attachments": True,
        "max_attachment_bytes": 10_000_000,
        "ignore_bots": True,
        "max_response_chars": 1800,
        "max_message_chars": 4000,
        "poll_interval": 2.0,
    },
    "slack": {
        "enabled": False,
        "bot_token_env": "PHOBOS_SLACK_BOT_TOKEN",
        "app_token_env": "PHOBOS_SLACK_APP_TOKEN",
        "allowed_channel_ids": [],
        "allowed_user_ids": [],
        "command_prefix": "",
        "mention_required": False,
        "allow_all": False,
        "allow_approval_actions": False,
        "import_attachments": True,
        "max_attachment_bytes": 10_000_000,
        "ignore_bots": True,
        "max_response_chars": 3000,
        "max_message_chars": 4000,
        "poll_interval": 2.0,
    },
    "telegram": {
        "enabled": False,
        "token_env": "PHOBOS_TELEGRAM_TOKEN",
        "allowed_channel_ids": [],
        "allowed_user_ids": [],
        "command_prefix": "",
        "mention_required": False,
        "allow_all": False,
        "allow_approval_actions": False,
        "import_attachments": True,
        "max_attachment_bytes": 10_000_000,
        "ignore_bots": True,
        "max_response_chars": 3500,
        "max_message_chars": 4000,
        "poll_interval": 2.0,
    },
}


@dataclass(slots=True)
class BridgeConfig:
    platform: str
    enabled: bool = False
    token_env: str = ""
    bot_token_env: str = ""
    app_token_env: str = ""
    allowed_channel_ids: tuple[str, ...] = ()
    allowed_user_ids: tuple[str, ...] = ()
    command_prefix: str = ""
    mention_required: bool = False
    allow_all: bool = False
    allow_approval_actions: bool = False
    import_attachments: bool = True
    max_attachment_bytes: int = 10_000_000
    ignore_bots: bool = True
    max_response_chars: int = 1800
    max_message_chars: int = 4000
    poll_interval: float = 2.0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, platform: str, data: dict[str, Any] | None = None) -> "BridgeConfig":
        defaults = dict(BRIDGE_DEFAULTS.get(platform, {}))
        merged = defaults | dict(data or {})
        known = {
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
            "import_attachments",
            "max_attachment_bytes",
            "ignore_bots",
            "max_response_chars",
            "max_message_chars",
            "poll_interval",
        }
        extra = {key: value for key, value in merged.items() if key not in known}
        return cls(
            platform=platform,
            enabled=bool(merged.get("enabled", False)),
            token_env=str(merged.get("token_env", "")),
            bot_token_env=str(merged.get("bot_token_env", "")),
            app_token_env=str(merged.get("app_token_env", "")),
            allowed_channel_ids=_tuple_of_strings(merged.get("allowed_channel_ids", ())),
            allowed_user_ids=_tuple_of_strings(merged.get("allowed_user_ids", ())),
            command_prefix=str(merged.get("command_prefix", "")),
            mention_required=bool(merged.get("mention_required", False)),
            allow_all=bool(merged.get("allow_all", False)),
            allow_approval_actions=bool(merged.get("allow_approval_actions", False)),
            import_attachments=bool(merged.get("import_attachments", True)),
            max_attachment_bytes=max(0, int(merged.get("max_attachment_bytes", 10_000_000))),
            ignore_bots=bool(merged.get("ignore_bots", True)),
            max_response_chars=max(200, int(merged.get("max_response_chars", 1800))),
            max_message_chars=max(200, int(merged.get("max_message_chars", 4000))),
            poll_interval=max(0.1, float(merged.get("poll_interval", 2.0))),
            extra=extra,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["allowed_channel_ids"] = list(self.allowed_channel_ids)
        data["allowed_user_ids"] = list(self.allowed_user_ids)
        return data

    def sanitized(self) -> dict[str, Any]:
        data = self.to_dict()
        for key in ["token", "bot_token", "app_token"]:
            data.pop(key, None)
        redacted = _redact_value(data)
        return redacted if isinstance(redacted, dict) else data


def default_bridge_configs() -> dict[str, dict[str, Any]]:
    return json.loads(json.dumps(BRIDGE_DEFAULTS))


@dataclass(slots=True)
class BridgeMessage:
    platform: str
    text: str
    channel_id: str
    user_id: str
    message_id: str = ""
    user_name: str = ""
    is_bot: bool = False
    is_private: bool = False
    attachments: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "channel_id": self.channel_id,
            "user_id": self.user_id,
            "message_id": self.message_id,
            "user_name": self.user_name,
            "is_bot": self.is_bot,
            "is_private": self.is_private,
            "attachment_count": len(self.attachments),
        }


@dataclass(slots=True)
class BridgeDispatchResult:
    status: str
    reason: str = ""
    normalized_text: str = ""
    response: str = ""
    chunks: list[str] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def bridge_config_from_runtime(runtime_config: Any, platform: str, overrides: dict[str, Any] | None = None) -> BridgeConfig:
    bridges = getattr(runtime_config, "bridges", None) or {}
    data = dict(bridges.get(platform, {})) if isinstance(bridges, dict) else {}
    if overrides:
        data.update({key: value for key, value in overrides.items() if value is not None})
    return BridgeConfig.from_dict(platform, data)


def handle_bridge_message(
    runtime: "OffSecAgentRuntime",
    message: BridgeMessage,
    config: BridgeConfig,
    *,
    bot_user_id: str | None = None,
) -> BridgeDispatchResult:
    allowed, reason = _allow_message(message, config)
    if not allowed:
        return BridgeDispatchResult("ignored", reason=reason)
    normalized, trigger_reason = normalize_bridge_text(message.text, config, bot_user_id=bot_user_id, is_private=message.is_private)
    if not normalized:
        if message.attachments and config.import_attachments:
            imported = _import_bridge_attachments(runtime, message, config)
            if _attachment_import_blocked(imported):
                response = "Bridge attachment rejected before dispatch; no text command was executed."
                runtime.store.audit(runtime.session_id, "bridge_attachment_blocked", message.audit_metadata() | {"attachments": _redact_value(imported)})
                return BridgeDispatchResult("blocked", reason="attachment-too-large", normalized_text="", response=response, chunks=chunk_text(response, config.max_response_chars), attachments=imported)
            response = f"Imported/listed {len(imported)} bridge media/voice attachment(s); no text command was executed."
            runtime.store.audit(runtime.session_id, "bridge_attachments_handled", message.audit_metadata() | {"attachments": _redact_value(imported)})
            return BridgeDispatchResult("handled", reason="attachments", normalized_text="", response=response, chunks=chunk_text(response, config.max_response_chars), attachments=imported)
        return BridgeDispatchResult("ignored", reason=trigger_reason or "empty-message")
    if len(normalized) > config.max_message_chars:
        response = f"Message ignored: exceeds max_message_chars={config.max_message_chars}."
        return BridgeDispatchResult("error", reason="message-too-long", normalized_text="", response=response, chunks=chunk_text(response, config.max_response_chars))
    if _is_approval_action(normalized) and not config.allow_approval_actions:
        response = "Bridge approval actions are disabled by default; use the local CLI/gateway or set allow_approval_actions=true for this bridge."
        runtime.store.audit(runtime.session_id, "bridge_message_blocked", message.audit_metadata() | {"reason": "approval-action-disabled"})
        return BridgeDispatchResult("blocked", reason="approval-action-disabled", normalized_text=normalized, response=response, chunks=chunk_text(response, config.max_response_chars))
    imported_attachments = _import_bridge_attachments(runtime, message, config)
    if _attachment_import_blocked(imported_attachments):
        response = "Bridge attachment rejected before dispatch; no text command was executed."
        runtime.store.audit(runtime.session_id, "bridge_attachment_blocked", message.audit_metadata() | {"attachments": _redact_value(imported_attachments)})
        return BridgeDispatchResult("blocked", reason="attachment-too-large", normalized_text=normalized, response=response, chunks=chunk_text(response, config.max_response_chars), attachments=imported_attachments)
    metadata = message.audit_metadata() | {"normalized_preview": redact_secrets(normalized[:200])}
    if imported_attachments:
        metadata["attachments"] = _redact_value(imported_attachments)
    runtime.store.audit(runtime.session_id, "bridge_message_received", metadata)
    try:
        response = runtime.handle_message(normalized)
        status = "handled"
        runtime.store.audit(runtime.session_id, "bridge_message_handled", message.audit_metadata() | {"response_preview": redact_secrets(response[:300])})
    except Exception as exc:  # pragma: no cover - defensive runtime boundary
        response = f"Phobos bridge error: {exc}"
        status = "error"
        runtime.store.audit(runtime.session_id, "bridge_message_error", message.audit_metadata() | {"error": str(exc)})
    chunks = chunk_text(response, config.max_response_chars)
    return BridgeDispatchResult(status, reason=trigger_reason, normalized_text=normalized, response=response, chunks=chunks, attachments=imported_attachments)


def _import_bridge_attachments(runtime: "OffSecAgentRuntime", message: BridgeMessage, config: BridgeConfig) -> list[dict[str, Any]]:
    if not config.import_attachments or not message.attachments:
        return []
    imported: list[dict[str, Any]] = []
    for index, attachment in enumerate(message.attachments, 1):
        size = _int_value(attachment.get("size"), 0)
        name = str(attachment.get("name") or attachment.get("filename") or f"attachment-{index}")
        mime_type = str(attachment.get("mime_type") or attachment.get("content_type") or attachment.get("mimetype") or "application/octet-stream")
        kind = str(attachment.get("kind") or _kind_from_mime(mime_type)).strip() or "file"
        metadata = {
            "platform": message.platform,
            "channel_id": message.channel_id,
            "message_id": message.message_id,
            "user_id": message.user_id,
            "name": name,
            "mime_type": mime_type,
            "kind": kind,
            "size": size,
        }
        if size and config.max_attachment_bytes and size > config.max_attachment_bytes:
            imported.append(metadata | {"status": "skipped", "reason": "attachment-too-large"})
            continue
        local_path = str(attachment.get("local_path") or "").strip()
        if local_path:
            result = runtime.registry.run("media_import", {"path": local_path, "kind": kind})
            item = metadata | {"status": result.status, "tool_message": result.message}
            if result.data.get("media"):
                item["media"] = result.data["media"]
            imported.append(_redact_value(item) if isinstance(_redact_value(item), dict) else item)
            continue
        source = str(attachment.get("url") or attachment.get("url_private_download") or attachment.get("file_id") or attachment.get("source") or "")
        if not source:
            imported.append(metadata | {"status": "skipped", "reason": "no-local-path-or-source"})
            continue
        source_redacted = redact_secrets(source) or ""
        media_id = runtime.store.create_media_artifact(
            runtime.session_id,
            kind,
            source_redacted,
            "",
            mime_type,
            str(attachment.get("sha256") or ""),
            size,
            metadata | {"source_kind": "remote-metadata-only", "downloaded": False},
        )
        imported.append(metadata | {"status": "metadata-recorded", "media_id": media_id, "source": source_redacted})
    return imported


def _attachment_import_blocked(imported: list[dict[str, Any]]) -> bool:
    return any(item.get("status") == "skipped" and item.get("reason") == "attachment-too-large" for item in imported)


def _int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _kind_from_mime(mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("audio/"):
        return "audio"
    if mime_type.startswith("video/"):
        return "video"
    return "file"


def normalize_bridge_text(text: str, config: BridgeConfig, *, bot_user_id: str | None = None, is_private: bool = False) -> tuple[str, str]:
    original = text.strip()
    if not original:
        return "", "empty-message"
    mentioned = False
    stripped = original
    if bot_user_id:
        pattern = re.compile(rf"<@!?{re.escape(str(bot_user_id))}>[:,]?\s*")
        match = pattern.search(original)
        if match:
            mentioned = True
            after = original[match.end() :].strip()
            before = original[: match.start()].strip()
            # Discord users often type "hey @Phobos /status" or put the mention
            # at the end of a sentence. Treat the bot's own mention as the
            # trigger wherever Discord places it, preferring the text after the
            # mention when present and falling back to the text before it.
            stripped = after or before
    prefixed = False
    if config.command_prefix:
        if stripped.startswith(config.command_prefix):
            stripped = stripped[len(config.command_prefix) :].strip()
            prefixed = True
        elif original.startswith(config.command_prefix):
            stripped = original[len(config.command_prefix) :].strip()
            prefixed = True
    if config.mention_required and not mentioned and not is_private:
        return "", "mention-required"
    if config.command_prefix and not prefixed and not mentioned and not is_private:
        return "", "prefix-required"
    return stripped.strip(), "mentioned" if mentioned else "prefixed" if prefixed else "accepted"


def chunk_text(text: str, limit: int = 1800) -> list[str]:
    if not text:
        return [""]
    limit = max(200, int(limit))
    text = _neutralize_mass_mentions(text)
    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        cut = remaining.rfind("\n", 0, limit)
        if cut < max(80, limit // 4):
            cut = remaining.rfind(" ", 0, limit)
        if cut < max(80, limit // 4):
            cut = limit
        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    return chunks


def bridge_doctor(platforms: list[str] | tuple[str, ...] | None = None, *, timeout: float = 15.0) -> dict[str, Any]:
    """Check live bridge token/auth readiness without joining streams or sending messages.

    This intentionally performs only no-message auth/readiness calls. It never
    returns token values or websocket URLs. A platform with missing env vars is
    reported as ``missing`` rather than raising, so it is safe for CI/smoke use.
    """
    requested = [str(item).lower() for item in (platforms or ("discord", "slack", "telegram"))]
    if "all" in requested:
        requested = ["discord", "slack", "telegram"]
    checks: list[dict[str, Any]] = []
    for platform in requested:
        if platform == "discord":
            checks.append(_bridge_doctor_discord(timeout))
        elif platform == "slack":
            checks.append(_bridge_doctor_slack(timeout))
        elif platform == "telegram":
            checks.append(_bridge_doctor_telegram(timeout))
        else:
            checks.append({"platform": platform, "status": "unsupported", "ok": False})
    ok = all(item.get("ok") for item in checks) if checks else False
    return {"status": "ok" if ok else "attention", "ok": ok, "message_sending": False, "checks": checks}


def _bridge_doctor_discord(timeout: float) -> dict[str, Any]:
    env_name = str(BRIDGE_DEFAULTS["discord"].get("token_env") or "PHOBOS_DISCORD_TOKEN")
    token = os.environ.get(env_name, "")
    base = {"platform": "discord", "env": env_name, "message_sending": False}
    if not token:
        return base | {"status": "missing", "ok": False, "reason": "token env var is not set"}
    try:
        me = _http_json("GET", "https://discord.com/api/v10/users/@me", headers={"Authorization": f"Bot {token}"}, timeout=timeout)
        gateway = _http_json("GET", "https://discord.com/api/v10/gateway/bot", headers={"Authorization": f"Bot {token}"}, timeout=timeout)
        return base | {
            "status": "ok",
            "ok": True,
            "bot_user_id": str(me.get("id", "")),
            "username_present": bool(me.get("username")),
            "gateway_url_present": bool(gateway.get("url")),
            "session_start_limit_present": bool(gateway.get("session_start_limit")),
        }
    except Exception as exc:  # pragma: no cover - live network/API boundary
        return base | {"status": "error", "ok": False, "error": redact_secrets(str(exc))}


def _bridge_doctor_slack(timeout: float) -> dict[str, Any]:
    bot_env = str(BRIDGE_DEFAULTS["slack"].get("bot_token_env") or "PHOBOS_SLACK_BOT_TOKEN")
    app_env = str(BRIDGE_DEFAULTS["slack"].get("app_token_env") or "PHOBOS_SLACK_APP_TOKEN")
    bot_token = os.environ.get(bot_env, "")
    app_token = os.environ.get(app_env, "")
    base = {"platform": "slack", "bot_token_env": bot_env, "app_token_env": app_env, "message_sending": False}
    if not bot_token or not app_token:
        missing = [name for name, value in ((bot_env, bot_token), (app_env, app_token)) if not value]
        return base | {"status": "missing", "ok": False, "missing_env": missing}
    try:
        auth = _http_json("GET", "https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {bot_token}"}, timeout=timeout)
        opened = _http_json("POST", "https://slack.com/api/apps.connections.open", payload={}, headers={"Authorization": f"Bearer {app_token}"}, timeout=timeout)
        ok = bool(auth.get("ok")) and bool(opened.get("ok"))
        return base | {
            "status": "ok" if ok else "error",
            "ok": ok,
            "team_id": str(auth.get("team_id", "")),
            "user_id": str(auth.get("user_id", "")),
            "socket_mode_url_present": bool(opened.get("url")),
            "auth_error": "" if auth.get("ok") else str(auth.get("error", "")),
            "socket_error": "" if opened.get("ok") else str(opened.get("error", "")),
        }
    except Exception as exc:  # pragma: no cover - live network/API boundary
        return base | {"status": "error", "ok": False, "error": redact_secrets(str(exc))}


def _bridge_doctor_telegram(timeout: float) -> dict[str, Any]:
    env_name = str(BRIDGE_DEFAULTS["telegram"].get("token_env") or "PHOBOS_TELEGRAM_TOKEN")
    token = os.environ.get(env_name, "")
    base = {"platform": "telegram", "env": env_name, "message_sending": False}
    if not token:
        return base | {"status": "missing", "ok": False, "reason": "token env var is not set"}
    try:
        me = _http_json("GET", f"https://api.telegram.org/bot{token}/getMe", timeout=timeout)
        result = me.get("result") or {}
        ok = bool(me.get("ok"))
        return base | {"status": "ok" if ok else "error", "ok": ok, "bot_user_id": str(result.get("id", "")), "username_present": bool(result.get("username")), "api_error": "" if ok else str(me.get("description", ""))}
    except Exception as exc:  # pragma: no cover - live network/API boundary
        return base | {"status": "error", "ok": False, "error": redact_secrets(str(exc))}


def run_bridge(platform: str, runtime: "OffSecAgentRuntime", config: BridgeConfig) -> None:
    platform = platform.lower()
    if platform == "discord":
        DiscordGatewayBridge(runtime, config).run_forever()
        return
    if platform == "telegram":
        TelegramPollingBridge(runtime, config).run_forever()
        return
    if platform == "slack":
        SlackSocketModeBridge(runtime, config).run_forever()
        return
    raise ValueError(f"Unsupported bridge platform: {platform}")


class DiscordGatewayBridge:
    api_base = "https://discord.com/api/v10"

    def __init__(self, runtime: "OffSecAgentRuntime", config: BridgeConfig):
        self.runtime = runtime
        self.config = config
        self.token = _require_env(config.token_env or "PHOBOS_DISCORD_TOKEN")
        self.bot_user_id = ""
        self.sequence: int | None = None

    def run_forever(self) -> None:  # pragma: no cover - requires live Discord token/network
        backoff = 1.0
        while True:
            try:
                self._run_once()
                backoff = 1.0
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.runtime.store.audit(self.runtime.session_id, "bridge_error", {"platform": "discord", "error": str(exc)})
                time.sleep(backoff)
                backoff = min(60.0, backoff * 2)

    def _run_once(self) -> None:
        gateway = _http_json("GET", f"{self.api_base}/gateway/bot", headers={"Authorization": f"Bot {self.token}"})
        url = str(gateway.get("url") or "wss://gateway.discord.gg") + "/?v=10&encoding=json"
        ws = SimpleWebSocket.connect(url)
        heartbeat_interval = 30.0
        next_heartbeat = time.monotonic() + heartbeat_interval
        while True:
            now = time.monotonic()
            if now >= next_heartbeat:
                ws.send_json({"op": 1, "d": self.sequence})
                next_heartbeat = now + heartbeat_interval
            payload = ws.recv_json(timeout=1.0)
            if payload is None:
                continue
            op = payload.get("op")
            if "s" in payload and payload.get("s") is not None:
                self.sequence = int(payload["s"])
            if op == 10:
                heartbeat_interval = float(payload.get("d", {}).get("heartbeat_interval", 30000)) / 1000.0
                identify = {
                    "op": 2,
                    "d": {
                        "token": self.token,
                        "intents": int(self.config.extra.get("intents", 1 | 512 | 4096 | 32768)),
                        "properties": {"os": "linux", "browser": "phobos-agent", "device": "phobos-agent"},
                    },
                }
                ws.send_json(identify)
                next_heartbeat = time.monotonic() + heartbeat_interval
                continue
            if op == 7:
                raise RuntimeError("Discord requested reconnect")
            if op == 9:
                raise RuntimeError("Discord invalid session")
            if op != 0:
                continue
            event_type = payload.get("t")
            data = payload.get("d") or {}
            if event_type == "READY":
                self.bot_user_id = str(data.get("user", {}).get("id", ""))
                self.runtime.store.audit(self.runtime.session_id, "bridge_ready", {"platform": "discord", "bot_user_id": self.bot_user_id})
                continue
            if event_type == "MESSAGE_CREATE":
                self._handle_message_create(data)

    def _handle_message_create(self, data: dict[str, Any]) -> None:
        author = data.get("author") or {}
        message = BridgeMessage(
            platform="discord",
            text=str(data.get("content", "")),
            channel_id=str(data.get("channel_id", "")),
            user_id=str(author.get("id", "")),
            message_id=str(data.get("id", "")),
            user_name=str(author.get("username", "")),
            is_bot=bool(author.get("bot", False)),
            is_private=not bool(data.get("guild_id")),
            attachments=_discord_attachments(data),
            raw={"guild_id": data.get("guild_id")},
        )
        result = handle_bridge_message(self.runtime, message, self.config, bot_user_id=self.bot_user_id)
        if result.status == "handled":
            for chunk in result.chunks:
                self.send_message(message.channel_id, chunk, reply_to=message.message_id)

    def send_message(self, channel_id: str, content: str, *, reply_to: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {"content": content[:2000], "allowed_mentions": {"parse": []}}
        if reply_to:
            payload["message_reference"] = {"message_id": reply_to, "fail_if_not_exists": False}
        return _http_json("POST", f"{self.api_base}/channels/{channel_id}/messages", payload=payload, headers={"Authorization": f"Bot {self.token}"})


class SlackSocketModeBridge:
    api_base = "https://slack.com/api"

    def __init__(self, runtime: "OffSecAgentRuntime", config: BridgeConfig):
        self.runtime = runtime
        self.config = config
        self.bot_token = _require_env(config.bot_token_env or "PHOBOS_SLACK_BOT_TOKEN")
        self.app_token = _require_env(config.app_token_env or "PHOBOS_SLACK_APP_TOKEN")
        self.bot_user_id = ""

    def run_forever(self) -> None:  # pragma: no cover - requires live Slack token/network
        backoff = 1.0
        while True:
            try:
                self._run_once()
                backoff = 1.0
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.runtime.store.audit(self.runtime.session_id, "bridge_error", {"platform": "slack", "error": str(exc)})
                time.sleep(backoff)
                backoff = min(60.0, backoff * 2)

    def _run_once(self) -> None:
        auth = _http_json("GET", f"{self.api_base}/auth.test", headers={"Authorization": f"Bearer {self.bot_token}"})
        self.bot_user_id = str(auth.get("user_id", ""))
        opened = _http_json("POST", f"{self.api_base}/apps.connections.open", payload={}, headers={"Authorization": f"Bearer {self.app_token}"})
        if not opened.get("ok"):
            raise RuntimeError(f"Slack Socket Mode open failed: {opened}")
        ws = SimpleWebSocket.connect(str(opened["url"]))
        self.runtime.store.audit(self.runtime.session_id, "bridge_ready", {"platform": "slack", "bot_user_id": self.bot_user_id})
        while True:
            payload = ws.recv_json(timeout=30.0)
            if payload is None:
                continue
            envelope_id = payload.get("envelope_id")
            if envelope_id:
                ws.send_json({"envelope_id": envelope_id})
            if payload.get("type") != "events_api":
                continue
            event = ((payload.get("payload") or {}).get("event") or {})
            if event.get("type") != "message" or event.get("subtype"):
                continue
            self._handle_event(event)

    def _handle_event(self, event: dict[str, Any]) -> None:
        user_id = str(event.get("user") or event.get("bot_id") or "")
        message = BridgeMessage(
            platform="slack",
            text=str(event.get("text", "")),
            channel_id=str(event.get("channel", "")),
            user_id=user_id,
            message_id=str(event.get("ts", "")),
            is_bot=bool(event.get("bot_id")) or user_id == self.bot_user_id,
            is_private=str(event.get("channel_type", "")) == "im" or str(event.get("channel", "")).startswith("D"),
            attachments=_slack_attachments(event),
            raw={"thread_ts": event.get("thread_ts")},
        )
        result = handle_bridge_message(self.runtime, message, self.config, bot_user_id=self.bot_user_id)
        if result.status == "handled":
            thread_ts = str(event.get("thread_ts") or event.get("ts") or "")
            for chunk in result.chunks:
                self.send_message(message.channel_id, chunk, thread_ts=thread_ts)

    def send_message(self, channel_id: str, text: str, *, thread_ts: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": channel_id, "text": text, "mrkdwn": True}
        if thread_ts:
            payload["thread_ts"] = thread_ts
        return _http_json("POST", f"{self.api_base}/chat.postMessage", payload=payload, headers={"Authorization": f"Bearer {self.bot_token}"})


class TelegramPollingBridge:
    def __init__(self, runtime: "OffSecAgentRuntime", config: BridgeConfig):
        self.runtime = runtime
        self.config = config
        self.token = _require_env(config.token_env or "PHOBOS_TELEGRAM_TOKEN")
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.bot_user_id = ""

    def run_forever(self) -> None:  # pragma: no cover - requires live Telegram token/network
        me = _http_json("GET", f"{self.api_base}/getMe")
        if me.get("ok"):
            self.bot_user_id = str((me.get("result") or {}).get("id", ""))
        self.runtime.store.audit(self.runtime.session_id, "bridge_ready", {"platform": "telegram", "bot_user_id": self.bot_user_id})
        offset = 0
        while True:
            params = urlencode({"timeout": 30, "offset": offset, "allowed_updates": json.dumps(["message"])} )
            try:
                updates = _http_json("GET", f"{self.api_base}/getUpdates?{params}")
            except Exception as exc:
                self.runtime.store.audit(self.runtime.session_id, "bridge_error", {"platform": "telegram", "error": str(exc)})
                time.sleep(self.config.poll_interval)
                continue
            for update in updates.get("result", []) if updates.get("ok") else []:
                offset = max(offset, int(update.get("update_id", 0)) + 1)
                message = update.get("message") or {}
                if message:
                    self._handle_update_message(message)

    def _handle_update_message(self, data: dict[str, Any]) -> None:
        chat = data.get("chat") or {}
        user = data.get("from") or {}
        text = str(data.get("text") or data.get("caption") or "")
        message = BridgeMessage(
            platform="telegram",
            text=text,
            channel_id=str(chat.get("id", "")),
            user_id=str(user.get("id", "")),
            message_id=str(data.get("message_id", "")),
            user_name=str(user.get("username", "")),
            is_bot=bool(user.get("is_bot", False)),
            is_private=str(chat.get("type", "")) == "private",
            attachments=_telegram_attachments(data),
            raw={"chat_type": chat.get("type")},
        )
        result = handle_bridge_message(self.runtime, message, self.config, bot_user_id=self.bot_user_id)
        if result.status == "handled":
            for chunk in result.chunks:
                self.send_message(message.channel_id, chunk, reply_to=message.message_id)

    def send_message(self, chat_id: str, text: str, *, reply_to: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if reply_to:
            payload["reply_to_message_id"] = reply_to
        return _http_json("POST", f"{self.api_base}/sendMessage", payload=payload)


class SimpleWebSocket:
    """Tiny stdlib WebSocket client for Discord Gateway and Slack Socket Mode.

    It implements client-side masking, text JSON frames, ping/pong, and close
    handling. Compression extensions are intentionally not requested.
    """

    def __init__(self, sock: ssl.SSLSocket | socket.socket):
        self.sock = sock

    @classmethod
    def connect(cls, url: str, headers: dict[str, str] | None = None, timeout: float = 20.0) -> "SimpleWebSocket":
        parsed = urlparse(url)
        if parsed.scheme not in {"ws", "wss"}:
            raise ValueError(f"Unsupported WebSocket URL scheme: {parsed.scheme}")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        raw = socket.create_connection((host, port), timeout=timeout)
        sock: ssl.SSLSocket | socket.socket
        if parsed.scheme == "wss":
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request_headers = {
            "Host": host if parsed.port is None else f"{host}:{port}",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            "User-Agent": "phobos-agent/0.1",
        }
        request_headers.update(headers or {})
        request = "GET {path} HTTP/1.1\r\n{headers}\r\n\r\n".format(
            path=path,
            headers="\r\n".join(f"{name}: {value}" for name, value in request_headers.items()),
        )
        sock.sendall(request.encode("ascii"))
        response = _read_until(sock, b"\r\n\r\n", timeout=timeout)
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"WebSocket handshake failed: {response[:200]!r}")
        expected_accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        if expected_accept.encode("ascii") not in response:
            raise RuntimeError("WebSocket handshake did not include the expected accept key")
        return cls(sock)

    def send_json(self, payload: dict[str, Any]) -> None:
        self._send_frame(0x1, json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def recv_json(self, timeout: float | None = None) -> dict[str, Any] | None:
        previous_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            fragments: list[bytes] = []
            while True:
                fin, opcode, payload = self._recv_frame()
                if opcode == 0x8:
                    raise ConnectionError("WebSocket closed")
                if opcode == 0x9:
                    self._send_frame(0xA, payload)
                    continue
                if opcode == 0xA:
                    continue
                if opcode in {0x1, 0x0}:
                    fragments.append(payload)
                    if fin:
                        text = b"".join(fragments).decode("utf-8")
                        return json.loads(text)
        except socket.timeout:
            return None
        finally:
            self.sock.settimeout(previous_timeout)

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        finally:
            self.sock.close()

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        first = 0x80 | (opcode & 0x0F)
        mask_key = random.randbytes(4) if hasattr(random, "randbytes") else os.urandom(4)
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", first, 0x80 | length)
        elif length < (1 << 16):
            header = struct.pack("!BBH", first, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, length)
        masked = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + mask_key + masked)

    def _recv_frame(self) -> tuple[bool, int, bytes]:
        header = _read_exact(self.sock, 2)
        first, second = header[0], header[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _read_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _read_exact(self.sock, 8))[0]
        mask = _read_exact(self.sock, 4) if masked else b""
        payload = _read_exact(self.sock, length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload


def _discord_attachments(data: dict[str, Any]) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for item in data.get("attachments", []) or []:
        if not isinstance(item, dict):
            continue
        attachments.append({
            "platform": "discord",
            "id": str(item.get("id", "")),
            "name": str(item.get("filename") or item.get("name") or "attachment"),
            "url": str(item.get("url") or item.get("proxy_url") or ""),
            "mime_type": str(item.get("content_type") or "application/octet-stream"),
            "size": _int_value(item.get("size"), 0),
            "kind": _kind_from_mime(str(item.get("content_type") or "")),
        })
    return attachments


def _slack_attachments(event: dict[str, Any]) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for item in event.get("files", []) or []:
        if not isinstance(item, dict):
            continue
        mime_type = str(item.get("mimetype") or item.get("filetype") or "application/octet-stream")
        attachments.append({
            "platform": "slack",
            "id": str(item.get("id", "")),
            "name": str(item.get("name") or item.get("title") or "attachment"),
            "url_private_download": str(item.get("url_private_download") or item.get("url_private") or ""),
            "mime_type": mime_type,
            "size": _int_value(item.get("size"), 0),
            "kind": _kind_from_mime(mime_type),
        })
    return attachments


def _telegram_attachments(data: dict[str, Any]) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for key in ("voice", "audio", "video", "document", "animation"):
        item = data.get(key)
        if isinstance(item, dict):
            mime_type = str(item.get("mime_type") or ("audio/ogg" if key == "voice" else "application/octet-stream"))
            attachments.append({
                "platform": "telegram",
                "id": str(item.get("file_id", "")),
                "file_id": str(item.get("file_id", "")),
                "name": str(item.get("file_name") or key),
                "mime_type": mime_type,
                "size": _int_value(item.get("file_size"), 0),
                "kind": "audio" if key in {"voice", "audio"} else _kind_from_mime(mime_type),
            })
    photos = data.get("photo") or []
    if isinstance(photos, list) and photos:
        item = max((photo for photo in photos if isinstance(photo, dict)), key=lambda photo: _int_value(photo.get("file_size"), 0), default={})
        if item:
            attachments.append({
                "platform": "telegram",
                "id": str(item.get("file_id", "")),
                "file_id": str(item.get("file_id", "")),
                "name": "photo",
                "mime_type": "image/jpeg",
                "size": _int_value(item.get("file_size"), 0),
                "kind": "image",
            })
    return attachments


def _allow_message(message: BridgeMessage, config: BridgeConfig) -> tuple[bool, str]:
    if config.ignore_bots and message.is_bot:
        return False, "bot-message"
    allowed_channels = set(config.allowed_channel_ids)
    allowed_users = set(config.allowed_user_ids)
    if config.allow_all:
        return True, "allow-all"
    if message.is_private:
        if allowed_users and message.user_id not in allowed_users:
            return False, "user-not-allowed"
        return True, "private-message"
    if not allowed_channels:
        if allowed_users:
            return False, "channel-allowlist-required"
        return False, "allowlist-required"
    if message.channel_id not in allowed_channels:
        return False, "channel-not-allowed"
    if allowed_users and message.user_id not in allowed_users:
        return False, "user-not-allowed"
    return True, "allowlisted"


def _is_approval_action(text: str) -> bool:
    return bool(re.match(r"^/(approve|deny)(?:\s|$)", text.strip(), flags=re.IGNORECASE))


def _neutralize_mass_mentions(text: str) -> str:
    replacements = {
        "@everyone": "@\u200beveryone",
        "@here": "@\u200bhere",
        "@channel": "@\u200bchannel",
        "@all": "@\u200ball",
        "<!here>": "<!\u200bhere>",
        "<!channel>": "<!\u200bchannel>",
        "<!everyone>": "<!\u200beveryone>",
    }
    for needle, replacement in replacements.items():
        text = text.replace(needle, replacement)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, str):
        return redact_secrets(value)
    return value


def _tuple_of_strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    return tuple(str(item) for item in value if str(item))


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _http_json(method: str, url: str, *, payload: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: float = 30.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Accept": "application/json", "User-Agent": "phobos-agent/0.1"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request_headers.update(headers or {})
    req = Request(url, data=body, headers=request_headers, method=method)
    with urlopen(req, timeout=timeout) as response:  # noqa: S310 - operator-supplied bridge endpoints are fixed platform APIs
        text = response.read().decode("utf-8", errors="replace")
    return json.loads(text) if text else {}


def _read_until(sock: ssl.SSLSocket | socket.socket, marker: bytes, *, timeout: float) -> bytes:
    previous = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        data = b""
        while marker not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed during read")
            data += chunk
        return data
    finally:
        sock.settimeout(previous)


def _read_exact(sock: ssl.SSLSocket | socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("socket closed during frame read")
        data += chunk
    return data
