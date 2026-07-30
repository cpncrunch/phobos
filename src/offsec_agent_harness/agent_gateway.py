from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from pathlib import Path
import html
import json
import os
import threading
from urllib.parse import parse_qs, urlparse

from .agent_runtime import OffSecAgentRuntime
from .agent_bridges import BridgeConfig
from .agent_config import AgentAppConfig


DEFAULT_MAX_JSON_BODY_BYTES = 1_048_576


class GatewayRequestError(ValueError):
    """Clean HTTP error raised for malformed gateway request payloads."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class AgentGateway:
    """Local/remote HTTP gateway for the standalone Phobos Agent.

    The gateway remains safe-by-default: it binds to 127.0.0.1 unless the CLI
    asks otherwise, and a non-local bind requires a bearer token environment
    variable unless the operator explicitly opts into unsafe no-auth mode. This
    lets a browser UI connect to a VPS-hosted agent without turning Phobos into
    an unauthenticated remote shell.
    """

    def __init__(
        self,
        runtime: OffSecAgentRuntime,
        host: str = "127.0.0.1",
        port: int = 8765,
        *,
        token_env: str | None = None,
        allow_origins: tuple[str, ...] = (),
        unsafe_no_auth: bool = False,
        max_body_bytes: int = DEFAULT_MAX_JSON_BODY_BYTES,
    ):
        if isinstance(max_body_bytes, bool):
            raise ValueError("max_body_bytes must be an integer")
        try:
            max_body_bytes_int = int(max_body_bytes)
        except (TypeError, ValueError):
            raise ValueError("max_body_bytes must be an integer") from None
        if max_body_bytes_int <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.runtime = runtime
        self.host = host
        self.port = port
        self.max_body_bytes = max_body_bytes_int
        self.token_env = str(token_env or "").strip()
        self.auth_token = os.environ.get(self.token_env, "") if self.token_env else ""
        if self.token_env and not self.auth_token:
            raise ValueError(f"Gateway token env var is not set: {self.token_env}")
        if not _is_local_bind(host) and not self.auth_token and not unsafe_no_auth:
            raise ValueError("Refusing non-local gateway bind without --token-env; pass --unsafe-no-auth only for isolated test networks.")
        handler = self._handler_class()
        self.server = ThreadingHTTPServer((host, port), handler)
        self.server.runtime = runtime  # type: ignore[attr-defined]
        self.server.runtime_lock = threading.RLock()  # type: ignore[attr-defined]
        self.server.auth_token = self.auth_token  # type: ignore[attr-defined]
        self.server.token_env = self.token_env  # type: ignore[attr-defined]
        self.server.allow_origins = tuple(origin.strip() for origin in allow_origins if origin.strip())  # type: ignore[attr-defined]
        self.server.unsafe_no_auth = unsafe_no_auth  # type: ignore[attr-defined]
        self.server.max_body_bytes = self.max_body_bytes  # type: ignore[attr-defined]
        self.server.bind_host = host  # type: ignore[attr-defined]

    @property
    def server_address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    @property
    def auth_required(self) -> bool:
        return bool(self.auth_token)

    def serve_forever(self) -> None:  # pragma: no cover - CLI convenience
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            server_version = "PhobosAgentGateway/0.2"

            def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib hook name
                _write_empty(self, status=204)

            def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
                runtime: OffSecAgentRuntime = self.server.runtime  # type: ignore[attr-defined]
                lock = self.server.runtime_lock  # type: ignore[attr-defined]
                parsed = urlparse(self.path)
                path = parsed.path
                if path in {"/ui-client", "/remote-ui"}:
                    _write_html(self, remote_client_html())
                    return
                if path == "/health":
                    local_bind = _is_local_bind(str(getattr(self.server, "bind_host", "")))
                    _write_json(self, {"ok": True, "session_id": runtime.session_id, "engagement": runtime.roe.name, "auth_required": _auth_required(self), "remote_safe": bool(getattr(self.server, "auth_token", "")) or local_bind, "max_body_bytes": getattr(self.server, "max_body_bytes", DEFAULT_MAX_JSON_BODY_BYTES)})
                    return
                if not _authorized(self):
                    _audit_gateway_auth(runtime, lock, self, path)
                    _write_json(self, {"error": "unauthorized", "auth": "Send Authorization: Bearer <token> or X-Phobos-Token."}, status=401)
                    return
                with lock:
                    if path in {"/", "/ui"}:
                        _write_html(self, _dashboard_html(runtime))
                        return
                    if path == "/routes":
                        _write_json(self, {"paths": _gateway_paths(), "auth_required": _auth_required(self)})
                        return
                    if path == "/tools":
                        _write_json(self, {"tools": [spec.to_dict() for spec in runtime.registry.specs()]})
                        return
                    if path == "/schemas":
                        query = parse_qs(parsed.query)
                        name = (query.get("name") or [""])[0]
                        _write_json(self, runtime.registry.run("tool_schemas", {"name": name}).to_dict())
                        return
                    if path == "/status":
                        _write_json(self, runtime.registry.run("runtime_status", {}).to_dict())
                        return
                    if path == "/preflight":
                        _write_json(self, runtime.registry.run("safety_preflight", {}).to_dict())
                        return
                    if path in {"/guardrail-test", "/guardrail-selftest", "/guardrails-test", "/safety-selftest"}:
                        query = parse_qs(parsed.query)
                        args: dict[str, Any] = {}
                        target = (query.get("target") or query.get("host") or query.get("url") or [""])[0]
                        if target:
                            args["target"] = target
                        if (query.get("out") or [""])[0]:
                            args["out"] = (query.get("out") or [""])[0]
                        _write_json(self, runtime.registry.run("guardrail_selftest", args).to_dict())
                        return
                    if path in {"/scope", "/scope-check", "/roe-check"}:
                        query = parse_qs(parsed.query)
                        args: dict[str, Any] = {}
                        target = (query.get("target") or query.get("host") or query.get("url") or [""])[0]
                        if target:
                            args["target"] = target
                        _write_json(self, runtime.registry.run("scope_check", args).to_dict())
                        return
                    if path == "/sessions":
                        _write_json(self, {"session_id": runtime.session_id, "sessions": runtime.store.list_sessions(limit=50), "recent": runtime.store.recent_messages(runtime.session_id, limit=12)})
                        return
                    if path == "/context":
                        _write_json(self, runtime.registry.run("context_snapshot", {}).to_dict())
                        return
                    if path == "/memories":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 50)
                        if limit is None:
                            return
                        args: dict[str, Any] = {"limit": limit}
                        if (query.get("query") or [""])[0]:
                            args["query"] = (query.get("query") or [""])[0]
                        _write_json(self, runtime.registry.run("list_memories", args).to_dict())
                        return
                    if path in {"/memory", "/memory-detail"}:
                        query = parse_qs(parsed.query)
                        memory_id = (query.get("id") or query.get("memory_id") or [""])[0]
                        key = (query.get("key") or [""])[0]
                        if not memory_id and not key:
                            _write_json(self, {"error": "id or key is required"}, status=400)
                            return
                        if memory_id:
                            parsed_id = _query_required_int(self, query, "id", "memory_id", label="id")
                            if parsed_id is None:
                                return
                            args = {"id": parsed_id}
                        else:
                            args = {"key": key}
                        _write_json(self, runtime.registry.run("get_memory", args).to_dict())
                        return
                    if path == "/approvals":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 100)
                        if limit is None:
                            return
                        args: dict[str, Any] = {
                            "status": (query.get("status") or ["pending"])[0],
                            "limit": limit,
                        }
                        _write_json(self, runtime.registry.run("list_approvals", args).to_dict())
                        return
                    if path in {"/approval", "/approval-detail"}:
                        query = parse_qs(parsed.query)
                        approval_id = _query_required_int(self, query, "id", "approval_id", label="id")
                        if approval_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_approval", {"id": approval_id}).to_dict())
                        return
                    if path == "/audit":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 50)
                        if limit is None:
                            return
                        _write_json(self, runtime.registry.run("audit_log", {"limit": limit}).to_dict())
                        return
                    if path in {"/audit-detail", "/audit-event"}:
                        query = parse_qs(parsed.query)
                        audit_id = _query_required_int(self, query, "id", "audit_id", label="id")
                        if audit_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_audit", {"id": audit_id}).to_dict())
                        return
                    if path == "/timeline":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 100)
                        if limit is None:
                            return
                        args: dict[str, Any] = {"limit": limit}
                        if (query.get("category") or [""])[0]:
                            args["category"] = (query.get("category") or [""])[0]
                        if (query.get("include_audit") or [""])[0]:
                            include_audit = _query_bool(self, query, "include_audit")
                            if include_audit is None:
                                return
                            args["include_audit"] = include_audit
                        _write_json(self, runtime.registry.run("evidence_timeline", args).to_dict())
                        return
                    if path in {"/manifest", "/evidence-manifest"}:
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 1000)
                        if limit is None:
                            return
                        args = {"limit": limit}
                        if (query.get("max_bytes") or [""])[0]:
                            max_bytes = _query_int(self, query, "max_bytes", 50000000)
                            if max_bytes is None:
                                return
                            args["max_bytes"] = max_bytes
                        if (query.get("include_agent") or [""])[0]:
                            include_agent = _query_bool(self, query, "include_agent")
                            if include_agent is None:
                                return
                            args["include_agent"] = include_agent
                        _write_json(self, runtime.registry.run("evidence_manifest", args).to_dict())
                        return
                    if path in {"/manifest-verify", "/evidence-manifest-verify"}:
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 1000)
                        if limit is None:
                            return
                        args = {
                            "path": (query.get("path") or query.get("manifest") or [""])[0],
                            "limit": limit,
                        }
                        if (query.get("out") or [""])[0]:
                            args["out"] = (query.get("out") or [""])[0]
                        if (query.get("max_bytes") or [""])[0]:
                            max_bytes = _query_int(self, query, "max_bytes", 50000000)
                            if max_bytes is None:
                                return
                            args["max_bytes"] = max_bytes
                        if (query.get("detect_new") or [""])[0]:
                            detect_new = _query_bool(self, query, "detect_new")
                            if detect_new is None:
                                return
                            args["detect_new"] = detect_new
                        _write_json(self, runtime.registry.run("evidence_manifest_verify", args).to_dict())
                        return
                    if path in {"/secret-scan", "/evidence-secret-scan"}:
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 200)
                        if limit is None:
                            return
                        args = {"limit": limit}
                        if (query.get("out") or [""])[0]:
                            args["out"] = (query.get("out") or [""])[0]
                        if (query.get("max_bytes") or [""])[0]:
                            max_bytes = _query_int(self, query, "max_bytes", 2000000)
                            if max_bytes is None:
                                return
                            args["max_bytes"] = max_bytes
                        if (query.get("include_agent") or [""])[0]:
                            include_agent = _query_bool(self, query, "include_agent")
                            if include_agent is None:
                                return
                            args["include_agent"] = include_agent
                        _write_json(self, runtime.registry.run("evidence_secret_scan", args).to_dict())
                        return
                    if path in {"/closeout", "/closeout-review"}:
                        query = parse_qs(parsed.query)
                        args = {"out": (query.get("out") or [""])[0]} if (query.get("out") or [""])[0] else {}
                        _write_json(self, runtime.registry.run("closeout_review", args).to_dict())
                        return
                    if path in {"/ref", "/detail", "/resolve-ref", "/local-ref"}:
                        query = parse_qs(parsed.query)
                        args: dict[str, Any] = {}
                        ref_value = (query.get("ref") or query.get("local_ref") or query.get("query") or [""])[0]
                        if ref_value:
                            args["ref"] = ref_value
                        if (query.get("kind") or [""])[0]:
                            args["kind"] = (query.get("kind") or [""])[0]
                        if (query.get("id") or [""])[0]:
                            ref_id = _query_required_int(self, query, "id", label="id")
                            if ref_id is None:
                                return
                            args["id"] = ref_id
                        if (query.get("path") or [""])[0]:
                            args["path"] = (query.get("path") or [""])[0]
                        if (query.get("max_bytes") or [""])[0]:
                            max_bytes = _query_int(self, query, "max_bytes", 50000000)
                            if max_bytes is None:
                                return
                            args["max_bytes"] = max_bytes
                        if not args:
                            _write_json(self, {"error": "ref or kind+id/path is required"}, status=400)
                            return
                        _write_json(self, runtime.registry.run("resolve_local_ref", args).to_dict())
                        return
                    if path == "/tasks":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 100)
                        if limit is None:
                            return
                        args = {
                            "status": (query.get("status") or ["all"])[0],
                            "limit": limit,
                        }
                        _write_json(self, runtime.registry.run("list_tasks", args).to_dict())
                        return
                    if path in {"/task", "/task-detail"}:
                        query = parse_qs(parsed.query)
                        task_id = _query_required_int(self, query, "id", "task_id", label="id")
                        if task_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_task", {"id": task_id}).to_dict())
                        return
                    if path == "/findings":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 50)
                        if limit is None:
                            return
                        _write_json(self, runtime.registry.run("list_findings", {"status": (query.get("status") or ["all"])[0], "limit": limit}).to_dict())
                        return
                    if path in {"/finding", "/finding-detail"}:
                        query = parse_qs(parsed.query)
                        finding_id = _query_required_int(self, query, "id", "finding_id", label="id")
                        if finding_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_finding", {"id": finding_id}).to_dict())
                        return
                    if path in {"/finding-bundle", "/finding-package"}:
                        query = parse_qs(parsed.query)
                        finding_id = _query_required_int(self, query, "id", "finding_id", label="id")
                        if finding_id is None:
                            return
                        args: dict[str, Any] = {"id": finding_id}
                        if (query.get("out") or [""])[0]:
                            args["out"] = (query.get("out") or [""])[0]
                        if (query.get("max_bytes") or [""])[0]:
                            max_bytes = _query_int(self, query, "max_bytes", 2000000)
                            if max_bytes is None:
                                return
                            args["max_bytes"] = max_bytes
                        _write_json(self, runtime.registry.run("finding_bundle", args).to_dict())
                        return
                    if path == "/tool-runs":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 50)
                        if limit is None:
                            return
                        args: dict[str, Any] = {"limit": limit}
                        if (query.get("tool_name") or [""])[0]:
                            args["tool_name"] = (query.get("tool_name") or [""])[0]
                        _write_json(self, runtime.registry.run("list_tool_runs", args).to_dict())
                        return
                    if path in {"/tool-run", "/tool-run-detail"}:
                        query = parse_qs(parsed.query)
                        run_id = _query_required_int(self, query, "id", "run_id", label="id")
                        if run_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_tool_run", {"id": run_id}).to_dict())
                        return
                    if path == "/jobs":
                        _write_json(self, runtime.registry.run("list_jobs", {}).to_dict())
                        return
                    if path in {"/job", "/job-detail"}:
                        query = parse_qs(parsed.query)
                        job_id = _query_required_int(self, query, "id", "job_id", label="id")
                        if job_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_job", {"id": job_id}).to_dict())
                        return
                    if path == "/processes":
                        query = parse_qs(parsed.query)
                        limit = _query_int(self, query, "limit", 20)
                        if limit is None:
                            return
                        args = {"limit": limit}
                        _write_json(self, runtime.registry.run("list_processes", args).to_dict())
                        return
                    if path in {"/process", "/process-detail"}:
                        query = parse_qs(parsed.query)
                        process_id = _query_required_int(self, query, "id", "process_id", label="id")
                        if process_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_process", {"id": process_id}).to_dict())
                        return
                    if path == "/lcm":
                        _write_json(self, runtime.registry.run("context_describe", {}).to_dict())
                        return
                    if path == "/delegations":
                        _write_json(self, runtime.registry.run("list_delegations", {}).to_dict())
                        return
                    if path in {"/delegation", "/delegation-detail"}:
                        query = parse_qs(parsed.query)
                        delegation_id = _query_required_int(self, query, "id", "delegation_id", label="id")
                        if delegation_id is None:
                            return
                        _write_json(self, runtime.registry.run("get_delegation", {"id": delegation_id}).to_dict())
                        return
                    if path == "/media":
                        _write_json(self, runtime.registry.run("media_list", {}).to_dict())
                        return
                    if path in {"/media-detail", "/media-artifact"}:
                        query = parse_qs(parsed.query)
                        media_id = _query_required_int(self, query, "id", "media_id", label="id")
                        if media_id is None:
                            return
                        _write_json(self, runtime.registry.run("media_get", {"id": media_id}).to_dict())
                        return
                    if path == "/auth":
                        _write_json(self, runtime.registry.run("auth_status", {}).to_dict() | {"gateway": _gateway_auth_status(self)})
                        return
                    if path == "/bridges":
                        bridge_configs = {name: BridgeConfig.from_dict(name, data).sanitized() for name, data in (runtime.config.bridges or {}).items()}
                        _write_json(self, {"bridges": bridge_configs})
                        return
                    if path == "/guardrails":
                        _write_json(self, _guardrail_policy(runtime))
                        return
                _write_json(self, {"error": "not found", "paths": _gateway_paths()}, status=404)

            def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
                runtime: OffSecAgentRuntime = self.server.runtime  # type: ignore[attr-defined]
                lock = self.server.runtime_lock  # type: ignore[attr-defined]
                parsed = urlparse(self.path)
                path = parsed.path
                if not _authorized(self):
                    _audit_gateway_auth(runtime, lock, self, path)
                    _write_json(self, {"error": "unauthorized", "auth": "Send Authorization: Bearer <token> or X-Phobos-Token."}, status=401)
                    return
                try:
                    payload = _read_json(self)
                    if not isinstance(payload, dict):
                        _write_json(self, {"error": "JSON body must be an object"}, status=400)
                        return
                    with lock:
                        if path == "/guardrails":
                            result = _apply_guardrail_policy(runtime, payload)
                            _write_json(self, result)
                            return
                        if path == "/message":
                            message = str(payload.get("message", ""))
                            if not message:
                                _write_json(self, {"error": "message is required"}, status=400)
                                return
                            response = runtime.handle_message(message)
                            _write_json(self, {"response": response, "session_id": runtime.session_id})
                            return
                        if path == "/tool":
                            name = str(payload.get("name", "")).strip()
                            tool_args = payload.get("args") or {}
                            if not name:
                                _write_json(self, {"error": "name is required"}, status=400)
                                return
                            if not isinstance(tool_args, dict):
                                _write_json(self, {"error": "args must be an object"}, status=400)
                                return
                            result = runtime.registry.run(name, tool_args)
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                        if path == "/finding":
                            result = runtime.registry.run("create_finding", payload)
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                        if path == "/run-due":
                            _write_json(self, {"jobs_run": runtime.run_due_jobs()})
                            return
                        if path == "/approve":
                            approval_id = _payload_required_int(self, payload, "id", "approval_id", label="id")
                            if approval_id is None:
                                return
                            result = runtime.registry.run("approve", {"id": approval_id, "by": payload.get("by", "gateway")})
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                        if path == "/deny":
                            approval_id = _payload_required_int(self, payload, "id", "approval_id", label="id")
                            if approval_id is None:
                                return
                            result = runtime.registry.run("deny", {"id": approval_id, "by": payload.get("by", "gateway"), "reason": payload.get("reason", "")})
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                    _write_json(self, {"error": "not found", "paths": _gateway_paths()}, status=404)
                except GatewayRequestError as exc:
                    _write_json(self, {"error": str(exc)}, status=exc.status)
                except ValueError as exc:
                    _write_json(self, {"error": str(exc)}, status=400)
                except Exception as exc:  # pragma: no cover - defensive gateway boundary
                    _write_json(self, {"error": str(exc)}, status=500)

            def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib hook name
                runtime: OffSecAgentRuntime = self.server.runtime  # type: ignore[attr-defined]
                lock = self.server.runtime_lock  # type: ignore[attr-defined]
                with lock:
                    runtime.store.audit(runtime.session_id, "gateway_access", {"client": self.address_string(), "message": fmt % args})

        return Handler


def _gateway_paths() -> list[str]:
    return [
        "/",
        "/ui-client",
        "/health",
        "/routes",
        "/status",
        "/preflight",
        "/guardrail-test",
        "/guardrail-selftest",
        "/scope",
        "/scope-check",
        "/roe-check",
        "/tools",
        "/schemas",
        "/sessions",
        "/context",
        "/memories",
        "/memory",
        "/memory-detail",
        "/timeline",
        "/manifest",
        "/evidence-manifest",
        "/manifest-verify",
        "/evidence-manifest-verify",
        "/secret-scan",
        "/evidence-secret-scan",
        "/closeout",
        "/closeout-review",
        "/ref",
        "/detail",
        "/resolve-ref",
        "/local-ref",
        "/lcm",
        "/tasks",
        "/task",
        "/task-detail",
        "/findings",
        "/finding-detail",
        "/finding-bundle",
        "/finding-package",
        "/tool-runs",
        "/tool-run",
        "/tool-run-detail",
        "/jobs",
        "/job",
        "/job-detail",
        "/processes",
        "/process",
        "/process-detail",
        "/approvals",
        "/approval",
        "/approval-detail",
        "/delegations",
        "/delegation",
        "/delegation-detail",
        "/media",
        "/media-detail",
        "/media-artifact",
        "/auth",
        "/bridges",
        "/guardrails",
        "/audit",
        "/message",
        "/tool",
        "/finding",
        "/approve",
        "/deny",
        "/run-due",
    ]


def _query_first(query: dict[str, list[str]], *names: str) -> Any:
    for name in names:
        values = query.get(name) or []
        if values:
            return values[0]
    return ""


def _query_int(handler: BaseHTTPRequestHandler, query: dict[str, list[str]], name: str, default: int) -> int | None:
    raw = (query.get(name) or [default])[0]
    if raw == "":
        raw = default
    try:
        return int(raw)
    except (TypeError, ValueError):
        _write_json(handler, {"error": f"{name} must be an integer"}, status=400)
        return None


def _query_required_int(handler: BaseHTTPRequestHandler, query: dict[str, list[str]], *names: str, label: str = "id") -> int | None:
    raw = _query_first(query, *names)
    if raw == "":
        _write_json(handler, {"error": f"{label} is required"}, status=400)
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        _write_json(handler, {"error": f"{label} must be an integer"}, status=400)
        return None


def _query_bool(handler: BaseHTTPRequestHandler, query: dict[str, list[str]], name: str, default: bool = False) -> bool | None:
    raw = (query.get(name) or [""])[0]
    if raw == "":
        return default
    text = str(raw).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    _write_json(handler, {"error": f"{name} must be a boolean"}, status=400)
    return None


def remote_client_html(default_base_url: str = "") -> str:
    default_base = html.escape(default_base_url, quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Phobos Agent Remote Client</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0d1117; color: #e6edf3; }}
    input, textarea, select {{ width: 100%; box-sizing: border-box; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: .5rem; padding: .55rem; }}
    textarea {{ min-height: 7rem; }} button {{ background: #238636; color: white; border: 0; border-radius: .5rem; padding: .55rem .85rem; margin-top: .4rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }} section {{ border: 1px solid #30363d; border-radius: .75rem; padding: 1rem; background: #111827; }}
    pre {{ white-space: pre-wrap; background: #161b22; border-radius: .5rem; padding: .75rem; max-height: 28rem; overflow: auto; }} code {{ background: #161b22; padding: .1rem .25rem; border-radius: .25rem; }}
  </style>
</head>
<body>
  <h1>Phobos Agent Remote Client</h1>
  <p>Connect this browser to a local or VPS-hosted Phobos Agent gateway. The token stays in this browser tab and is sent as an <code>Authorization: Bearer &lt;token&gt;</code> header; it is not stored by Phobos docs or config.</p>
  <section>
    <label>Agent base URL <input id="base" value="{default_base}" placeholder="https://agent.example.com or http://127.0.0.1:8765"></label><br><br>
    <label>Bearer token <input id="token" type="password" placeholder="paste gateway token from your password manager"></label><br>
    <button onclick="loadAll()">Connect / Refresh</button>
    <button onclick="health()">Health</button>
    <pre id="errors"></pre>
  </section>
  <div class="grid">
    <section><h2>Status</h2><pre id="status"></pre></section>
    <section><h2>Guardrail Self-Test</h2><pre id="guardrailtest"></pre></section>
    <section><h2>Timeline</h2><pre id="timeline"></pre></section>
    <section><h2>Evidence Manifest</h2><pre id="manifest"></pre></section>
    <section><h2>Closeout Review</h2><pre id="closeout"></pre></section>
    <section><h2>Findings</h2><pre id="findings"></pre></section>
    <section><h2>Tool Runs</h2><pre id="toolruns"></pre></section>
    <section><h2>Approvals</h2><pre id="approvals"></pre></section>
    <section><h2>Tasks</h2><pre id="tasks"></pre></section>
    <section><h2>Processes</h2><pre id="processes"></pre></section>
  </div>
  <section>
    <h2>Granular Guardrails</h2>
    <p>Edit engagement ROE and per-tool policy. Engagement fields persist to the ROE JSON. Tool policy persists when the agent was started with a config file; otherwise it applies to this running session only.</p>
    <label>Safety mode
      <select id="guardSafety">
        <option value="non_destructive">non_destructive — allow routine in-scope enumeration</option>
        <option value="standard">standard — approval-gate active/noisy testing</option>
      </select>
    </label>
    <label>Testing window<input id="guardWindow" placeholder="for example: business hours, change window ID, or not specified"></label>
    <label>Scope targets, one per line<textarea id="guardScope"></textarea></label>
    <label>Allowed techniques, one per line<textarea id="guardAllowed"></textarea></label>
    <label>Prohibited techniques, one per line<textarea id="guardProhibited"></textarea></label>
    <label>Stop conditions, one per line<textarea id="guardStops"></textarea></label>
    <label>Notes<textarea id="guardNotes" placeholder="operator notes; do not paste secrets"></textarea></label>
    <label>Tools requiring approval, one per line<textarea id="guardConfirm"></textarea></label>
    <label>Blocked tools, one per line<textarea id="guardBlocked"></textarea></label>
    <button onclick="saveGuardrails()">Save Guardrail Policy</button>
    <pre id="guardrails"></pre>
  </section>
  <section>
    <h2>Send Message</h2>
    <textarea id="message">/status</textarea>
    <button onclick="sendMessage()">Send</button>
    <pre id="messageResult"></pre>
  </section>
  <section>
    <h2>Create Finding</h2>
    <input id="findingTitle" placeholder="Finding title">
    <input id="findingSeverity" value="Medium" placeholder="Severity">
    <textarea id="findingDescription" placeholder="Description"></textarea>
    <button onclick="createFinding()">Create Finding</button>
    <pre id="findingResult"></pre>
  </section>
<script>
function baseUrl() {{ return document.getElementById('base').value.replace(/\/$/, ''); }}
function token() {{ return document.getElementById('token').value; }}
async function api(path, opts={{}}) {{
  const headers = Object.assign({{'Content-Type': 'application/json'}}, opts.headers || {{}});
  if (token()) headers['Authorization'] = 'Bearer ' + token();
  const res = await fetch(baseUrl() + path, Object.assign({{}}, opts, {{headers}}));
  const text = await res.text();
  let data; try {{ data = JSON.parse(text); }} catch(e) {{ data = {{raw: text}}; }}
  if (!res.ok) throw new Error(res.status + ' ' + JSON.stringify(data));
  return data;
}}
function show(id, data) {{ document.getElementById(id).textContent = JSON.stringify(data, null, 2); }}
function err(e) {{ document.getElementById('errors').textContent = String(e); }}
async function health() {{ try {{ show('errors', await api('/health')); }} catch(e) {{ err(e); }} }}
async function loadAll() {{ try {{ document.getElementById('errors').textContent=''; await Promise.all([
  api('/status').then(d=>show('status',d)), api('/guardrail-test').then(d=>show('guardrailtest',d)), api('/guardrails').then(d=>{{ show('guardrails',d); fillGuardrails(d); }}), api('/timeline?limit=25&include_audit=false').then(d=>show('timeline',d)), api('/manifest?limit=50').then(d=>show('manifest',d)), api('/closeout').then(d=>show('closeout',d)), api('/findings').then(d=>show('findings',d)), api('/tool-runs').then(d=>show('toolruns',d)), api('/approvals').then(d=>show('approvals',d)), api('/tasks').then(d=>show('tasks',d)), api('/processes').then(d=>show('processes',d))
]); }} catch(e) {{ err(e); }} }}
function setLines(id, values) {{ document.getElementById(id).value = (values || []).join('\\n'); }}
function getLines(id) {{ return document.getElementById(id).value.split(/\\n|,/).map(x=>x.trim()).filter(Boolean); }}
function getStopLines(id) {{ return document.getElementById(id).value.split(/\\n/).map(x=>x.trim()).filter(Boolean); }}
function fillGuardrails(data) {{
  const e = data.engagement || {{}}; const p = data.runtime_policy || {{}};
  document.getElementById('guardSafety').value = e.safety_mode || 'non_destructive';
  document.getElementById('guardWindow').value = e.testing_window || 'not specified';
  document.getElementById('guardNotes').value = e.notes || '';
  setLines('guardScope', e.in_scope_targets); setLines('guardAllowed', e.allowed_techniques); setLines('guardProhibited', e.prohibited_techniques); setLines('guardStops', e.stop_conditions);
  setLines('guardConfirm', p.confirm_tools); setLines('guardBlocked', p.blocked_tools);
}}
async function saveGuardrails() {{ try {{
  const payload = {{
    safety_mode: document.getElementById('guardSafety').value,
    testing_window: document.getElementById('guardWindow').value,
    notes: document.getElementById('guardNotes').value,
    in_scope_targets: getLines('guardScope'),
    allowed_techniques: getLines('guardAllowed'),
    prohibited_techniques: getLines('guardProhibited'),
    stop_conditions: getStopLines('guardStops'),
    confirm_tools: getLines('guardConfirm'),
    blocked_tools: getLines('guardBlocked'),
    persist: true
  }};
  show('guardrails', await api('/guardrails', {{method:'POST', body: JSON.stringify(payload)}})); await loadAll();
}} catch(e) {{ err(e); }} }}
async function sendMessage() {{ try {{ show('messageResult', await api('/message', {{method:'POST', body: JSON.stringify({{message: document.getElementById('message').value}})}})); await loadAll(); }} catch(e) {{ err(e); }} }}
async function createFinding() {{ try {{ show('findingResult', await api('/finding', {{method:'POST', body: JSON.stringify({{title: document.getElementById('findingTitle').value, severity: document.getElementById('findingSeverity').value, description: document.getElementById('findingDescription').value}})}})); await loadAll(); }} catch(e) {{ err(e); }} }}
</script>
</body>
</html>
"""


def _read_json(handler: BaseHTTPRequestHandler) -> Any:
    raw_length = handler.headers.get("Content-Length", "0") or "0"
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        raise GatewayRequestError("Content-Length must be an integer") from None
    if length < 0:
        raise GatewayRequestError("Content-Length must be non-negative")
    max_body = int(getattr(handler.server, "max_body_bytes", DEFAULT_MAX_JSON_BODY_BYTES))  # type: ignore[attr-defined]
    if length > max_body:
        raise GatewayRequestError(f"JSON body too large; limit is {max_body} bytes", status=413)
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise GatewayRequestError("JSON body must be UTF-8") from None
    except json.JSONDecodeError:
        raise GatewayRequestError("JSON body must be valid JSON") from None


def _payload_first(payload: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in payload:
            return payload.get(name)
    return None


def _payload_required_int(handler: BaseHTTPRequestHandler, payload: dict[str, Any], *names: str, label: str = "id") -> int | None:
    raw = _payload_first(payload, *names)
    if raw is None or raw == "":
        _write_json(handler, {"error": f"{label} is required"}, status=400)
        return None
    if isinstance(raw, bool):
        _write_json(handler, {"error": f"{label} must be an integer"}, status=400)
        return None
    if isinstance(raw, float):
        _write_json(handler, {"error": f"{label} must be an integer"}, status=400)
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        _write_json(handler, {"error": f"{label} must be an integer"}, status=400)
        return None


def _write_json(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    _write_common_headers(handler, "application/json", len(body))
    handler.end_headers()
    handler.wfile.write(body)


def _write_empty(handler: BaseHTTPRequestHandler, status: int = 204) -> None:
    handler.send_response(status)
    _write_common_headers(handler, "text/plain", 0)
    handler.end_headers()


def _write_html(handler: BaseHTTPRequestHandler, body_text: str, status: int = 200) -> None:
    body = body_text.encode("utf-8")
    handler.send_response(status)
    _write_common_headers(handler, "text/html; charset=utf-8", len(body))
    handler.end_headers()
    handler.wfile.write(body)


def _write_common_headers(handler: BaseHTTPRequestHandler, content_type: str, length: int) -> None:
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(length))
    origin = handler.headers.get("Origin", "")
    allowed = _cors_origin(handler, origin)
    if allowed:
        handler.send_header("Access-Control-Allow-Origin", allowed)
        handler.send_header("Vary", "Origin")
        handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Phobos-Token")
        handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")


def _cors_origin(handler: BaseHTTPRequestHandler, origin: str) -> str:
    origins = tuple(getattr(handler.server, "allow_origins", ()))  # type: ignore[attr-defined]
    if not origin:
        return ""
    if "*" in origins:
        return "*"
    return origin if origin in origins else ""


def _auth_required(handler: BaseHTTPRequestHandler) -> bool:
    return bool(getattr(handler.server, "auth_token", ""))  # type: ignore[attr-defined]


def _authorized(handler: BaseHTTPRequestHandler) -> bool:
    token = getattr(handler.server, "auth_token", "")  # type: ignore[attr-defined]
    if not token:
        return True
    auth = handler.headers.get("Authorization", "")
    supplied = ""
    if auth.lower().startswith("bearer "):
        supplied = auth.split(" ", 1)[1].strip()
    supplied = supplied or handler.headers.get("X-Phobos-Token", "").strip()
    return supplied == token


def _gateway_auth_status(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    token_env = str(getattr(handler.server, "token_env", ""))  # type: ignore[attr-defined]
    return {"auth_required": _auth_required(handler), "token_env": token_env, "token_present": bool(getattr(handler.server, "auth_token", "")), "allow_origins": list(getattr(handler.server, "allow_origins", ())), "unsafe_no_auth": bool(getattr(handler.server, "unsafe_no_auth", False)), "max_body_bytes": int(getattr(handler.server, "max_body_bytes", DEFAULT_MAX_JSON_BODY_BYTES))}


def _audit_gateway_auth(runtime: OffSecAgentRuntime, lock: threading.RLock, handler: BaseHTTPRequestHandler, path: str) -> None:
    with lock:
        runtime.store.audit(runtime.session_id, "gateway_auth_failed", {"client": handler.client_address[0] if handler.client_address else "", "path": path})


def _is_local_bind(host: str) -> bool:
    return str(host).strip().lower() in {"127.0.0.1", "localhost", "::1", ""}


SAFETY_MODE_DESCRIPTIONS = {
    "non_destructive": "Allow routine in-scope active enumeration; confirm state-changing or lockout-sensitive actions; block destructive/disruptive/prohibited actions.",
    "standard": "Conservative mode: active/noisy testing also queues for approval; destructive/disruptive/prohibited actions still block.",
}


def _guardrail_policy(runtime: OffSecAgentRuntime) -> dict[str, Any]:
    tool_specs = sorted(runtime.registry.specs(), key=lambda spec: spec.name)
    blocked = sorted(runtime.registry.blocked_tools)
    confirm = sorted(runtime.registry.confirm_tools)
    blocked_set = set(blocked)
    confirm_set = set(confirm)
    tools = []
    for spec in tool_specs:
        policy = "blocked" if spec.name in blocked_set else "confirm" if spec.name in confirm_set else "allow"
        tools.append({"name": spec.name, "description": spec.description, "policy": policy})
    config_path = runtime.config.config_path
    return {
        "engagement": {
            "path": str(runtime.config.engagement_path),
            "name": runtime.roe.name,
            "authorized": runtime.roe.authorized,
            "in_scope_targets": list(runtime.roe.in_scope_targets),
            "allowed_techniques": list(runtime.roe.allowed_techniques),
            "prohibited_techniques": list(runtime.roe.prohibited_techniques),
            "testing_window": runtime.roe.testing_window,
            "notes": runtime.roe.notes,
            "stop_conditions": list(runtime.roe.stop_conditions),
            "evidence_dir": runtime.roe.evidence_dir,
            "safety_mode": runtime.roe.safety_mode,
            "safety_modes": SAFETY_MODE_DESCRIPTIONS,
        },
        "runtime_policy": {
            "blocked_tools": blocked,
            "confirm_tools": confirm,
            "config_path": str(config_path or ""),
            "persistent": bool(config_path),
        },
        "tools": tools,
        "presets": {
            "balanced": {"safety_mode": "non_destructive", "description": "Default Caligo/Phobos posture."},
            "conservative": {"safety_mode": "standard", "description": "Approval-gate active scanner/noisy tools."},
            "import_only": {"description": "Block live scanner/process tools; parser/import paths can still be used explicitly.", "blocked_tools": ["nmap_scan", "httpx_probe", "nuclei_scan", "ffuf_scan", "run_command", "start_process"]},
        },
    }


def _apply_guardrail_policy(runtime: OffSecAgentRuntime, payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("guardrail payload must be an object")
    engagement_keys = {"safety_mode", "in_scope_targets", "allowed_techniques", "prohibited_techniques", "testing_window", "notes", "stop_conditions"}
    runtime_keys = {"blocked_tools", "confirm_tools"}
    top_keys = engagement_keys | runtime_keys | {"engagement", "runtime_policy", "tool_policy", "persist"}
    unknown_top = sorted(set(payload) - top_keys)
    if unknown_top:
        raise ValueError("unknown guardrail policy fields: " + ", ".join(unknown_top))
    if "engagement" in payload and not isinstance(payload.get("engagement"), dict):
        raise ValueError("engagement must be an object")
    if "runtime_policy" in payload and not isinstance(payload.get("runtime_policy"), dict):
        raise ValueError("runtime_policy must be an object")
    if "tool_policy" in payload and not isinstance(payload.get("tool_policy"), dict):
        raise ValueError("tool_policy must be an object")
    engagement_payload = payload.get("engagement") if isinstance(payload.get("engagement"), dict) else payload
    if engagement_payload is not payload:
        unknown_engagement = sorted(set(engagement_payload) - engagement_keys)
        if unknown_engagement:
            raise ValueError("unknown engagement policy fields: " + ", ".join(unknown_engagement))
    runtime_payload = payload.get("runtime_policy") or payload.get("tool_policy")
    if isinstance(runtime_payload, dict):
        unknown_runtime = sorted(set(runtime_payload) - runtime_keys)
        if unknown_runtime:
            raise ValueError("unknown runtime policy fields: " + ", ".join(unknown_runtime))
    else:
        runtime_payload = payload
    persist = bool(payload.get("persist", True))
    changed: list[str] = []
    warnings: list[str] = []

    safety_mode = engagement_payload.get("safety_mode")
    if safety_mode is not None:
        normalized = str(safety_mode).strip().lower().replace("-", "_")
        if normalized not in SAFETY_MODE_DESCRIPTIONS:
            raise ValueError("safety_mode must be non_destructive or standard")
        if runtime.roe.safety_mode != normalized:
            runtime.roe.safety_mode = normalized
            changed.append("engagement.safety_mode")

    list_fields = {
        "in_scope_targets": True,
        "allowed_techniques": True,
        "prohibited_techniques": True,
        "stop_conditions": False,
    }
    for field, comma_split in list_fields.items():
        if field in engagement_payload:
            values = _coerce_policy_list(engagement_payload.get(field), comma_split=comma_split)
            if getattr(runtime.roe, field) != values:
                setattr(runtime.roe, field, values)
                changed.append(f"engagement.{field}")

    if "testing_window" in engagement_payload:
        testing_window = str(engagement_payload.get("testing_window") or "not specified")
        if runtime.roe.testing_window != testing_window:
            runtime.roe.testing_window = testing_window
            changed.append("engagement.testing_window")
    if "notes" in engagement_payload:
        notes = str(engagement_payload.get("notes") or "")
        if runtime.roe.notes != notes:
            runtime.roe.notes = notes
            changed.append("engagement.notes")

    engagement_changed = any(item.startswith("engagement.") for item in changed)
    if engagement_changed and persist:
        runtime.roe.save(runtime.config.engagement_path)

    policy_changed = False
    if "blocked_tools" in runtime_payload or "confirm_tools" in runtime_payload:
        available = {spec.name for spec in runtime.registry.specs()}
        blocked = set(_coerce_policy_list(runtime_payload.get("blocked_tools", sorted(runtime.registry.blocked_tools))))
        confirm = set(_coerce_policy_list(runtime_payload.get("confirm_tools", sorted(runtime.registry.confirm_tools))))
        unknown = sorted((blocked | confirm) - available)
        if unknown:
            warnings.append("Unknown tool names ignored: " + ", ".join(unknown))
        blocked &= available
        confirm &= available
        confirm -= blocked
        if blocked != runtime.registry.blocked_tools:
            runtime.registry.blocked_tools = blocked
            runtime.config.blocked_tools = tuple(sorted(blocked))
            changed.append("runtime_policy.blocked_tools")
            policy_changed = True
        if confirm != runtime.registry.confirm_tools:
            runtime.registry.confirm_tools = confirm
            runtime.config.confirm_tools = tuple(sorted(confirm))
            changed.append("runtime_policy.confirm_tools")
            policy_changed = True

    config_persisted = False
    if policy_changed and persist:
        if runtime.config.config_path:
            cfg_path = Path(runtime.config.config_path)
            cfg = AgentAppConfig.load(cfg_path)
            cfg.blocked_tools = sorted(runtime.registry.blocked_tools)
            cfg.confirm_tools = sorted(runtime.registry.confirm_tools)
            cfg.save(cfg_path)
            config_persisted = True
        else:
            warnings.append("Runtime tool policy updated in memory only because no agent.config.json path is attached to this runtime.")

    runtime.store.audit(runtime.session_id, "guardrail_policy_updated", {"changed": changed, "persist": persist, "config_persisted": config_persisted, "warnings": warnings})
    result = _guardrail_policy(runtime)
    result["status"] = "updated"
    result["changed"] = changed
    result["persisted"] = {"engagement": bool(engagement_changed and persist), "runtime_policy": config_persisted}
    result["warnings"] = warnings
    return result


def _coerce_policy_list(value: Any, *, comma_split: bool = True) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        if comma_split:
            raw = value.replace("\r", "\n").replace(",", "\n").split("\n")
        else:
            raw = value.replace("\r", "\n").split("\n")
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = [value]
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = str(item).strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def _dashboard_html(runtime: OffSecAgentRuntime) -> str:
    status = runtime.registry.run("runtime_status", {}).data
    tasks = runtime.store.list_tasks(runtime.session_id, status="all", limit=20)
    approvals = runtime.store.list_approvals(runtime.session_id, status="pending")
    recent = runtime.store.recent_messages(runtime.session_id, limit=8)
    media = runtime.store.list_media_artifacts(runtime.session_id, limit=8)
    delegations = runtime.store.list_delegations(runtime.session_id, limit=8)
    findings = runtime.store.list_findings(runtime.session_id, status="all", limit=8)
    tool_runs = runtime.store.list_tool_runs(runtime.session_id, limit=8)
    jobs = runtime.registry.run("list_jobs", {}).data.get("jobs", [])
    guardrails = _guardrail_policy(runtime)
    engagement_policy = guardrails["engagement"]
    runtime_policy = guardrails["runtime_policy"]
    tool_count = len(runtime.registry.specs())
    task_items = "\n".join(f"<li><code>{html.escape(task['status'])}</code> #{task['id']} {html.escape(task['content'])}</li>" for task in tasks) or "<li>No tasks yet.</li>"
    approval_items = "\n".join(f"<li>#{approval['id']} <code>{html.escape(approval['tool_name'])}</code> {html.escape(str(approval.get('requested_at', '')))}</li>" for approval in approvals) or "<li>No pending approvals.</li>"
    recent_items = "\n".join(f"<li><code>{html.escape(msg['role'])}</code> {html.escape(str(msg['content'])[:300])}</li>" for msg in recent) or "<li>No messages yet.</li>"
    media_items = "\n".join(f"<li><code>{html.escape(item['kind'])}</code> {html.escape(str(item.get('mime_type', '')))} {html.escape(str(item.get('artifact_path') or item.get('source_path') or ''))}</li>" for item in media) or "<li>No media artifacts yet.</li>"
    delegation_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['status'])}</code> {html.escape(str(item.get('prompt', ''))[:160])}</li>" for item in delegations) or "<li>No delegations yet.</li>"
    finding_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['status'])}</code> {html.escape(item['severity'])} — {html.escape(item['title'])}</li>" for item in findings) or "<li>No findings yet.</li>"
    tool_run_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['tool_name'])}</code> {html.escape(item['status'])} — {html.escape(item['target'])}</li>" for item in tool_runs) or "<li>No structured tool runs yet.</li>"
    job_items = "\n".join(f"<li>#{item.get('id')} <code>{'enabled' if item.get('enabled') else 'disabled'}</code> {html.escape(str(item.get('schedule', '')))} — {html.escape(str(item.get('name', ''))[:140])}</li>" for item in jobs[:8]) or "<li>No scheduled jobs yet.</li>"
    api_links = ", ".join(f'<a href="{html.escape(path)}">{html.escape(path)}</a>' for path in _gateway_paths() if path not in {"/message", "/tool", "/finding", "/guardrails", "/approve", "/deny", "/run-due"})
    safety_non_destructive_selected = "selected" if str(runtime.roe.safety_mode) == "non_destructive" else ""
    safety_standard_selected = "selected" if str(runtime.roe.safety_mode) == "standard" else ""
    scope_text = html.escape("\n".join(engagement_policy["in_scope_targets"]))
    allowed_text = html.escape("\n".join(engagement_policy["allowed_techniques"]))
    prohibited_text = html.escape("\n".join(engagement_policy["prohibited_techniques"]))
    testing_window_text = html.escape(str(engagement_policy["testing_window"]), quote=True)
    notes_text = html.escape(str(engagement_policy.get("notes", "")))
    stops_text = html.escape("\n".join(engagement_policy["stop_conditions"]))
    confirm_tools_text = html.escape("\n".join(runtime_policy["confirm_tools"]))
    blocked_tools_text = html.escape("\n".join(runtime_policy["blocked_tools"]))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Phobos Agent Gateway</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0d1117; color: #e6edf3; }}
    a {{ color: #7dd3fc; }} code, pre {{ background: #161b22; border-radius: .35rem; padding: .15rem .35rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }}
    section {{ border: 1px solid #30363d; border-radius: .75rem; padding: 1rem; background: #111827; }}
    input, textarea, select {{ width: 100%; min-height: 2.4rem; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: .5rem; padding: .5rem; box-sizing: border-box; }}
    textarea {{ min-height: 7rem; }}
    button {{ background: #238636; color: white; border: 0; border-radius: .5rem; padding: .5rem .8rem; }}
    .wide {{ grid-column: 1 / -1; }}
  </style>
</head>
<body>
  <h1>Phobos Agent Gateway</h1>
  <p>Hermes-like runtime for authorized OffSec workflows. Default safety posture: <code>{html.escape(str(runtime.roe.safety_mode))}</code>. For a browser-to-VPS client, open <a href="/ui-client">/ui-client</a>.</p>
  <div class="grid">
    <section><h2>Status</h2><pre>{html.escape(json.dumps(status, indent=2)[:1600])}</pre></section>
    <section><h2>Task Board</h2><ul>{task_items}</ul></section>
    <section><h2>Findings</h2><ul>{finding_items}</ul></section>
    <section><h2>Structured Tool Runs</h2><ul>{tool_run_items}</ul></section>
    <section><h2>Scheduled Jobs</h2><ul>{job_items}</ul></section>
    <section><h2>Pending Approvals</h2><ul>{approval_items}</ul></section>
    <section><h2>Media / Voice Artifacts</h2><ul>{media_items}</ul></section>
    <section><h2>Local Delegations</h2><ul>{delegation_items}</ul></section>
    <section><h2>Recent Messages</h2><ul>{recent_items}</ul></section>
    <section class="wide">
      <h2>Granular Guardrails</h2>
      <p>Adjust engagement ROE and per-tool runtime policy. ROE fields persist to <code>{html.escape(str(runtime.config.engagement_path))}</code>. Tool policy persistence: <code>{html.escape(str(runtime_policy['persistent']))}</code>{' via <code>' + html.escape(str(runtime_policy['config_path'])) + '</code>' if runtime_policy['config_path'] else ' (current runtime only unless started with --config)'}.</p>
      <label>Safety mode
        <select id="guardSafety">
          <option value="non_destructive" {safety_non_destructive_selected}>non_destructive — allow routine in-scope enumeration</option>
          <option value="standard" {safety_standard_selected}>standard — approval-gate active/noisy testing</option>
        </select>
      </label>
      <label>Testing window<input id="guardWindow" value="{testing_window_text}" placeholder="business hours, change window ID, or not specified"></label>
      <label>Scope targets, one per line<textarea id="guardScope">{scope_text}</textarea></label>
      <label>Allowed techniques, one per line<textarea id="guardAllowed">{allowed_text}</textarea></label>
      <label>Prohibited techniques, one per line<textarea id="guardProhibited">{prohibited_text}</textarea></label>
      <label>Stop conditions, one per line<textarea id="guardStops">{stops_text}</textarea></label>
      <label>Notes<textarea id="guardNotes" placeholder="operator notes; do not paste secrets">{notes_text}</textarea></label>
      <label>Tools requiring approval, one per line<textarea id="guardConfirm">{confirm_tools_text}</textarea></label>
      <label>Blocked tools, one per line<textarea id="guardBlocked">{blocked_tools_text}</textarea></label>
      <button onclick="saveGuardrails()">Save Guardrail Policy</button>
      <pre id="guardrailResponse"></pre>
    </section>
  </div>
  <section>
    <h2>Send Message</h2>
    <textarea id="message">/status</textarea><br>
    <button onclick="sendMessage()">Send to /message</button>
    <pre id="response"></pre>
  </section>
  <section>
    <h2>API Links</h2>
    <p>Tools registered: {tool_count}. JSON endpoints: {api_links}. POST endpoints: <code>/message</code>, <code>/tool</code>, <code>/finding</code>, <code>/approve</code>, <code>/deny</code>, <code>/run-due</code>.</p>
  </section>
  <script>
    function getLines(id) {{ return document.getElementById(id).value.split(/\\n|,/).map(x=>x.trim()).filter(Boolean); }}
    function getStopLines(id) {{ return document.getElementById(id).value.split(/\\n/).map(x=>x.trim()).filter(Boolean); }}
    async function saveGuardrails() {{
      const payload = {{
        safety_mode: document.getElementById('guardSafety').value,
        testing_window: document.getElementById('guardWindow').value,
        notes: document.getElementById('guardNotes').value,
        in_scope_targets: getLines('guardScope'),
        allowed_techniques: getLines('guardAllowed'),
        prohibited_techniques: getLines('guardProhibited'),
        stop_conditions: getStopLines('guardStops'),
        confirm_tools: getLines('guardConfirm'),
        blocked_tools: getLines('guardBlocked'),
        persist: true
      }};
      const response = await fetch('/guardrails', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify(payload)}});
      document.getElementById('guardrailResponse').textContent = JSON.stringify(await response.json(), null, 2);
    }}
    async function sendMessage() {{
      const response = await fetch('/message', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{message: document.getElementById('message').value}})}});
      document.getElementById('response').textContent = JSON.stringify(await response.json(), null, 2);
    }}
  </script>
</body>
</html>
"""
