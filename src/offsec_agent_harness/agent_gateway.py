from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import html
import json
import threading
from urllib.parse import parse_qs, urlparse

from .agent_runtime import OffSecAgentRuntime
from .agent_bridges import BridgeConfig


class AgentGateway:
    """Minimal local HTTP gateway for the standalone Phobos Agent.

    This mirrors the Hermes gateway idea for local API access: local clients can
    send a message, list tools, run due jobs, and health-check the runtime. The
    Discord/Slack/Telegram bridges live in agent_bridges.py. Bind this gateway
    to 127.0.0.1 by default.
    """

    def __init__(self, runtime: OffSecAgentRuntime, host: str = "127.0.0.1", port: int = 8765):
        self.runtime = runtime
        self.host = host
        self.port = port
        handler = self._handler_class()
        self.server = ThreadingHTTPServer((host, port), handler)
        self.server.runtime = runtime  # type: ignore[attr-defined]
        self.server.runtime_lock = threading.RLock()  # type: ignore[attr-defined]

    @property
    def server_address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def serve_forever(self) -> None:  # pragma: no cover - CLI convenience
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            server_version = "PhobosAgentGateway/0.1"

            def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
                runtime: OffSecAgentRuntime = self.server.runtime  # type: ignore[attr-defined]
                lock = self.server.runtime_lock  # type: ignore[attr-defined]
                parsed = urlparse(self.path)
                path = parsed.path
                with lock:
                    if path in {"/", "/ui"}:
                        _write_html(self, _dashboard_html(runtime))
                        return
                    if path == "/health":
                        _write_json(self, {"ok": True, "session_id": runtime.session_id, "engagement": runtime.roe.name})
                        return
                    if path == "/routes":
                        _write_json(self, {"paths": _gateway_paths()})
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
                    if path == "/sessions":
                        _write_json(self, {"session_id": runtime.session_id, "sessions": runtime.store.list_sessions(limit=50), "recent": runtime.store.recent_messages(runtime.session_id, limit=12)})
                        return
                    if path == "/context":
                        _write_json(self, runtime.registry.run("context_snapshot", {}).to_dict())
                        return
                    if path == "/approvals":
                        _write_json(self, runtime.registry.run("list_approvals", {}).to_dict())
                        return
                    if path == "/audit":
                        _write_json(self, runtime.registry.run("audit_log", {"limit": 50}).to_dict())
                        return
                    if path == "/tasks":
                        _write_json(self, runtime.registry.run("list_tasks", {"status": "all"}).to_dict())
                        return
                    if path == "/jobs":
                        _write_json(self, runtime.registry.run("list_jobs", {}).to_dict())
                        return
                    if path == "/processes":
                        _write_json(self, runtime.registry.run("list_processes", {}).to_dict())
                        return
                    if path == "/lcm":
                        _write_json(self, runtime.registry.run("context_describe", {}).to_dict())
                        return
                    if path == "/delegations":
                        _write_json(self, runtime.registry.run("list_delegations", {}).to_dict())
                        return
                    if path == "/media":
                        _write_json(self, runtime.registry.run("media_list", {}).to_dict())
                        return
                    if path == "/auth":
                        _write_json(self, runtime.registry.run("auth_status", {}).to_dict())
                        return
                    if path == "/bridges":
                        bridge_configs = {name: BridgeConfig.from_dict(name, data).sanitized() for name, data in (runtime.config.bridges or {}).items()}
                        _write_json(self, {"bridges": bridge_configs})
                        return
                _write_json(self, {"error": "not found", "paths": _gateway_paths()}, status=404)

            def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
                runtime: OffSecAgentRuntime = self.server.runtime  # type: ignore[attr-defined]
                try:
                    payload = _read_json(self)
                    lock = self.server.runtime_lock  # type: ignore[attr-defined]
                    with lock:
                        if self.path == "/message":
                            message = str(payload.get("message", ""))
                            if not message:
                                _write_json(self, {"error": "message is required"}, status=400)
                                return
                            response = runtime.handle_message(message)
                            _write_json(self, {"response": response, "session_id": runtime.session_id})
                            return
                        if self.path == "/tool":
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
                        if self.path == "/run-due":
                            _write_json(self, {"jobs_run": runtime.run_due_jobs()})
                            return
                        if self.path == "/approve":
                            approval_id = payload.get("id") or payload.get("approval_id")
                            if approval_id is None:
                                _write_json(self, {"error": "id is required"}, status=400)
                                return
                            result = runtime.registry.run("approve", {"id": approval_id, "by": payload.get("by", "gateway")})
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                        if self.path == "/deny":
                            approval_id = payload.get("id") or payload.get("approval_id")
                            if approval_id is None:
                                _write_json(self, {"error": "id is required"}, status=400)
                                return
                            result = runtime.registry.run("deny", {"id": approval_id, "by": payload.get("by", "gateway"), "reason": payload.get("reason", "")})
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                    _write_json(self, {"error": "not found", "paths": _gateway_paths()}, status=404)
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
        "/health",
        "/routes",
        "/status",
        "/tools",
        "/schemas",
        "/sessions",
        "/context",
        "/lcm",
        "/tasks",
        "/jobs",
        "/processes",
        "/approvals",
        "/delegations",
        "/media",
        "/auth",
        "/bridges",
        "/audit",
        "/message",
        "/tool",
        "/approve",
        "/deny",
        "/run-due",
    ]


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _write_json(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _write_html(handler: BaseHTTPRequestHandler, body_text: str, status: int = 200) -> None:
    body = body_text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _dashboard_html(runtime: OffSecAgentRuntime) -> str:
    status = runtime.registry.run("runtime_status", {}).data
    tasks = runtime.store.list_tasks(runtime.session_id, status="all", limit=20)
    approvals = runtime.store.list_approvals(runtime.session_id, status="pending")
    recent = runtime.store.recent_messages(runtime.session_id, limit=8)
    media = runtime.store.list_media_artifacts(runtime.session_id, limit=8)
    delegations = runtime.store.list_delegations(runtime.session_id, limit=8)
    tool_count = len(runtime.registry.specs())
    task_items = "\n".join(f"<li><code>{html.escape(task['status'])}</code> #{task['id']} {html.escape(task['content'])}</li>" for task in tasks) or "<li>No tasks yet.</li>"
    approval_items = "\n".join(f"<li>#{approval['id']} <code>{html.escape(approval['tool_name'])}</code> {html.escape(str(approval.get('requested_at', '')))}</li>" for approval in approvals) or "<li>No pending approvals.</li>"
    recent_items = "\n".join(f"<li><code>{html.escape(msg['role'])}</code> {html.escape(str(msg['content'])[:300])}</li>" for msg in recent) or "<li>No messages yet.</li>"
    media_items = "\n".join(f"<li><code>{html.escape(item['kind'])}</code> {html.escape(str(item.get('mime_type', '')))} {html.escape(str(item.get('artifact_path') or item.get('source_path') or ''))}</li>" for item in media) or "<li>No media artifacts yet.</li>"
    delegation_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['status'])}</code> {html.escape(str(item.get('prompt', ''))[:160])}</li>" for item in delegations) or "<li>No delegations yet.</li>"
    api_links = ", ".join(f'<a href="{html.escape(path)}">{html.escape(path)}</a>' for path in _gateway_paths() if path not in {"/message", "/tool", "/approve", "/deny", "/run-due"})
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
    textarea {{ width: 100%; min-height: 7rem; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: .5rem; padding: .5rem; }}
    button {{ background: #238636; color: white; border: 0; border-radius: .5rem; padding: .5rem .8rem; }}
  </style>
</head>
<body>
  <h1>Phobos Agent Gateway</h1>
  <p>Local Hermes-like runtime for authorized OffSec workflows. Default safety posture: <code>{html.escape(str(runtime.roe.safety_mode))}</code>.</p>
  <div class="grid">
    <section><h2>Status</h2><pre>{html.escape(json.dumps(status, indent=2)[:1600])}</pre></section>
    <section><h2>Task Board</h2><ul>{task_items}</ul></section>
    <section><h2>Pending Approvals</h2><ul>{approval_items}</ul></section>
    <section><h2>Media / Voice Artifacts</h2><ul>{media_items}</ul></section>
    <section><h2>Local Delegations</h2><ul>{delegation_items}</ul></section>
    <section><h2>Recent Messages</h2><ul>{recent_items}</ul></section>
  </div>
  <section>
    <h2>Send Message</h2>
    <textarea id="message">/status</textarea><br>
    <button onclick="sendMessage()">Send to /message</button>
    <pre id="response"></pre>
  </section>
  <section>
    <h2>API Links</h2>
    <p>Tools registered: {tool_count}. JSON endpoints: {api_links}. POST endpoints: <code>/message</code>, <code>/tool</code>, <code>/approve</code>, <code>/deny</code>, <code>/run-due</code>.</p>
  </section>
  <script>
    async function sendMessage() {{
      const response = await fetch('/message', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{message: document.getElementById('message').value}})}});
      document.getElementById('response').textContent = JSON.stringify(await response.json(), null, 2);
    }}
  </script>
</body>
</html>
"""
