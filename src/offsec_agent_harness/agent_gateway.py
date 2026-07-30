from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import html
import json
import os
import threading
from urllib.parse import parse_qs, urlparse

from .agent_runtime import OffSecAgentRuntime
from .agent_bridges import BridgeConfig


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
    ):
        self.runtime = runtime
        self.host = host
        self.port = port
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
                    _write_json(self, {"ok": True, "session_id": runtime.session_id, "engagement": runtime.roe.name, "auth_required": _auth_required(self), "remote_safe": bool(getattr(self.server, "auth_token", "")) or _is_local_bind(self.server.server_address[0])})
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
                    if path == "/findings":
                        query = parse_qs(parsed.query)
                        _write_json(self, runtime.registry.run("list_findings", {"status": (query.get("status") or ["all"])[0], "limit": int((query.get("limit") or [50])[0])}).to_dict())
                        return
                    if path == "/tool-runs":
                        query = parse_qs(parsed.query)
                        args: dict[str, Any] = {"limit": int((query.get("limit") or [50])[0])}
                        if (query.get("tool_name") or [""])[0]:
                            args["tool_name"] = (query.get("tool_name") or [""])[0]
                        _write_json(self, runtime.registry.run("list_tool_runs", args).to_dict())
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
                        _write_json(self, runtime.registry.run("auth_status", {}).to_dict() | {"gateway": _gateway_auth_status(self)})
                        return
                    if path == "/bridges":
                        bridge_configs = {name: BridgeConfig.from_dict(name, data).sanitized() for name, data in (runtime.config.bridges or {}).items()}
                        _write_json(self, {"bridges": bridge_configs})
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
                    with lock:
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
                            approval_id = payload.get("id") or payload.get("approval_id")
                            if approval_id is None:
                                _write_json(self, {"error": "id is required"}, status=400)
                                return
                            result = runtime.registry.run("approve", {"id": approval_id, "by": payload.get("by", "gateway")})
                            _write_json(self, {"result": result.to_dict(), "session_id": runtime.session_id})
                            return
                        if path == "/deny":
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
        "/ui-client",
        "/health",
        "/routes",
        "/status",
        "/tools",
        "/schemas",
        "/sessions",
        "/context",
        "/lcm",
        "/tasks",
        "/findings",
        "/tool-runs",
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
        "/finding",
        "/approve",
        "/deny",
        "/run-due",
    ]


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
    input, textarea {{ width: 100%; box-sizing: border-box; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: .5rem; padding: .55rem; }}
    textarea {{ min-height: 7rem; }} button {{ background: #238636; color: white; border: 0; border-radius: .5rem; padding: .55rem .85rem; margin-top: .4rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }} section {{ border: 1px solid #30363d; border-radius: .75rem; padding: 1rem; background: #111827; }}
    pre {{ white-space: pre-wrap; background: #161b22; border-radius: .5rem; padding: .75rem; max-height: 28rem; overflow: auto; }} code {{ background: #161b22; padding: .1rem .25rem; border-radius: .25rem; }}
  </style>
</head>
<body>
  <h1>Phobos Agent Remote Client</h1>
  <p>Connect this browser to a local or VPS-hosted Phobos Agent gateway. The token stays in this browser tab and is sent as an <code>Authorization: Bearer</code> header; it is not stored by Phobos docs or config.</p>
  <section>
    <label>Agent base URL <input id="base" value="{default_base}" placeholder="https://agent.example.com or http://127.0.0.1:8765"></label><br><br>
    <label>Bearer token <input id="token" type="password" placeholder="paste gateway token from your password manager"></label><br>
    <button onclick="loadAll()">Connect / Refresh</button>
    <button onclick="health()">Health</button>
    <pre id="errors"></pre>
  </section>
  <div class="grid">
    <section><h2>Status</h2><pre id="status"></pre></section>
    <section><h2>Findings</h2><pre id="findings"></pre></section>
    <section><h2>Tool Runs</h2><pre id="toolruns"></pre></section>
    <section><h2>Approvals</h2><pre id="approvals"></pre></section>
    <section><h2>Tasks</h2><pre id="tasks"></pre></section>
    <section><h2>Processes</h2><pre id="processes"></pre></section>
  </div>
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
  api('/status').then(d=>show('status',d)), api('/findings').then(d=>show('findings',d)), api('/tool-runs').then(d=>show('toolruns',d)), api('/approvals').then(d=>show('approvals',d)), api('/tasks').then(d=>show('tasks',d)), api('/processes').then(d=>show('processes',d))
]); }} catch(e) {{ err(e); }} }}
async function sendMessage() {{ try {{ show('messageResult', await api('/message', {{method:'POST', body: JSON.stringify({{message: document.getElementById('message').value}})}})); await loadAll(); }} catch(e) {{ err(e); }} }}
async function createFinding() {{ try {{ show('findingResult', await api('/finding', {{method:'POST', body: JSON.stringify({{title: document.getElementById('findingTitle').value, severity: document.getElementById('findingSeverity').value, description: document.getElementById('findingDescription').value}})}})); await loadAll(); }} catch(e) {{ err(e); }} }}
</script>
</body>
</html>
"""


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


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
    return {"auth_required": _auth_required(handler), "token_env": token_env, "token_present": bool(getattr(handler.server, "auth_token", "")), "allow_origins": list(getattr(handler.server, "allow_origins", ())), "unsafe_no_auth": bool(getattr(handler.server, "unsafe_no_auth", False))}


def _audit_gateway_auth(runtime: OffSecAgentRuntime, lock: threading.RLock, handler: BaseHTTPRequestHandler, path: str) -> None:
    with lock:
        runtime.store.audit(runtime.session_id, "gateway_auth_failed", {"client": handler.client_address[0] if handler.client_address else "", "path": path})


def _is_local_bind(host: str) -> bool:
    return str(host).strip().lower() in {"127.0.0.1", "localhost", "::1", ""}


def _dashboard_html(runtime: OffSecAgentRuntime) -> str:
    status = runtime.registry.run("runtime_status", {}).data
    tasks = runtime.store.list_tasks(runtime.session_id, status="all", limit=20)
    approvals = runtime.store.list_approvals(runtime.session_id, status="pending")
    recent = runtime.store.recent_messages(runtime.session_id, limit=8)
    media = runtime.store.list_media_artifacts(runtime.session_id, limit=8)
    delegations = runtime.store.list_delegations(runtime.session_id, limit=8)
    findings = runtime.store.list_findings(runtime.session_id, status="all", limit=8)
    tool_runs = runtime.store.list_tool_runs(runtime.session_id, limit=8)
    tool_count = len(runtime.registry.specs())
    task_items = "\n".join(f"<li><code>{html.escape(task['status'])}</code> #{task['id']} {html.escape(task['content'])}</li>" for task in tasks) or "<li>No tasks yet.</li>"
    approval_items = "\n".join(f"<li>#{approval['id']} <code>{html.escape(approval['tool_name'])}</code> {html.escape(str(approval.get('requested_at', '')))}</li>" for approval in approvals) or "<li>No pending approvals.</li>"
    recent_items = "\n".join(f"<li><code>{html.escape(msg['role'])}</code> {html.escape(str(msg['content'])[:300])}</li>" for msg in recent) or "<li>No messages yet.</li>"
    media_items = "\n".join(f"<li><code>{html.escape(item['kind'])}</code> {html.escape(str(item.get('mime_type', '')))} {html.escape(str(item.get('artifact_path') or item.get('source_path') or ''))}</li>" for item in media) or "<li>No media artifacts yet.</li>"
    delegation_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['status'])}</code> {html.escape(str(item.get('prompt', ''))[:160])}</li>" for item in delegations) or "<li>No delegations yet.</li>"
    finding_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['status'])}</code> {html.escape(item['severity'])} — {html.escape(item['title'])}</li>" for item in findings) or "<li>No findings yet.</li>"
    tool_run_items = "\n".join(f"<li>#{item['id']} <code>{html.escape(item['tool_name'])}</code> {html.escape(item['status'])} — {html.escape(item['target'])}</li>" for item in tool_runs) or "<li>No structured tool runs yet.</li>"
    api_links = ", ".join(f'<a href="{html.escape(path)}">{html.escape(path)}</a>' for path in _gateway_paths() if path not in {"/message", "/tool", "/finding", "/approve", "/deny", "/run-due"})
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
  <p>Hermes-like runtime for authorized OffSec workflows. Default safety posture: <code>{html.escape(str(runtime.roe.safety_mode))}</code>. For a browser-to-VPS client, open <a href="/ui-client">/ui-client</a>.</p>
  <div class="grid">
    <section><h2>Status</h2><pre>{html.escape(json.dumps(status, indent=2)[:1600])}</pre></section>
    <section><h2>Task Board</h2><ul>{task_items}</ul></section>
    <section><h2>Findings</h2><ul>{finding_items}</ul></section>
    <section><h2>Structured Tool Runs</h2><ul>{tool_run_items}</ul></section>
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
    <p>Tools registered: {tool_count}. JSON endpoints: {api_links}. POST endpoints: <code>/message</code>, <code>/tool</code>, <code>/finding</code>, <code>/approve</code>, <code>/deny</code>, <code>/run-due</code>.</p>
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
