from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import re
import urllib.error
import urllib.request

from .models import redact_secrets


class JSONRPCError(RuntimeError):
    def __init__(self, code: int | None, message: str, data: Any = None):
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass(slots=True)
class HTTPRequestArtifact:
    raw: str
    method: str = "UNKNOWN"
    path: str = "/"
    host: str = ""
    headers: dict[str, str] | None = None
    body: str = ""

    @classmethod
    def parse(cls, raw: str) -> "HTTPRequestArtifact":
        normalized = raw.replace("\r\n", "\n")
        head, _, body = normalized.partition("\n\n")
        lines = [line for line in head.split("\n") if line]
        method = "UNKNOWN"
        path = "/"
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                method, path = parts[0].upper(), parts[1]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        host = headers.get("Host", headers.get("host", ""))
        return cls(raw=raw, method=method, path=path, host=host, headers=headers, body=body)

    @classmethod
    def load(cls, path: str | Path) -> "HTTPRequestArtifact":
        return cls.parse(Path(path).read_text(encoding="utf-8"))

    def redacted_raw(self) -> str:
        return redact_secrets(self.raw) or ""

    def summary(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "header_count": len(self.headers or {}),
            "body_bytes": len(self.body.encode("utf-8")),
        }


class BurpMCPClient:
    """Small JSON-RPC client for Burp MCP style endpoints."""

    def __init__(self, url: str, host_header: str | None = None, timeout: float = 10.0):
        self.url = url
        self.host_header = host_header
        self.timeout = timeout
        self._counter = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._counter += 1
        payload = {"jsonrpc": "2.0", "id": self._counter, "method": method, "params": params or {}}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.host_header:
            headers["Host"] = self.host_header
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ConnectionError(f"Burp MCP HTTP {exc.code}: {body[:500]}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Burp MCP connection failed: {exc.reason}") from exc
        parsed = json.loads(text) if text.strip() else {}
        if isinstance(parsed, dict) and parsed.get("error"):
            err = parsed["error"]
            raise JSONRPCError(err.get("code"), err.get("message", "unknown error"), err.get("data"))
        if isinstance(parsed, dict) and "result" in parsed:
            return parsed["result"]
        return parsed

    def probe(self) -> dict[str, Any]:
        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "phobos-agent", "version": "0.1.0"},
        }
        try:
            return {"ok": True, "method": "initialize", "result": self.call("initialize", params)}
        except JSONRPCError as exc:
            if exc.code == -32601:
                return {"ok": True, "method": "tools/list", "result": self.call("tools/list", {})}
            raise

    def create_repeater_tab(self, name: str, request: HTTPRequestArtifact | str) -> dict[str, Any]:
        raw = request.raw if isinstance(request, HTTPRequestArtifact) else request
        attempts = [
            ("create_repeater_tab", {"name": name, "request": raw}),
            ("create_repeater_tab", {"tab_name": name, "raw_request": raw}),
            ("create_repeater_tab_from_raw_http_request", {"name": name, "raw_request": raw}),
            ("tools/call", {"name": "create_repeater_tab", "arguments": {"name": name, "request": raw}}),
        ]
        errors: list[str] = []
        for method, params in attempts:
            try:
                return {"ok": True, "method": method, "result": self.call(method, params)}
            except JSONRPCError as exc:
                errors.append(str(exc))
                if exc.code != -32601:
                    raise
        raise JSONRPCError(-32601, "No supported Burp Repeater tab creation method found", errors)


def write_burp_artifacts(root: Path, tab_name: str, request: HTTPRequestArtifact, result: dict[str, Any] | None = None) -> dict[str, str]:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", tab_name.strip()).strip("-").lower() or "burp-request"
    out_dir = root / "burp"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"{safe}.http"
    redacted_path = out_dir / f"{safe}.redacted.http"
    meta_path = out_dir / f"{safe}.json"
    raw_path.write_text(request.raw, encoding="utf-8")
    redacted_path.write_text(request.redacted_raw(), encoding="utf-8")
    meta = {"tab_name": tab_name, "request": request.summary(), "mcp_result": result or {}}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return {"raw_request": str(raw_path), "redacted_request": str(redacted_path), "metadata": str(meta_path)}
