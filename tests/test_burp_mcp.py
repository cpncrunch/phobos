import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from offsec_agent_harness.burp_mcp import BurpMCPClient, HTTPRequestArtifact, write_burp_artifacts


class _Handler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode())
        self.__class__.calls.append(payload)
        method = payload.get("method")
        if method == "initialize":
            result = {"serverInfo": {"name": "fake-burp-mcp"}}
        elif method == "create_repeater_tab":
            params = payload.get("params", {})
            result = {"tab": params.get("name") or params.get("tab_name"), "created": True}
        else:
            self._send({"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601, "message": "not found"}})
            return
        self._send({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})

    def _send(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class BurpMCPTests(unittest.TestCase):
    def setUp(self):
        _Handler.calls = []
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/mcp"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def test_probe_create_tab_and_artifacts(self):
        raw = "GET /admin HTTP/1.1\r\nHost: app.example.test\r\nAuthorization: Bearer abc.def\r\n\r\n"
        artifact = HTTPRequestArtifact.parse(raw)
        self.assertEqual(artifact.method, "GET")
        self.assertEqual(artifact.host, "app.example.test")
        client = BurpMCPClient(self.url)
        self.assertTrue(client.probe()["ok"])
        created = client.create_repeater_tab("IDOR proof", artifact)
        self.assertTrue(created["ok"])
        self.assertEqual(created["result"]["tab"], "IDOR proof")
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_burp_artifacts(Path(tmp), "IDOR proof", artifact, created)
            self.assertTrue(Path(paths["raw_request"]).exists())
            redacted = Path(paths["redacted_request"]).read_text()
            self.assertNotIn("abc.def", redacted)
            self.assertIn("<REDACTED>", redacted)
