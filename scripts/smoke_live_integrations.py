#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phobos_agent import AgentRuntimeConfig, EngagementROE, PhobosAgentRuntime, bridge_doctor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run live-but-safe Phobos integration checks against local targets and platform auth endpoints.")
    parser.add_argument("--out-root", default="demo-phobos-live", help="Output directory to recreate under repo root.")
    parser.add_argument("--require-bridge-tokens", action="store_true", help="Fail if bridge auth checks are missing/error instead of recording readiness.")
    parser.add_argument("--require-scanners", action="store_true", help="Fail if nmap/httpx/nuclei/ffuf binaries are missing or execution does not complete.")
    args = parser.parse_args(argv)

    root = Path(args.out_root)
    if not root.is_absolute():
        root = REPO / root
    if root.exists():
        shutil.rmtree(root)
    output = root / "output"
    evidence = root / "evidence"
    data = root / "data"
    webroot = root / "webroot"
    output.mkdir(parents=True)
    data.mkdir(parents=True)
    webroot.mkdir(parents=True)
    (webroot / "index.html").write_text("<html><title>Phobos live smoke</title><body>ok</body></html>\n", encoding="utf-8")
    (webroot / "admin").write_text("admin marker\n", encoding="utf-8")
    (root / "wordlist.txt").write_text("admin\nmissing\n", encoding="utf-8")
    safe_nuclei_template = root / "phobos-safe-template.yaml"
    safe_nuclei_template.write_text(
        "id: phobos-live-smoke\n"
        "info:\n"
        "  name: Phobos Live Smoke Safe Template\n"
        "  author: phobos\n"
        "  severity: info\n"
        "http:\n"
        "  - method: GET\n"
        "    path:\n"
        "      - '{{BaseURL}}/'\n"
        "    matchers:\n"
        "      - type: word\n"
        "        words:\n"
        "          - 'Phobos live smoke'\n",
        encoding="utf-8",
    )

    checks: dict[str, object] = {}

    def write(name: str, value: object) -> None:
        if isinstance(value, str):
            text = value
        else:
            text = json.dumps(value, indent=2, sort_keys=True)
        (output / name).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")

    doctor = bridge_doctor(["discord", "slack", "telegram"], timeout=15.0)
    write("bridge-doctor.json", doctor)
    checks["bridge_doctor_ran"] = bool(doctor.get("checks"))
    checks["live_bridge_auth_ready"] = "ready" if doctor.get("ok") else "missing-or-error"
    checks["live_bridge_no_message_send"] = doctor.get("message_sending") is False and all(item.get("message_sending") is False for item in doctor.get("checks", []))

    binaries = {name: shutil.which(name) for name in ["nmap", "httpx", "nuclei", "ffuf"]}
    write("scanner-binaries.json", binaries)
    checks["scanner_binaries_present"] = all(binaries.values()) or not args.require_scanners

    class QuietHandler(SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(webroot), **kw)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    engagement = root / "engagement.json"
    EngagementROE(
        name="Phobos Live Integrations",
        authorized=True,
        in_scope_targets=["127.0.0.1", f"127.0.0.1:{port}", f"http://127.0.0.1:{port}"],
        allowed_techniques=["web", "host", "service-enumeration", "content-discovery", "vulnerability-scan"],
        prohibited_techniques=["dos", "destructive", "persistence", "evasion", "malware"],
        safety_mode="non_destructive",
        evidence_dir=str(evidence),
    ).save(engagement)
    runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(data / "phobos-live.db"), session_name="live"))
    try:
        scanner_results: dict[str, dict[str, object]] = {}
        if binaries.get("nmap"):
            result = runtime.registry.run("nmap_scan", {"target": "127.0.0.1", "ports": str(port), "profile": "safe", "execute": True, "timeout": 30})
            scanner_results["nmap"] = result.to_dict()
        if binaries.get("httpx"):
            result = runtime.registry.run("httpx_probe", {"url": f"http://127.0.0.1:{port}", "execute": True, "timeout": 30})
            scanner_results["httpx"] = result.to_dict()
        if binaries.get("nuclei"):
            result = runtime.registry.run("nuclei_scan", {"url": f"http://127.0.0.1:{port}", "templates": str(safe_nuclei_template), "execute": True, "timeout": 30, "rate_limit": 1})
            scanner_results["nuclei"] = result.to_dict()
        if binaries.get("ffuf"):
            result = runtime.registry.run("ffuf_scan", {"url": f"http://127.0.0.1:{port}/FUZZ", "wordlist": str(root / "wordlist.txt"), "execute": True, "timeout": 30, "rate": 5})
            scanner_results["ffuf"] = result.to_dict()
        write("scanner-results.json", scanner_results)
        expected = [name for name, path in binaries.items() if path]
        checks["scanner_wrapper_live_execution_ok"] = all(scanner_results.get(name, {}).get("status") == "executed" for name in expected) and (bool(expected) or not args.require_scanners)
        checks["scanner_wrapper_live_artifacts_ok"] = all(scanner_results.get(name, {}).get("artifacts", {}).get("tool_run") for name in expected) and (bool(expected) or not args.require_scanners)
        status = runtime.registry.run("runtime_status", {}).to_dict()
        write("runtime-status.json", status)
        checks["safety_posture_preserved"] = status.get("data", {}).get("engagement", {}).get("safety_mode") == "non_destructive"
    finally:
        runtime.close()
        server.shutdown()

    summary = "PHOBOS LIVE INTEGRATION SMOKE SUMMARY\n" + "\n".join(f"{k}={v}" for k, v in checks.items()) + "\n"
    write("live-summary.txt", summary)
    print(summary, end="")
    failed = [key for key, value in checks.items() if isinstance(value, bool) and not value]
    if args.require_bridge_tokens and checks.get("live_bridge_auth_ready") != "ready":
        failed.append("live_bridge_auth_ready")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
