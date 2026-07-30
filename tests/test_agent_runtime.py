import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import unittest
from unittest import mock
import zipfile
from pathlib import Path

from offsec_agent_harness import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeDispatchResult, BridgeMessage, EngagementROE, OffSecAgentRuntime, bridge_doctor, chunk_text, discover_skills, handle_bridge_message, load_skill
from offsec_agent_harness.agent_bridges import DiscordGatewayBridge
from offsec_agent_harness.agent_crypto import seal_bytes, unseal_bytes
from offsec_agent_harness.model_adapters import BaseModelAdapter, ModelResponse


class FakePlannerAdapter(BaseModelAdapter):
    provider = "fake-planner"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model planned a safe memory write",
                    "tool_calls": [
                        {
                            "tool": "remember",
                            "args": {"key": "model-plan", "value": "model planner worked"},
                            "reason": "operator asked for durable local state",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class AgentRuntimeTests(unittest.TestCase):
    def make_runtime(self, tmp: str) -> tuple[OffSecAgentRuntime, Path]:
        tmp_path = Path(tmp)
        engagement = tmp_path / "engagement.json"
        EngagementROE(
            name="Runtime Test",
            authorized=True,
            in_scope_targets=["app.example.test", "10.10.0.0/24"],
            evidence_dir=str(tmp_path / "evidence"),
        ).save(engagement)
        runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(tmp_path / "agent.db"), session_name="unit"))
        return runtime, engagement

    def test_safety_preflight_reports_readiness_without_target_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            gateway = None
            try:
                preflight = runtime.registry.run("safety_preflight", {"out": "unit-preflight"})
                self.assertEqual(preflight.status, "ok", preflight.to_dict())
                self.assertEqual(preflight.data["readiness"], "ready")
                self.assertTrue(preflight.data["no_target_activity"])
                self.assertTrue(preflight.data["secret_values_redacted"])
                markdown_path = Path(preflight.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Safety Preflight", markdown)
                self.assertIn("Local SQLite/WAL/SHM remain plaintext", markdown)

                slash = runtime.handle_message("/preflight out=slash-preflight.md")
                self.assertIn("Safety preflight ready", slash)
                self.assertIn("safety_preflight", runtime.handle_message("/schemas name=safety_preflight"))

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/preflight", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["readiness"], "ready")
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

            unsafe_engagement = Path(tmp) / "unsafe-engagement.json"
            EngagementROE(
                name="Unsafe Readiness",
                authorized=False,
                in_scope_targets=["0.0.0.0/0"],
                prohibited_techniques=[],
                stop_conditions=[],
                evidence_dir=str(Path(tmp) / "unsafe-evidence"),
            ).save(unsafe_engagement)
            old_token = os.environ.get("PHOBOS_PREFLIGHT_TOKEN")
            os.environ["PHOBOS_PREFLIGHT_TOKEN"] = "token=supersecret"
            unsafe_runtime = OffSecAgentRuntime(AgentRuntimeConfig(
                engagement_path=str(unsafe_engagement),
                db_path=str(Path(tmp) / "unsafe-agent.db"),
                session_name="unsafe",
                auto_execute_natural=True,
                bridges={"discord": {"enabled": True, "token_env": "PHOBOS_PREFLIGHT_TOKEN", "allow_all": True, "allow_approval_actions": True, "ignore_bots": False}},
            ))
            try:
                unsafe = unsafe_runtime.registry.run("safety_preflight", {})
                self.assertEqual(unsafe.status, "ok", unsafe.to_dict())
                self.assertEqual(unsafe.data["readiness"], "blocked")
                statuses = {check["status"] for check in unsafe.data["checks"]}
                self.assertIn("fail", statuses)
                self.assertIn("warn", statuses)
                serialized = json.dumps(unsafe.to_dict()) + Path(unsafe.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertNotIn("supersecret", serialized)
            finally:
                unsafe_runtime.close()
                if old_token is None:
                    os.environ.pop("PHOBOS_PREFLIGHT_TOKEN", None)
                else:
                    os.environ["PHOBOS_PREFLIGHT_TOKEN"] = old_token

    def test_memory_assess_run_approval_jobs_and_subagents(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                remembered = runtime.handle_message('/remember key=client value="ACME test engagement" tags=engagement')
                self.assertIn("Stored memory", remembered)
                recalled = runtime.handle_message('/recall query=ACME')
                self.assertIn("ACME test engagement", recalled)

                assessed = runtime.handle_message('/assess target=app.example.test type=web purpose="headers" command="curl -I https://app.example.test"')
                self.assertIn("Guardrail decision: allow", assessed)

                executed = runtime.handle_message('/run target=app.example.test type=host purpose="local smoke" command="printf agent-ok" execute=true')
                self.assertIn("[executed]", executed)
                self.assertIn("agent-ok", executed)

                confirm = runtime.handle_message('/run target=app.example.test type=web purpose="controlled test update token=supersecret" command="curl -X POST https://app.example.test/profile token=supersecret" execute=true')
                self.assertIn("needs_approval", confirm)
                approvals = runtime.handle_message('/approvals')
                approval_detail = runtime.handle_message('/approval id=1')
                self.assertIn("controlled test update", approvals)
                self.assertIn("token=<REDACTED>", approvals)
                self.assertIn("token=<REDACTED>", approval_detail)
                self.assertNotIn("supersecret", approvals + approval_detail)
                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="other"))
                try:
                    cross_session = other_runtime.handle_message('/approval id=1')
                    cross_approve = other_runtime.handle_message('/approve id=1')
                    self.assertIn("not found in this session", cross_session)
                    self.assertIn("not found in this session", cross_approve)
                finally:
                    other_runtime.close()
                denied = runtime.handle_message('/deny id=1 reason="unit test"')
                self.assertIn("denied", denied)
                all_approvals = runtime.handle_message('/approvals status=all')
                self.assertIn("denied", all_approvals)
                self.assertNotIn("supersecret", all_approvals)

                job = runtime.handle_message('/job name=daily schedule=manual prompt="/recall query=ACME"')
                self.assertIn("Scheduled job", job)
                due = runtime.run_due_jobs()
                self.assertEqual(len(due), 1)
                self.assertIn("ACME", due[0]["response"])

                review = runtime.handle_message('/subagents prompt="Review controlled IDOR evidence" roles=scope,safety,report')
                self.assertIn("Subagent review complete", review)
            finally:
                runtime.close()

    def test_natural_language_fallback_records_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                response = runtime.handle_message("What is the safest next step for a controlled IDOR?")
                self.assertNotIn("Phobos Agent response", response)
                self.assertIn("pentest assistant", response)
                execution_request = runtime.handle_message("Run nmap against app.example.test")
                self.assertIn("I didn’t run anything", execution_request)
                messages = runtime.store.recent_messages(runtime.session_id, limit=10)
                self.assertEqual(messages[-1]["role"], "assistant")
            finally:
                runtime.close()

    def test_workspace_context_process_and_audit_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                written = runtime.handle_message('/write path=notes/finding.md content="client authz note"')
                self.assertIn("Wrote notes/finding.md", written)
                read = runtime.handle_message('/read path=notes/finding.md')
                self.assertIn("client authz note", read)
                searched = runtime.handle_message('/workspace-search query=authz glob="**/*.md"')
                self.assertIn("finding.md", searched)
                patched = runtime.handle_message('/patch-file path=notes/finding.md old=authz new=authorization')
                self.assertIn("Patched notes/finding.md", patched)

                compact = runtime.handle_message('/compact limit=20')
                self.assertIn("Context summary", compact)
                context = runtime.handle_message('/context limit=4')
                self.assertIn("Context snapshot", context)

                started = runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "background smoke",
                    "command": "printf bg-ok",
                    "execute": True,
                })
                self.assertEqual(started.status, "started", started.message)
                process_id = started.data["process_id"]
                for _ in range(20):
                    polled = runtime.registry.run("poll_process", {"id": process_id})
                    if polled.status in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(polled.status, "completed", polled.to_dict())
                log = runtime.registry.run("process_log", {"id": process_id})
                self.assertIn("bg-ok", log.data["stdout"])
                processes = runtime.handle_message('/processes')
                self.assertIn("background smoke", processes)
                audit = runtime.handle_message('/audit limit=20')
                self.assertIn("tool_call", audit)
            finally:
                runtime.close()

    def test_workspace_search_does_not_follow_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                outside = Path(tmp) / "outside-workspace-secret.txt"
                outside.write_text("outside-symlink-marker should stay outside workspace", encoding="utf-8")
                link = runtime.registry.workspace_root / "outside-link.txt"
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")

                searched = runtime.handle_message('/workspace-search query=outside-symlink-marker glob="**/*.txt"')
                self.assertIn("Found 0 matches", searched)
                self.assertNotIn("outside-symlink-marker should stay outside workspace", searched)

                read = runtime.handle_message('/read path=outside-link.txt')
                self.assertIn("escapes the engagement workspace", read)

                pack_source = Path(tmp) / "outside-pack-sentinel.txt"
                pack_source.write_text("OUTSIDE_PACK_LEAK_SENTINEL", encoding="utf-8")
                pack_link = runtime.registry.workspace_root / "pack-link.txt"
                pack_link.symlink_to(pack_source)
                pack = runtime.registry.run("export_pack", {"out": "symlink-pack.zip"})
                self.assertEqual(pack.status, "ok", pack.to_dict())
                with zipfile.ZipFile(pack.data["pack"]) as archive:
                    combined = "\n".join(
                        archive.read(name).decode("utf-8", errors="replace")
                        for name in archive.namelist()
                        if name.endswith((".json", ".md", ".txt"))
                    )
                    manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
                self.assertNotIn("OUTSIDE_PACK_LEAK_SENTINEL", combined)
                self.assertTrue(any(item.get("reason") == "symlink target outside evidence root" for item in manifest.get("skipped", [])))
            finally:
                runtime.close()

    def test_runtime_artifact_outputs_block_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            old_seal = os.environ.get("PHOBOS_TEST_ARTIFACT_SEAL")
            os.environ["PHOBOS_TEST_ARTIFACT_SEAL"] = "artifact containment passphrase"
            try:
                created = runtime.registry.run("create_finding", {"title": "Artifact containment finding", "severity": "Low"})
                self.assertEqual(created.status, "ok", created.to_dict())
                finding_id = created.data["finding"]["id"]

                good = runtime.registry.run("finding_review", {"id": finding_id, "out": "nested/review"})
                self.assertEqual(good.status, "ok", good.to_dict())
                good_path = Path(good.artifacts["markdown"]).resolve()
                findings_dir = (Path(runtime.registry.harness.store.root) / "agent" / "findings").resolve()
                self.assertEqual(os.path.commonpath([str(findings_dir), str(good_path)]), str(findings_dir))

                escape_cases = [
                    ("finding_review", {"id": finding_id, "out": str(Path(tmp) / "outside-review.md")}, Path(tmp) / "outside-review.md"),
                    ("operator_briefing", {"out": str(Path(tmp) / "outside-briefing.md")}, Path(tmp) / "outside-briefing.md"),
                    ("export_session", {"out": str(Path(tmp) / "outside-handoff.json")}, Path(tmp) / "outside-handoff.json"),
                    ("export_pack", {"out": str(Path(tmp) / "outside-pack.zip")}, Path(tmp) / "outside-pack.zip"),
                    ("sealed_export", {"passphrase_env": "PHOBOS_TEST_ARTIFACT_SEAL", "out": str(Path(tmp) / "outside-sealed.json")}, Path(tmp) / "outside-sealed.json"),
                    ("evidence_manifest", {"out": str(Path(tmp) / "outside-manifest.json")}, Path(tmp) / "outside-manifest.json"),
                    ("closeout_review", {"out": str(Path(tmp) / "outside-closeout.md")}, Path(tmp) / "outside-closeout.md"),
                ]
                for tool, args, outside_path in escape_cases:
                    blocked = runtime.registry.run(tool, args)
                    self.assertEqual(blocked.status, "error", blocked.to_dict())
                    self.assertIn("escapes", blocked.message)
                    self.assertFalse(outside_path.exists(), f"{tool} wrote outside artifact dir")

                symlink_target = Path(tmp) / "outside-symlink-write.md"
                symlink_target.write_text("ORIGINAL OUTSIDE CONTENT", encoding="utf-8")
                link = findings_dir / "symlink-review.md"
                try:
                    link.symlink_to(symlink_target)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")
                symlink_block = runtime.registry.run("finding_export", {"id": finding_id, "out": "symlink-review.md"})
                self.assertEqual(symlink_block.status, "error", symlink_block.to_dict())
                self.assertIn("escapes", symlink_block.message)
                self.assertEqual(symlink_target.read_text(encoding="utf-8"), "ORIGINAL OUTSIDE CONTENT")
            finally:
                runtime.close()
                if old_seal is None:
                    os.environ.pop("PHOBOS_TEST_ARTIFACT_SEAL", None)
                else:
                    os.environ["PHOBOS_TEST_ARTIFACT_SEAL"] = old_seal

    def test_evidence_timeline_tool_slash_and_gateway_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                runtime.handle_message('/task-add content="Review timeline evidence token=supersecret" status=pending')
                nmap_output = "Starting Nmap\nNmap scan report for 10.10.0.5\nPORT   STATE SERVICE VERSION\n80/tcp open  http    nginx 1.24\n"
                nmap = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80", "stdout": nmap_output})
                self.assertEqual(nmap.status, "parsed", nmap.to_dict())
                finding = runtime.registry.run("create_finding", {
                    "title": "Timeline finding token=supersecret",
                    "severity": "Low",
                    "status": "needs-evidence",
                    "tool_run_ids": str(nmap.data["run_id"]),
                })
                self.assertEqual(finding.status, "ok", finding.to_dict())
                media_src = Path(tmp) / "timeline-media.txt"
                media_src.write_text("timeline media token=supersecret", encoding="utf-8")
                media = runtime.registry.run("media_import", {"path": str(media_src)})
                self.assertEqual(media.status, "ok", media.to_dict())
                approval = runtime.registry.run("run_command", {
                    "target": "app.example.test",
                    "type": "web",
                    "purpose": "timeline confirm token=supersecret",
                    "command": "curl -X POST https://app.example.test/profile?token=supersecret",
                    "execute": True,
                })
                self.assertEqual(approval.status, "needs_approval", approval.to_dict())

                timeline = runtime.registry.run("evidence_timeline", {"include_audit": True, "limit": 100})
                self.assertEqual(timeline.status, "ok", timeline.to_dict())
                categories = {entry["category"] for entry in timeline.data["entries"]}
                self.assertTrue({"tool_run", "finding", "approval", "task", "media", "audit"}.issubset(categories), categories)
                serialized = json.dumps(timeline.to_dict())
                self.assertNotIn("supersecret", serialized)
                markdown_path = Path(timeline.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Evidence Timeline", markdown)
                self.assertIn("nmap_scan", markdown)
                self.assertNotIn("supersecret", markdown)

                slash = runtime.handle_message('/timeline limit=10 include_audit=false')
                self.assertIn("Evidence timeline assembled", slash)
                self.assertIn("markdown", slash)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/timeline?limit=50&include_audit=false", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                gateway_categories = {entry["category"] for entry in payload["data"]["entries"]}
                self.assertTrue({"tool_run", "finding", "approval", "task", "media"}.issubset(gateway_categories), gateway_categories)
                self.assertNotIn("supersecret", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_evidence_manifest_hashes_artifacts_without_content_or_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proof = evidence_root / "reports" / "manifest-proof-token=supersecret.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof_bytes = b"manifest proof body token=supersecret"
                proof.write_bytes(proof_bytes)
                outside = Path(tmp) / "outside-manifest-sentinel.txt"
                outside.write_text("OUTSIDE_MANIFEST_SENTINEL", encoding="utf-8")
                link = evidence_root / "agent" / "media" / "manifest-escape-link.txt"
                link.parent.mkdir(parents=True, exist_ok=True)
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")

                manifest = runtime.registry.run("evidence_manifest", {"out": "unit-manifest.json", "limit": 100})
                self.assertEqual(manifest.status, "ok", manifest.to_dict())
                self.assertTrue(manifest.data["no_target_activity"])
                self.assertTrue(manifest.data["secret_values_redacted"])
                expected_hash = hashlib.sha256(proof_bytes).hexdigest()
                self.assertTrue(any(entry.get("sha256") == expected_hash and entry.get("category") == "finding" for entry in manifest.data["entries"]), manifest.data["entries"])
                self.assertTrue(any(item.get("reason") == "symlink target outside evidence root" for item in manifest.data["skipped"]), manifest.data["skipped"])
                serialized = json.dumps(manifest.to_dict())
                self.assertNotIn("supersecret", serialized)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", serialized)
                json_path = Path(manifest.artifacts["json"])
                markdown_path = Path(manifest.artifacts["markdown"])
                self.assertTrue(json_path.exists())
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Evidence Manifest", markdown)
                self.assertIn(expected_hash, markdown)
                self.assertNotIn("supersecret", markdown)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", markdown)

                slash = runtime.handle_message('/manifest limit=10 out=slash-manifest.json')
                self.assertIn("Evidence manifest wrote", slash)
                self.assertIn("evidence_manifest", runtime.handle_message("/schemas name=evidence_manifest"))

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/manifest?limit=50&include_agent=false", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertFalse(payload["data"]["include_agent"])
                self.assertNotIn("supersecret", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_closeout_review_reports_ready_state_and_blocks_pending_approvals(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proof = evidence_root / "reports" / "closeout-request-response.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof.write_text("HTTP response proof token=supersecret; baseline negative control; read-only no state change.", encoding="utf-8")
                run_id = runtime.store.create_tool_run(
                    runtime.session_id,
                    "httpx_probe",
                    "https://app.example.test",
                    "httpx -json https://app.example.test",
                    "parsed",
                    parsed={"summary": {"http_services": 1}},
                    artifact_path=str(proof),
                )
                created = runtime.registry.run("create_finding", {
                    "title": "Closeout-ready exposed management route",
                    "severity": "Medium",
                    "status": "confirmed",
                    "description": "A scoped management route returned a replayable HTTP response, with baseline negative control evidence recorded.",
                    "impact": "A scoped attacker could target administrative workflows based on the observed exposure without needing unsafe validation.",
                    "recommendation": "Restrict management route access, require MFA, and monitor administrative access attempts.",
                    "tool_run_ids": str(run_id),
                    "evidence": "Read-only validation with no state change or cleanup required.",
                })
                self.assertEqual(created.status, "ok", created.to_dict())
                self.assertEqual(runtime.registry.run("evidence_timeline", {"out": "unit-timeline.md"}).status, "ok")
                self.assertEqual(runtime.registry.run("evidence_manifest", {"out": "unit-manifest.json"}).status, "ok")
                self.assertEqual(runtime.registry.run("export_pack", {"out": "unit-pack.zip"}).status, "ok")

                ready = runtime.registry.run("closeout_review", {"out": "unit-closeout.md"})
                self.assertEqual(ready.status, "ok", ready.to_dict())
                self.assertEqual(ready.data["readiness"], "ready", ready.to_dict())
                self.assertTrue(ready.data["no_target_activity"])
                markdown_path = Path(ready.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Closeout Review", markdown)
                self.assertIn("Local SQLite/WAL/SHM remain plaintext", markdown)
                self.assertNotIn("supersecret", json.dumps(ready.to_dict()) + markdown)
                self.assertIn("closeout_review", runtime.handle_message("/schemas name=closeout_review"))

                queued = runtime.registry.run("run_command", {
                    "target": "app.example.test",
                    "type": "web",
                    "purpose": "closeout pending approval token=supersecret",
                    "command": "printf curl -X POST https://app.example.test/profile token=supersecret",
                    "execute": True,
                })
                self.assertEqual(queued.status, "needs_approval", queued.to_dict())
                blocked = runtime.registry.run("closeout_review", {})
                self.assertEqual(blocked.status, "ok", blocked.to_dict())
                self.assertEqual(blocked.data["readiness"], "blocked")
                self.assertEqual(blocked.data["summary"]["pending_approvals"], 1)
                blocked_markdown = Path(blocked.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertNotIn("supersecret", json.dumps(blocked.to_dict()) + blocked_markdown)
                slash = runtime.handle_message('/closeout out=slash-closeout.md')
                self.assertIn("Closeout review blocked", slash)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/closeout", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["readiness"], "blocked")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertNotIn("supersecret", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_closeout_review_includes_redacted_local_drilldown_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                evidence_root = runtime.registry.harness.store.root
                proc_dir = evidence_root / "agent" / "processes"
                proc_dir.mkdir(parents=True, exist_ok=True)
                approval_id = runtime.store.create_approval(
                    runtime.session_id,
                    "run_command",
                    {"command": "curl -X POST https://app.example.test/profile token=supersecret", "purpose": "queued token=supersecret"},
                    {"status": "confirm", "reasons": ["state change token=supersecret"]},
                )
                task_id = runtime.store.create_task(runtime.session_id, "Resolve closeout evidence token=supersecret", status="in_progress")
                active_proc = runtime.store.create_process(
                    runtime.session_id,
                    "printf token=supersecret",
                    "app.example.test",
                    "host",
                    "active closeout process token=supersecret",
                    str(proc_dir / "active.out"),
                    str(proc_dir / "active.err"),
                    str(proc_dir / "active.rc"),
                    {"status": "allow"},
                )
                runtime.store.update_process(active_proc, pid=999999, status="running")
                failed_proc = runtime.store.create_process(
                    runtime.session_id,
                    "printf token=supersecret",
                    "app.example.test",
                    "host",
                    "failed closeout process token=supersecret",
                    str(proc_dir / "failed.out"),
                    str(proc_dir / "failed.err"),
                    str(proc_dir / "failed.rc"),
                    {"status": "allow"},
                )
                runtime.store.update_process(failed_proc, pid=999998, status="failed", exit_code=1, ended_at="2026-01-01T00:00:00+00:00")
                finding_id = runtime.store.create_finding(
                    runtime.session_id,
                    "Closeout gap finding token=supersecret",
                    severity="High",
                    status="confirmed",
                    description="too short",
                    impact="too short",
                    recommendation="too short",
                    evidence=[],
                )

                result = runtime.registry.run("closeout_review", {"out": "drilldown-closeout.md"})
                self.assertEqual(result.status, "ok", result.to_dict())
                self.assertEqual(result.data["readiness"], "blocked")
                checks = {check["name"]: check for check in result.data["checks"]}

                def refs(name: str) -> set[str]:
                    return {str(item.get("ref")) for item in checks[name].get("related", [])}

                self.assertIn(f"approval:{approval_id}", refs("pending_approvals"))
                self.assertIn(f"task:{task_id}", refs("open_tasks"))
                self.assertIn(f"process:{active_proc}", refs("background_processes"))
                self.assertIn(f"process:{failed_proc}", refs("failed_processes"))
                self.assertIn(f"finding:{finding_id}", refs("finding_readiness"))
                self.assertIn("artifact:agent/manifests/", refs("manifests"))
                self.assertIn("artifact:agent/timelines/", refs("timelines"))
                self.assertIn("artifact:agent/exports/", refs("exports"))
                self.assertGreaterEqual(result.data["summary"].get("drilldown_links", 0), 7)
                markdown = Path(result.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("## Drill-down", markdown)
                self.assertIn(f"approval:{approval_id}", markdown)
                serialized = json.dumps(result.to_dict()) + markdown
                self.assertNotIn("supersecret", serialized)
                self.assertNotIn("curl -X POST", serialized)
                self.assertTrue(result.data["no_target_activity"])
            finally:
                runtime.close()

    def test_lcm_context_reflect_cross_session_delegation_and_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 4)
                runtime.handle_message("LCM marker acme-lcm-node source context")
                compacted = runtime.handle_message('/lcm-compact title="LCM parity marker" limit=20 parent=true')
                self.assertIn("Context node", compacted)
                described = runtime.handle_message('/lcm-describe')
                self.assertIn("LCM parity marker", described)
                expanded = runtime.handle_message('/lcm-expand id=1')
                self.assertIn("acme-lcm-node", expanded)
                queried = runtime.handle_message('/reflect query=acme-lcm-node')
                self.assertIn("Context query answered", queried)
                retained = runtime.handle_message('/hindsight-retain content="ACME hindsight marker" context=unit tags=hindsight')
                self.assertIn("Retained Hindsight-style memory", retained)
                hindsight = runtime.handle_message('/hindsight-recall query=ACME')
                self.assertIn("ACME hindsight marker", hindsight)
                reflected = runtime.handle_message('/hindsight query=acme-lcm-node')
                self.assertIn("Context query answered", reflected)
                self.assertIn("lcm_compact", runtime.handle_message('/schemas name=lcm_compact'))

                delegated_result = runtime.registry.run("delegate_tasks", {"prompt": "review lcm parity evidence", "roles": "scope,safety"})
                self.assertEqual(delegated_result.status, "ok", delegated_result.to_dict())
                results = delegated_result.data["delegation"]["results"]
                self.assertEqual(len(results), 2)
                child_ids = {item["child_session_id"] for item in results}
                self.assertEqual(len(child_ids), 2)
                self.assertNotIn(runtime.session_id, child_ids)
                delegations = runtime.handle_message('/delegations')
                self.assertIn("review lcm parity evidence", delegations)
                sessions = runtime.store.list_sessions(limit=20)
                self.assertTrue(any(str(row["name"]).startswith("delegation-") for row in sessions))
                child_search = runtime.store.search_all_messages("review lcm parity evidence", limit=10)
                self.assertTrue(any(row.get("session_id") in child_ids for row in child_search))

                started = runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "wait process smoke",
                    "command": "printf wait-ok",
                    "execute": True,
                })
                waited = runtime.registry.run("wait_process", {"id": started.data["process_id"], "timeout": 5})
                self.assertEqual(waited.status, "completed", waited.to_dict())
                self.assertIn("wait-ok", waited.data["stdout"])
            finally:
                runtime.close()

            other = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="other"))
            try:
                other.handle_message("cross-session marker crosssession-acme")
            finally:
                other.close()
            runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="unit"))
            try:
                searched = runtime.handle_message('/search-all query=crosssession-acme')
                self.assertIn("crosssession-acme", searched)
            finally:
                runtime.close()

    def test_model_auto_loop_media_and_sealed_export_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                model_runtime = OffSecAgentRuntime(
                    AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "model-agent.db"), session_name="model", auto_model_planning=True),
                    adapter=FakePlannerAdapter(),
                )
                try:
                    planned = model_runtime.handle_message('/auto model=true prompt="remember a model planner marker"')
                    self.assertIn('"mode": "plan_only"', planned)
                    applied = model_runtime.handle_message('/auto apply=true model=true prompt="remember a model planner marker"')
                    self.assertIn('"tool": "remember"', applied)
                    looped = model_runtime.handle_message('/auto-loop model=true prompt="remember a model planner marker" steps=3')
                    self.assertIn("Auto loop completed", looped)
                    recalled = model_runtime.handle_message('/recall query=model-plan')
                    self.assertIn("model planner worked", recalled)
                finally:
                    model_runtime.close()

                media_src = Path(tmp) / "proof.txt"
                media_src.write_text("media marker token=supersecret", encoding="utf-8")
                media = runtime.registry.run("media_import", {"path": str(media_src)})
                self.assertEqual(media.status, "ok", media.to_dict())
                self.assertTrue(Path(media.artifacts["file"]).exists())
                media_list = runtime.registry.run("media_list", {})
                self.assertEqual(len(media_list.data["media"]), 1)

                missing = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_TEST_MISSING_PASSPHRASE"})
                self.assertEqual(missing.status, "error")
                os.environ["PHOBOS_TEST_SEAL"] = "correct horse battery staple"
                os.environ["PHOBOS_TEST_SEAL_WRONG"] = "wrong passphrase"
                runtime.handle_message('/remember key=sealed-client value="ACME token=supersecret" tags=sealed')
                node = runtime.handle_message('/lcm-compact title="sealed context" limit=40')
                self.assertIn("Context node", node)
                sealed = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_TEST_SEAL", "out": "unit.sealed.json"})
                self.assertEqual(sealed.status, "ok", sealed.to_dict())
                sealed_path = Path(sealed.data["path"])
                sealed_text = sealed_path.read_text(encoding="utf-8")
                self.assertIn("PHOBOS_SEALED_V1", sealed_text)
                self.assertNotIn("supersecret", sealed_text)
                wrong = runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_TEST_SEAL_WRONG"})
                self.assertEqual(wrong.status, "error")
            finally:
                runtime.close()
                os.environ.pop("PHOBOS_TEST_SEAL", None)
                os.environ.pop("PHOBOS_TEST_SEAL_WRONG", None)

            os.environ["PHOBOS_TEST_SEAL"] = "correct horse battery staple"
            imported_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "sealed-import.db"), session_name="sealed-import"))
            try:
                imported = imported_runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_TEST_SEAL"})
                self.assertEqual(imported.status, "ok", imported.to_dict())
                self.assertGreaterEqual(imported.data["imported_context_nodes"], 1)
                recalled = imported_runtime.handle_message('/recall query=sealed-client')
                self.assertIn("ACME", recalled)
            finally:
                imported_runtime.close()
                os.environ.pop("PHOBOS_TEST_SEAL", None)

            sealed_bytes = seal_bytes(b"sealed roundtrip", "passphrase", aad=b"unit")
            self.assertEqual(unseal_bytes(sealed_bytes, "passphrase", aad=b"unit"), b"sealed roundtrip")
            with self.assertRaises(ValueError):
                unseal_bytes(sealed_bytes, "wrong", aad=b"unit")
            tampered = sealed_bytes.replace(b"PHOBOS_SEALED_V1", b"PHOBOS_SEALED_VX", 1)
            with self.assertRaises(ValueError):
                unseal_bytes(tampered, "passphrase", aad=b"unit")

    def test_fts_auto_planner_workspace_escape_and_pack_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 2)
                status = runtime.handle_message('/status')
                self.assertIn('"fts_available"', status)
                self.assertIn('"safety_mode": "non_destructive"', status)

                runtime.handle_message("session polishmarkerfts searchable artifact")
                searched = runtime.handle_message('/search query=polishmarkerfts')
                self.assertIn("polishmarkerfts", searched)

                escaped = runtime.handle_message('/write path=../escape.txt content=nope')
                self.assertIn("escapes the engagement workspace", escaped)
                self.assertFalse((Path(tmp) / "escape.txt").exists())

                planned = runtime.handle_message('/auto prompt="remember planner-client: ACME polished engagement"')
                self.assertIn('"mode": "plan_only"', planned)
                applied = runtime.handle_message('/auto apply=true prompt="remember planner-client: ACME polished engagement"')
                self.assertIn('"tool": "remember"', applied)
                recalled = runtime.handle_message('/recall query=planner-client')
                self.assertIn("ACME polished engagement", recalled)

                auto_assess = runtime.handle_message('/auto apply=true prompt=\'assess target=10.10.0.5 type=service-enumeration purpose=version-scan command="nmap -sV 10.10.0.5"\'')
                self.assertIn('"tool": "assess_action"', auto_assess)
                self.assertIn('"status": "allow"', auto_assess)

                runtime.handle_message('/run target=app.example.test type=host purpose="secret redaction smoke" command="printf token=supersecret" execute=true')
                packed = runtime.registry.run("export_pack", {"out": "unit-pack.zip"})
                self.assertEqual(packed.status, "ok", packed.to_dict())
                pack_path = Path(packed.data["pack"])
                self.assertTrue(pack_path.exists())
                with zipfile.ZipFile(pack_path) as archive:
                    names = set(archive.namelist())
                    self.assertIn("PACK_README.md", names)
                    self.assertIn("MANIFEST.json", names)
                    self.assertIn("runtime/state.json", names)
                    combined = "\n".join(archive.read(name).decode("utf-8", errors="replace") for name in names if name.endswith(('.json', '.md', '.jsonl', '.log', '.txt')))
                self.assertNotIn("supersecret", combined)
            finally:
                runtime.close()

    def test_task_board_policy_briefing_and_session_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 3)
                added = runtime.handle_message('/task-add content="parity polish token=supersecret"')
                self.assertIn("Task 1 added", added)
                updated = runtime.handle_message('/task-update id=1 status=in_progress')
                self.assertIn('"status": "in_progress"', updated)
                tasks = runtime.handle_message('/tasks')
                self.assertIn("parity polish", tasks)

                runtime.handle_message('/remember key=handoff-client value="ACME token=supersecret" tags=handoff')
                runtime.handle_message("portable handoff context marker")
                compact = runtime.handle_message('/compact limit=20')
                self.assertIn("Context summary", compact)
                briefing = runtime.registry.run("operator_briefing", {"query": "handoff-client"})
                self.assertEqual(briefing.status, "ok", briefing.to_dict())
                briefing_path = Path(briefing.artifacts["markdown"])
                self.assertTrue(briefing_path.exists())
                briefing_text = briefing_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Agent Operator Briefing", briefing_text)
                self.assertNotIn("supersecret", briefing_text)

                exported = runtime.registry.run("export_session", {"out": "unit-handoff.json"})
                self.assertEqual(exported.status, "ok", exported.to_dict())
                handoff = Path(exported.data["path"])
                self.assertTrue(handoff.exists())
                exported_text = handoff.read_text(encoding="utf-8")
                self.assertIn("phobos-agent-session-handoff", exported_text)
                self.assertNotIn("supersecret", exported_text)
            finally:
                runtime.close()

            imported_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent-import.db"), session_name="imported"))
            try:
                imported = imported_runtime.registry.run("import_session", {"path": str(handoff)})
                self.assertEqual(imported.status, "ok", imported.to_dict())
                recalled = imported_runtime.handle_message('/recall query=handoff-client')
                self.assertIn("imported:", recalled)
                imported_tasks = imported_runtime.handle_message('/tasks')
                self.assertIn("Imported from", imported_tasks)
            finally:
                imported_runtime.close()

    def test_runtime_tool_policy_confirm_and_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Policy Runtime Test",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            runtime = OffSecAgentRuntime(AgentRuntimeConfig(
                engagement_path=str(engagement),
                db_path=str(tmp_path / "agent.db"),
                session_name="policy",
                confirm_tools=("workspace_write",),
                blocked_tools=("export_pack",),
            ))
            try:
                pending = runtime.registry.run("workspace_write", {"path": "notes/policy.md", "content": "policy-ok"})
                self.assertEqual(pending.status, "needs_approval", pending.to_dict())
                self.assertFalse((runtime.registry.workspace_root / "notes" / "policy.md").exists())
                approved = runtime.registry.run("approve", {"id": pending.data["approval_id"]})
                self.assertEqual(approved.status, "ok", approved.to_dict())
                self.assertTrue((runtime.registry.workspace_root / "notes" / "policy.md").exists())
                blocked = runtime.registry.run("export_pack", {})
                self.assertEqual(blocked.status, "blocked", blocked.to_dict())
                status = runtime.registry.run("runtime_status", {})
                self.assertIn("export_pack", status.data["policy"]["blocked_tools"])
            finally:
                runtime.close()

    def test_local_skills_progressive_loading_and_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime, engagement = self.make_runtime(tmp)
            runtime.close()
            skills_dir = tmp_path / "skills"
            skill_dir = skills_dir / "demo-skill"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: demo-skill\n"
                "description: Demo local skill for progressive disclosure.\n"
                "triggers:\n"
                "  - demo trigger\n"
                "---\n"
                "# Demo Skill\n\n"
                "Step 1: keep scope and evidence first.\n",
                encoding="utf-8",
            )
            discovered = discover_skills([str(skills_dir)])
            self.assertIn("demo-skill", discovered)
            self.assertNotIn("Step 1", discovered["demo-skill"].to_dict().get("description", ""))
            loaded_direct = load_skill("demo-skill", [str(skills_dir)])
            self.assertIn("Step 1", loaded_direct.content)

            cfg_path = tmp_path / "agent.config.json"
            AgentAppConfig(
                workspace_dir=str(tmp_path / "workspace"),
                skill_dirs=[str(skills_dir)],
                preload_skills=["demo-skill"],
                skill_bundles={"demo": ["demo-skill"]},
            ).save(cfg_path)
            cfg = AgentAppConfig.load(cfg_path)
            self.assertEqual(cfg.skill_dirs, [str(skills_dir)])
            runtime = OffSecAgentRuntime(cfg.to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "skills"))
            try:
                self.assertIn("demo-skill", runtime.loaded_skills)
                skills = runtime.handle_message("/skills")
                self.assertIn("Demo local skill", skills)
                self.assertNotIn("Step 1: keep scope", skills)
                shown = runtime.handle_message("/skill name=demo-skill")
                self.assertIn("Step 1: keep scope", shown)
                runtime.loaded_skills.clear()
                dynamic = runtime.handle_message("/demo-skill")
                self.assertIn("Loaded skill demo-skill", dynamic)
                runtime.loaded_skills.clear()
                bundle = runtime.handle_message("/skill bundle=demo")
                self.assertIn('"demo-skill"', bundle)
                escaped = runtime.handle_message("/skill name=../demo-skill")
                self.assertIn("Skill load failed", escaped)
            finally:
                runtime.close()

    def test_structured_wrappers_findings_and_remote_gateway_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            old_token = os.environ.get("PHOBOS_GATEWAY_TEST_TOKEN")
            os.environ["PHOBOS_GATEWAY_TEST_TOKEN"] = "unit-token"
            try:
                nmap_output = """Starting Nmap
Nmap scan report for 10.10.0.5
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.24
443/tcp open  https   nginx 1.24
"""
                nmap = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80,443", "stdout": nmap_output})
                self.assertEqual(nmap.status, "parsed", nmap.to_dict())
                self.assertEqual(nmap.data["parsed"]["summary"]["open_ports"], 2)
                self.assertTrue(Path(nmap.data["artifact_path"]).exists())
                nmap_run_id = nmap.data["run_id"]

                httpx = runtime.registry.run("httpx_probe", {"url": "https://app.example.test", "stdout": json.dumps({"url": "https://app.example.test", "status_code": 200, "title": "ACME Portal", "tech": ["nginx"]})})
                self.assertEqual(httpx.status, "parsed", httpx.to_dict())
                self.assertEqual(httpx.data["parsed"]["responses"][0]["status_code"], 200)

                nuclei_line = json.dumps({"template-id": "exposed-panel", "info": {"name": "Exposed Panel", "severity": "medium"}, "matched-at": "https://app.example.test/admin"})
                nuclei = runtime.registry.run("nuclei_scan", {"url": "https://app.example.test", "stdout": nuclei_line})
                self.assertEqual(nuclei.status, "parsed", nuclei.to_dict())
                self.assertEqual(nuclei.data["parsed"]["summary"]["count"], 1)

                ffuf_output = json.dumps({"results": [{"url": "https://app.example.test/admin", "status": 200, "length": 1234, "words": 12, "lines": 5}]})
                ffuf = runtime.registry.run("ffuf_scan", {"url": "https://app.example.test/FUZZ", "wordlist": "words.txt", "stdout": ffuf_output})
                self.assertEqual(ffuf.status, "parsed", ffuf.to_dict())
                self.assertEqual(ffuf.data["parsed"]["summary"]["count"], 1)

                runs = runtime.registry.run("list_tool_runs", {})
                self.assertGreaterEqual(len(runs.data["runs"]), 4)
                self.assertIn("nmap_scan", runtime.handle_message('/schemas name=nmap_scan'))
                self.assertIn("Structured tool run", runtime.handle_message(f'/tool-run id={nmap_run_id}'))

                created = runtime.registry.run("create_finding", {
                    "title": "Exposed administrative interface",
                    "severity": "Medium",
                    "status": "needs-evidence",
                    "description": "An administrative interface was exposed during safe enumeration.",
                    "impact": "Attackers could target administrative authentication workflows.",
                    "recommendation": "Restrict access to trusted management networks and require MFA.",
                    "tool_run_ids": str(nmap_run_id),
                    "tags": "web,exposure",
                })
                self.assertEqual(created.status, "ok", created.to_dict())
                finding_id = created.data["finding"]["id"]
                updated = runtime.registry.run("update_finding", {"id": finding_id, "status": "confirmed", "evidence": "Gateway screenshot captured", "append_evidence": True})
                self.assertEqual(updated.data["finding"]["status"], "confirmed")
                exported = runtime.registry.run("finding_export", {"id": finding_id})
                self.assertEqual(exported.status, "ok", exported.to_dict())
                markdown = Path(exported.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Exposed administrative interface", markdown)
                self.assertIn("Tool run", markdown)
                reviewed = runtime.registry.run("finding_review", {"id": finding_id})
                self.assertEqual(reviewed.status, "ok", reviewed.to_dict())
                self.assertEqual(reviewed.data["review"]["readiness"], "ready_with_advisories")
                self.assertFalse(reviewed.data["review"]["blocking_gaps"])
                review_markdown = Path(reviewed.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Phobos Finding Review", review_markdown)
                self.assertIn("Negative control", review_markdown)
                self.assertNotIn("supersecret", review_markdown)
                weak = runtime.registry.run("create_finding", {"title": "Version-only candidate", "severity": "High"})
                weak_review = runtime.registry.run("finding_review", {"id": weak.data["finding"]["id"]})
                self.assertEqual(weak_review.status, "ok", weak_review.to_dict())
                self.assertEqual(weak_review.data["review"]["readiness"], "needs_evidence")
                self.assertTrue(weak_review.data["review"]["blocking_gaps"])
                self.assertIn("finding_review", runtime.handle_message('/schemas name=finding_review'))
                self.assertIn("Finding #", runtime.handle_message(f'/finding-review id={finding_id}'))
                listed = runtime.handle_message('/findings status=all')
                self.assertIn("Exposed administrative interface", listed)
                status = runtime.registry.run("runtime_status", {}).data
                self.assertGreaterEqual(status["schema"]["schema_version"], 5)
                self.assertGreaterEqual(status["tool_runs"], 4)
                self.assertGreaterEqual(status["findings"], 1)

                with self.assertRaises(ValueError):
                    AgentGateway(runtime, host="0.0.0.0", port=0)
                gateway = AgentGateway(runtime, port=0, token_env="PHOBOS_GATEWAY_TEST_TOKEN", allow_origins=("*",))
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
                    health = json.loads(response.read().decode("utf-8"))
                self.assertTrue(health["auth_required"])
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5)
                self.assertEqual(raised.exception.code, 401)
                authed = urllib.request.Request(f"http://{host}:{port}/status", headers={"Authorization": "Bearer unit-token", "Origin": "https://ui.example"})
                with urllib.request.urlopen(authed, timeout=5) as response:
                    remote_status = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")
                self.assertEqual(remote_status["status"], "ok")
                with urllib.request.urlopen(f"http://{host}:{port}/ui-client", timeout=5) as response:
                    ui_html = response.read().decode("utf-8")
                self.assertIn("Phobos Agent Remote Client", ui_html)
                finding_req = urllib.request.Request(
                    f"http://{host}:{port}/finding",
                    data=json.dumps({"title": "Remote-created finding", "severity": "Low"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer unit-token"},
                    method="POST",
                )
                with urllib.request.urlopen(finding_req, timeout=5) as response:
                    remote_finding = json.loads(response.read().decode("utf-8"))
                self.assertEqual(remote_finding["result"]["status"], "ok")
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()
                if old_token is None:
                    os.environ.pop("PHOBOS_GATEWAY_TEST_TOKEN", None)
                else:
                    os.environ["PHOBOS_GATEWAY_TEST_TOKEN"] = old_token

    def test_bridge_allowlists_prefix_mentions_and_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                config = BridgeConfig(
                    platform="discord",
                    allowed_channel_ids=("C1",),
                    allowed_user_ids=("U1",),
                    command_prefix="!phobos",
                    max_response_chars=240,
                )
                wrong_channel = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C2", user_id="U1"),
                    config,
                )
                self.assertEqual(wrong_channel.status, "ignored")
                self.assertEqual(wrong_channel.reason, "channel-not-allowed")

                missing_prefix = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/status", channel_id="C1", user_id="U1"),
                    config,
                )
                self.assertEqual(missing_prefix.status, "ignored")
                self.assertEqual(missing_prefix.reason, "prefix-required")

                handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", message_id="M1"),
                    config,
                )
                self.assertEqual(handled.status, "handled", handled.to_dict())
                self.assertEqual(handled.normalized_text, "/status")
                self.assertIn("Phobos is up", handled.response)
                self.assertIn("Safety: `non_destructive`", handled.response)
                self.assertNotIn('"session_id"', handled.response)
                self.assertIn('"safety_mode": "non_destructive"', handled.raw_response)
                self.assertTrue(handled.chunks)
                self.assertTrue(all(len(chunk) <= 240 for chunk in handled.chunks))

                raw_config = BridgeConfig.from_dict("discord", {"allowed_channel_ids": ["C1"], "allowed_user_ids": ["U1"], "command_prefix": "!phobos", "response_polish": False})
                raw_handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", message_id="M1-raw"),
                    raw_config,
                )
                self.assertIn('"safety_mode": "non_destructive"', raw_handled.response)
                self.assertEqual(raw_handled.response, raw_handled.raw_response)

                voice_note = Path(tmp) / "bridge-voice.ogg"
                voice_note.write_bytes(b"OggS voice-note token=supersecret")
                attachment_handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(
                        platform="discord",
                        text="!phobos /media-list",
                        channel_id="C1",
                        user_id="U1",
                        message_id="M-media",
                        attachments=[{"local_path": str(voice_note), "mime_type": "audio/ogg", "kind": "audio", "name": "voice.ogg"}],
                    ),
                    config,
                )
                self.assertEqual(attachment_handled.status, "handled", attachment_handled.to_dict())
                self.assertEqual(attachment_handled.attachments[0]["status"], "ok")
                self.assertEqual(attachment_handled.attachments[0]["kind"], "audio")
                self.assertIn("audio", runtime.handle_message("/media-list"))

                attachment_only = handle_bridge_message(
                    runtime,
                    BridgeMessage(
                        platform="telegram",
                        text="",
                        channel_id="PRIVATE1",
                        user_id="U3",
                        is_private=True,
                        attachments=[{"url": "https://example.invalid/evidence.png", "mime_type": "image/png", "size": 123}],
                    ),
                    BridgeConfig(platform="telegram"),
                )
                self.assertEqual(attachment_only.status, "handled")
                self.assertEqual(attachment_only.reason, "attachments")
                self.assertEqual(attachment_only.attachments[0]["status"], "metadata-recorded")

                ignored_bot = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", is_bot=True),
                    config,
                )
                self.assertEqual(ignored_bot.reason, "bot-message")

                user_only_public = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C-anywhere", user_id="U1"),
                    BridgeConfig(platform="discord", allowed_user_ids=("U1",), command_prefix="!phobos"),
                )
                self.assertEqual(user_only_public.status, "ignored")
                self.assertEqual(user_only_public.reason, "channel-allowlist-required")

                approval_blocked = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /approve id=1", channel_id="C1", user_id="U1"),
                    config,
                )
                self.assertEqual(approval_blocked.status, "blocked")
                self.assertEqual(approval_blocked.reason, "approval-action-disabled")

                approval_allowed = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /approve id=999999", channel_id="C1", user_id="U1"),
                    BridgeConfig(platform="discord", allowed_channel_ids=("C1",), allowed_user_ids=("U1",), command_prefix="!phobos", allow_approval_actions=True),
                )
                self.assertEqual(approval_allowed.status, "handled")
                self.assertIn("not found", approval_allowed.response)

                mention_config = BridgeConfig(platform="discord", allowed_channel_ids=("C1",), mention_required=True)
                no_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(no_mention.reason, "mention-required")
                mentioned = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="<@BOT1> /tools", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(mentioned.status, "handled")
                self.assertIn("Phobos tools are registered", mentioned.response)
                self.assertIn("/schemas name=<tool>", mentioned.response)

                inline_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="hey <@BOT1> /status", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(inline_mention.status, "handled")
                self.assertEqual(inline_mention.reason, "mentioned")
                self.assertEqual(inline_mention.normalized_text, "/status")
                self.assertIn("Phobos is up", inline_mention.response)
                self.assertIn('"safety_mode": "non_destructive"', inline_mention.raw_response)

                literal_alias = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="@phobos /status", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(literal_alias.status, "handled")
                self.assertEqual(literal_alias.reason, "mentioned")
                self.assertEqual(literal_alias.normalized_text, "/status")
                self.assertIn("Phobos is up", literal_alias.response)
                self.assertIn('"safety_mode": "non_destructive"', literal_alias.raw_response)

                trailing_alias = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools @Phobos", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(trailing_alias.status, "handled")
                self.assertEqual(trailing_alias.normalized_text, "/tools")
                self.assertIn("Phobos tools are registered", trailing_alias.response)

                trailing_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools <@BOT1>", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(trailing_mention.status, "handled")
                self.assertEqual(trailing_mention.normalized_text, "/tools")
                self.assertIn("Phobos tools are registered", trailing_mention.response)

                thread_config = BridgeConfig.from_dict(
                    "discord",
                    {"allowed_channel_ids": ["C1"], "command_prefix": "!phobos", "discord_thread_mode": "per-message"},
                )
                parent_message = BridgeMessage(platform="discord", text="@phobos /status", channel_id="C1", user_id="U1", message_id="M1", raw={"channel_type": 0})
                parent_result = handle_bridge_message(runtime, parent_message, thread_config, bot_user_id="BOT1")
                self.assertEqual(parent_result.status, "handled")
                bridge = DiscordGatewayBridge.__new__(DiscordGatewayBridge)
                bridge.runtime = runtime
                bridge.config = thread_config
                created_threads = []

                def fake_create_thread(channel_id, message_id, name):
                    created_threads.append((channel_id, message_id, name))
                    return "T1"

                bridge.create_thread_from_message = fake_create_thread
                self.assertEqual(bridge.response_channel_id(parent_message, parent_result), "T1")
                self.assertEqual(created_threads[0][0], "C1")
                self.assertEqual(created_threads[0][1], "M1")
                self.assertTrue(created_threads[0][2].startswith("Phobos - status"))

                thread_message = BridgeMessage(
                    platform="discord",
                    text="/status",
                    channel_id="T1",
                    user_id="U1",
                    message_id="M2",
                    raw={"channel_type": 11, "parent_id": "C1"},
                )
                thread_result = handle_bridge_message(runtime, thread_message, thread_config, bot_user_id="BOT1")
                self.assertEqual(thread_result.status, "handled")
                self.assertEqual(thread_result.normalized_text, "/status")
                self.assertEqual(bridge.response_channel_id(thread_message, BridgeDispatchResult("handled", normalized_text="/status")), "T1")

                private_message = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="telegram", text="/status", channel_id="PRIVATE1", user_id="U3", is_private=True),
                    BridgeConfig(platform="telegram"),
                )
                self.assertEqual(private_message.status, "handled")

                chunks = chunk_text("word " * 120, 200)
                self.assertGreater(len(chunks), 1)
                self.assertTrue(all(len(chunk) <= 200 for chunk in chunks))
                neutralized = "\n".join(chunk_text("@everyone @here <!channel> " + ("word " * 120), 200))
                self.assertNotIn("@everyone", neutralized)
                self.assertNotIn("@here", neutralized)
                self.assertNotIn("<!channel>", neutralized)
                self.assertIn("@\u200beveryone", neutralized)
            finally:
                runtime.close()

    def test_plugin_config_and_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime, engagement = self.make_runtime(tmp)
            runtime.close()
            plugin_dir = tmp_path / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "echo_plugin.py").write_text(
                "from offsec_agent_harness.agent_tools import ToolResult\n"
                "def register(registry):\n"
                "    def echo(args):\n"
                "        return ToolResult('ok', 'plugin echo', {'echo': args.get('value', '')})\n"
                "    registry.register_tool('plugin_echo', echo, {'description': 'Echo from a local plugin.', 'schema': {'type': 'object', 'properties': {'value': {'type': 'string'}}}})\n",
                encoding="utf-8",
            )
            cfg_path = tmp_path / "agent.config.json"
            AgentAppConfig(workspace_dir=str(tmp_path / "workspace"), plugin_dirs=[str(plugin_dir)]).save(cfg_path)
            cfg = AgentAppConfig.load(cfg_path).to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "unit", config_path=str(cfg_path))
            runtime = OffSecAgentRuntime(cfg)
            gateway = None
            try:
                self.assertIn("plugin_echo", runtime.handle_message('/tools'))
                plugin_result = runtime.handle_message('/tool name=plugin_echo value=hello')
                self.assertIn('"echo": "hello"', plugin_result)
                schema = runtime.handle_message('/schemas name=plugin_echo')
                self.assertIn("Echo from a local plugin", schema)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
                    health = json.loads(response.read().decode("utf-8"))
                self.assertTrue(health["ok"])
                with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
                    dashboard = response.read().decode("utf-8")
                self.assertIn("Phobos Agent Gateway", dashboard)
                self.assertIn("Granular Guardrails", dashboard)
                with urllib.request.urlopen(f"http://{host}:{port}/guardrails", timeout=5) as response:
                    guardrails = json.loads(response.read().decode("utf-8"))
                self.assertEqual(guardrails["engagement"]["safety_mode"], "non_destructive")
                self.assertTrue(any(tool["name"] == "nmap_scan" for tool in guardrails["tools"]))
                policy_req = urllib.request.Request(
                    f"http://{host}:{port}/guardrails",
                    data=json.dumps({
                        "safety_mode": "standard",
                        "testing_window": "business hours with client lead online",
                        "notes": "UI test note: tighten only, no secrets.",
                        "in_scope_targets": ["app.example.test", "10.10.0.0/24"],
                        "allowed_techniques": ["web", "service-enumeration", "offline-analysis"],
                        "prohibited_techniques": ["dos", "destructive", "persistence", "evasion", "malware", "credential-dumping"],
                        "stop_conditions": ["Stop before customer data access.", "Stop before production changes."],
                        "confirm_tools": ["nmap_scan"],
                        "blocked_tools": ["export_pack"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(policy_req, timeout=5) as response:
                    updated_policy = json.loads(response.read().decode("utf-8"))
                self.assertEqual(updated_policy["status"], "updated")
                self.assertIn("engagement.safety_mode", updated_policy["changed"])
                self.assertTrue(updated_policy["persisted"]["engagement"])
                self.assertTrue(updated_policy["persisted"]["runtime_policy"])
                persisted_roe = EngagementROE.load(engagement)
                self.assertEqual(persisted_roe.safety_mode, "standard")
                self.assertEqual(persisted_roe.testing_window, "business hours with client lead online")
                self.assertIn("tighten only", persisted_roe.notes)
                bad_req = urllib.request.Request(
                    f"http://{host}:{port}/guardrails",
                    data=json.dumps({"unknown_field": True}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_exc:
                    urllib.request.urlopen(bad_req, timeout=5)
                self.assertEqual(bad_exc.exception.code, 400)
                self.assertIn("unknown guardrail policy fields", bad_exc.exception.read().decode("utf-8"))
                persisted_cfg = AgentAppConfig.load(cfg_path)
                self.assertIn("nmap_scan", persisted_cfg.confirm_tools)
                self.assertIn("export_pack", persisted_cfg.blocked_tools)
                active_scan_confirm = runtime.handle_message('/assess target=app.example.test type=service-enumeration purpose="tight client" command="nmap -sV app.example.test"')
                self.assertIn("Guardrail decision: confirm", active_scan_confirm)
                policy_confirm = runtime.registry.run("nmap_scan", {"target": "app.example.test", "stdout": "80/tcp open http nginx"})
                self.assertEqual(policy_confirm.status, "needs_approval", policy_confirm.to_dict())
                policy_block = runtime.registry.run("export_pack", {})
                self.assertEqual(policy_block.status, "blocked", policy_block.to_dict())
                with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5) as response:
                    gateway_status = json.loads(response.read().decode("utf-8"))
                self.assertEqual(gateway_status["status"], "ok")

                runtime.registry.run("schedule_job", {"name": "gateway-job", "prompt": "/status", "schedule": "manual"})
                media_src = tmp_path / "gateway-proof.txt"
                media_src.write_text("gateway media marker", encoding="utf-8")
                runtime.registry.run("media_import", {"path": str(media_src)})
                runtime.registry.run("delegate_tasks", {"prompt": "gateway delegation marker", "roles": "scope"})
                process = runtime.registry.run("start_process", {"target": "app.example.test", "type": "host", "purpose": "gateway route process", "command": "printf gateway-process", "execute": True})
                runtime.registry.run("wait_process", {"id": process.data["process_id"], "timeout": 5})

                for route, marker in [
                    ("/routes", "/schemas"),
                    ("/schemas?name=start_process", "start_process"),
                    ("/jobs", "gateway-job"),
                    ("/processes", "gateway route process"),
                    ("/timeline?include_audit=false", "gateway route process"),
                    ("/delegations", "gateway delegation marker"),
                    ("/media", "gateway-proof"),
                    ("/auth", "secret_values_redacted"),
                    ("/bridges", "discord"),
                    ("/guardrails", "standard"),
                    ("/lcm", "nodes"),
                ]:
                    with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                        routed = response.read().decode("utf-8")
                    self.assertIn(marker, routed, route)

                approval = runtime.registry.run("run_command", {"target": "app.example.test", "type": "web", "purpose": "gateway deny approval", "command": "curl -X POST https://app.example.test/api", "execute": True})
                self.assertEqual(approval.status, "needs_approval", approval.to_dict())
                deny_req = urllib.request.Request(
                    f"http://{host}:{port}/deny",
                    data=json.dumps({"id": approval.data["approval_id"], "by": "unit", "reason": "gateway-test"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(deny_req, timeout=5) as response:
                    deny_data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(deny_data["result"]["status"], "denied")
                req = urllib.request.Request(
                    f"http://{host}:{port}/message",
                    data=json.dumps({"message": "/schemas name=plugin_echo"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode("utf-8"))
                self.assertIn("plugin_echo", data["response"])
                tool_req = urllib.request.Request(
                    f"http://{host}:{port}/tool",
                    data=json.dumps({"name": "plugin_echo", "args": {"value": "via-gateway"}}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(tool_req, timeout=5) as response:
                    tool_data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(tool_data["result"]["data"]["echo"], "via-gateway")
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()



    def test_bridge_doctor_sanitizes_live_auth_checks(self):
        import offsec_agent_harness.agent_bridges as bridges

        def fake_http_json(method, url, *, payload=None, headers=None, timeout=30.0):
            self.assertTrue(headers or url.startswith("https://api.telegram.org"))
            if "discord.com/api/v10/users/@me" in url:
                return {"id": "D-BOT", "username": "phobos"}
            if "discord.com/api/v10/gateway/bot" in url:
                return {"url": "wss://gateway.example", "session_start_limit": {"remaining": 100}}
            if "slack.com/api/auth.test" in url:
                return {"ok": True, "team_id": "T1", "user_id": "U-BOT"}
            if "slack.com/api/apps.connections.open" in url:
                return {"ok": True, "url": "wss://socket-mode-secret.example"}
            if "api.telegram.org" in url:
                return {"ok": True, "result": {"id": 42, "username": "phobos_bot"}}
            raise AssertionError(url)

        env = {
            "PHOBOS_DISCORD_TOKEN": "discord-secret",
            "PHOBOS_SLACK_BOT_TOKEN": "slack-bot-secret",
            "PHOBOS_SLACK_APP_TOKEN": "slack-app-secret",
            "PHOBOS_TELEGRAM_TOKEN": "telegram-secret",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(bridges, "_http_json", fake_http_json):
            result = bridge_doctor(["discord", "slack", "telegram"])
        self.assertTrue(result["ok"])
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("socket-mode-secret", serialized)
        self.assertTrue(all(item["message_sending"] is False for item in result["checks"]))

class AgentCliTests(unittest.TestCase):
    def test_phobos_agent_cli_once_and_tools(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            init_engagement = subprocess.run([
                sys.executable, "-m", "phobos_agent.cli", "init",
                "--name", "Agent CLI", "--scope", "app.example.test", "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init_engagement.returncode, 0, init_engagement.stderr)
            init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "init", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init.returncode, 0, init.stderr)
            data = json.loads(init.stdout)
            self.assertIn("session_id", data)

            tools = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "tools", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(tools.returncode, 0, tools.stderr)
            self.assertIn("run_command", tools.stdout)

            schema = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "schema", "--engagement", str(engagement), "--name", "runtime_status",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(schema.returncode, 0, schema.stderr)
            self.assertIn("runtime_status", schema.stdout)

            status = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "status", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("schema_version", status.stdout)

            evidence_manifest = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "evidence-manifest", "--engagement", str(engagement), "--out", "cli-manifest.json",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(evidence_manifest.returncode, 0, evidence_manifest.stderr)
            manifest_json = json.loads(evidence_manifest.stdout)
            self.assertEqual(manifest_json["status"], "ok")
            self.assertTrue(Path(manifest_json["artifacts"]["json"]).exists())
            self.assertTrue(Path(manifest_json["artifacts"]["markdown"]).exists())

            closeout = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "closeout", "--engagement", str(engagement), "--out", "cli-closeout.md",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(closeout.returncode, 0, closeout.stderr)
            closeout_json = json.loads(closeout.stdout)
            self.assertEqual(closeout_json["status"], "ok")
            self.assertTrue(closeout_json["data"]["no_target_activity"])
            self.assertTrue(Path(closeout_json["artifacts"]["markdown"]).exists())
            self.assertIn(closeout_json["data"]["readiness"], {"ready", "review", "blocked"})

            ui_client = tmp_path / "phobos-remote-ui.html"
            ui = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "ui-client", "--out", str(ui_client), "--agent-url", "https://agent.example.test",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(ui.returncode, 0, ui.stderr)
            self.assertTrue(ui_client.exists())
            self.assertIn("Phobos Agent Remote Client", ui_client.read_text(encoding="utf-8"))
            self.assertIn("https://agent.example.test", ui_client.read_text(encoding="utf-8"))

            deploy_dir = tmp_path / "deploy-kit"
            deploy = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "deploy-kit", "--out", str(deploy_dir), "--domain", "phobos.example.test", "--allow-origin", "https://ui.example.test",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(deploy.returncode, 0, deploy.stderr)
            deploy_json = json.loads(deploy.stdout)
            self.assertFalse(deploy_json["token_value_written"])
            self.assertTrue((deploy_dir / "phobos-agent.service").exists())
            self.assertTrue((deploy_dir / "nginx-phobos-agent.conf").exists())
            deploy_text = "\n".join(path.read_text(encoding="utf-8") for path in deploy_dir.iterdir() if path.is_file())
            self.assertIn("--token-env PHOBOS_GATEWAY_TOKEN", deploy_text)
            self.assertIn("127.0.0.1", deploy_text)
            self.assertIn("phobos.example.test", deploy_text)
            self.assertNotIn("use-a-long-random-secret", deploy_text)

            auth_env = dict(env)
            auth_env["PHOBOS_DISCORD_TOKEN"] = "discord-secret-value"
            auth = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "auth-status", "--engagement", str(engagement),
            ], cwd=project, env=auth_env, text=True, capture_output=True)
            self.assertEqual(auth.returncode, 0, auth.stderr)
            self.assertIn("secret_values_redacted", auth.stdout)
            self.assertNotIn("discord-secret-value", auth.stdout)

            bridge = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"),
                "bridge-test", "--engagement", str(engagement), "--platform", "discord",
                "--allow-channel", "C1", "--allow-user", "U1", "--prefix", "!phobos",
                "--channel-id", "C1", "--user-id", "U1", "--message", "!phobos /status",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(bridge.returncode, 0, bridge.stderr)
            bridge_json = json.loads(bridge.stdout)
            self.assertEqual(bridge_json["result"]["status"], "handled")
            self.assertEqual(bridge_json["result"]["normalized_text"], "/status")

            once = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", '/assess target=app.example.test type=web purpose=headers command="curl -I https://app.example.test"',
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(once.returncode, 0, once.stderr)
            self.assertIn("Guardrail decision: allow", once.stdout)

            marker = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", '/remember key=db-at-rest value="DB_AT_REST_SECRET_MARKER"',
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(marker.returncode, 0, marker.stderr)
            sealed_env = dict(env)
            sealed_env["PHOBOS_TEST_DB_SEAL"] = "correct-passphrase"
            sealed = tmp_path / "agent.db.sealed"
            sealed_run = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "seal-db", "--out", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL", "--remove-plaintext",
            ], cwd=project, env=sealed_env, text=True, capture_output=True)
            self.assertEqual(sealed_run.returncode, 0, sealed_run.stderr)
            sealed_json = json.loads(sealed_run.stdout)
            self.assertEqual(sealed_json["status"], "sealed")
            self.assertFalse((tmp_path / "agent.db").exists())
            self.assertNotIn(b"DB_AT_REST_SECRET_MARKER", sealed.read_bytes())

            wrong_env = dict(env)
            wrong_env["PHOBOS_TEST_DB_SEAL_WRONG"] = "wrong-passphrase"
            wrong = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "wrong.db"), "unseal-db", "--in", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL_WRONG", "--overwrite",
            ], cwd=project, env=wrong_env, text=True, capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)

            unsealed = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "unseal-db", "--in", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL", "--overwrite",
            ], cwd=project, env=sealed_env, text=True, capture_output=True)
            self.assertEqual(unsealed.returncode, 0, unsealed.stderr)
            recalled = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", "/recall query=db-at-rest",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(recalled.returncode, 0, recalled.stderr)
            self.assertIn("DB_AT_REST_SECRET_MARKER", recalled.stdout)

    def test_phobos_agent_profiles_cli(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env["HOME"] = str(tmp_path)
            profile_init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "caligo",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(profile_init.returncode, 0, profile_init.stderr)
            profile_json = json.loads(profile_init.stdout)
            self.assertEqual(profile_json["profile"], "caligo")
            self.assertTrue(Path(profile_json["config"]).exists())

            profiles = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profiles",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(profiles.returncode, 0, profiles.stderr)
            self.assertIn("caligo", profiles.stdout)

            engagement = tmp_path / "engagement.json"
            init_engagement = subprocess.run([
                sys.executable, "-m", "phobos_agent.cli", "init",
                "--name", "Profile CLI", "--scope", "app.example.test", "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init_engagement.returncode, 0, init_engagement.stderr)

            init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--profile", "caligo", "init", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init.returncode, 0, init.stderr)
            init_json = json.loads(init.stdout)
            self.assertIn(".phobos/profiles/caligo/phobos-agent.db", init_json["db"])
            self.assertTrue((tmp_path / ".phobos" / "profiles" / "caligo" / "phobos-agent.db").exists())

            bad = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "../bad",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)

    def test_phobos_agent_config_init_cli(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "agent.config.json"
            completed = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "config-init", "--out", str(out),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(out.exists())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["providers"][0]["provider"], "heuristic")
            self.assertFalse(data["auto_execute_natural"])
            self.assertFalse(data["auto_model_planning"])
            self.assertEqual(data["max_auto_steps"], 5)
            self.assertEqual(data["blocked_tools"], [])
            self.assertEqual(data["confirm_tools"], [])
            self.assertEqual(data["skill_dirs"], [])
            self.assertEqual(data["preload_skills"], [])
            self.assertEqual(data["skill_bundles"], {})
            self.assertIn("discord", data["bridges"])
            self.assertIn("slack", data["bridges"])
            self.assertIn("telegram", data["bridges"])
            self.assertEqual(data["bridges"]["discord"]["token_env"], "PHOBOS_DISCORD_TOKEN")
            self.assertFalse(data["bridges"]["discord"]["enabled"])
            self.assertFalse(data["bridges"]["discord"]["allow_approval_actions"])


if __name__ == "__main__":
    unittest.main()
