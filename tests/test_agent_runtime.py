import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import unittest
import zipfile
from pathlib import Path

from offsec_agent_harness import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeMessage, EngagementROE, OffSecAgentRuntime, chunk_text, discover_skills, handle_bridge_message, load_skill


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

                confirm = runtime.handle_message('/run target=app.example.test type=web purpose="controlled test update" command="curl -X POST https://app.example.test/profile" execute=true')
                self.assertIn("needs_approval", confirm)
                approvals = runtime.handle_message('/approvals')
                self.assertIn("controlled test update", approvals)
                denied = runtime.handle_message('/deny id=1 reason="unit test"')
                self.assertIn("denied", denied)

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
                self.assertIn("Phobos Agent response", response)
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
                added = runtime.handle_message('/task-add content="clone polish token=supersecret"')
                self.assertIn("Task 1 added", added)
                updated = runtime.handle_message('/task-update id=1 status=in_progress')
                self.assertIn('"status": "in_progress"', updated)
                tasks = runtime.handle_message('/tasks')
                self.assertIn("clone polish", tasks)

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
                self.assertIn('"safety_mode": "non_destructive"', handled.response)
                self.assertTrue(handled.chunks)
                self.assertTrue(all(len(chunk) <= 240 for chunk in handled.chunks))

                ignored_bot = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", is_bot=True),
                    config,
                )
                self.assertEqual(ignored_bot.reason, "bot-message")

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
                self.assertIn("Available tools", mentioned.response)

                private_message = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="telegram", text="/status", channel_id="PRIVATE1", user_id="U3", is_private=True),
                    BridgeConfig(platform="telegram"),
                )
                self.assertEqual(private_message.status, "handled")

                chunks = chunk_text("word " * 120, 200)
                self.assertGreater(len(chunks), 1)
                self.assertTrue(all(len(chunk) <= 200 for chunk in chunks))
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
            cfg = AgentAppConfig.load(cfg_path).to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "unit")
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
                with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5) as response:
                    gateway_status = json.loads(response.read().decode("utf-8"))
                self.assertEqual(gateway_status["status"], "ok")
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


if __name__ == "__main__":
    unittest.main()
