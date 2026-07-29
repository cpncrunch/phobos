#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phobos_agent import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeMessage, EngagementROE, PhobosAgentRuntime, handle_bridge_message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a harmless local Hermes-clone parity smoke test for phobos-agent.")
    parser.add_argument("--out-root", default="demo-phobos-parity", help="Output directory to recreate under the repository root.")
    args = parser.parse_args(argv)

    root = Path(args.out_root)
    if not root.is_absolute():
        root = REPO / root
    output = root / "output"
    data = root / "data"
    evidence = root / "evidence"
    workspace = root / "workspace"
    skill_root = root / "skills"
    config_path = root / "agent.config.json"
    engagement_path = root / "phobos-parity.engagement.json"
    db_path = data / "phobos-agent.db"

    shutil.rmtree(root, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    skill_dir = skill_root / "smoke-skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: smoke-skill\n"
        "description: Smoke skill for local progressive disclosure.\n"
        "triggers:\n"
        "  - smoke parity\n"
        "---\n"
        "# Smoke Skill\n\n"
        "Use this only as local smoke context; keep ROE and evidence first.\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    checks: dict[str, object] = {}

    def write(name: str, text: str) -> None:
        (output / name).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")

    def run_cmd(name: str, cmd: list[str]) -> str:
        completed = subprocess.run(cmd, cwd=REPO, env=env, text=True, capture_output=True, check=False)
        write(name + ".stdout.txt", completed.stdout)
        write(name + ".stderr.txt", completed.stderr)
        write(name + ".command.txt", "$ " + " ".join(cmd) + f"\nexit={completed.returncode}\n")
        if completed.returncode != 0:
            raise RuntimeError(f"{name} failed with exit {completed.returncode}: {completed.stderr or completed.stdout}")
        return completed.stdout

    run_cmd(
        "engagement-init",
        [
            sys.executable,
            "-m",
            "phobos_agent.cli",
            "init",
            "--name",
            "Phobos Agent Parity Smoke",
            "--scope",
            "app.example.test,10.10.0.0/24",
            "--allowed",
            "web,api,host,service-enumeration,offline-analysis",
            "--prohibited",
            "dos,destructive,persistence,evasion,malware",
            "--safety-mode",
            "non_destructive",
            "--evidence-dir",
            str(evidence),
            "--out",
            str(engagement_path),
        ],
    )
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    checks["default_non_destructive"] = engagement.get("safety_mode") == "non_destructive"

    run_cmd("config-init", [sys.executable, "-m", "phobos_agent.agent_cli", "config-init", "--out", str(config_path)])
    cfg = AgentAppConfig.load(config_path)
    cfg.workspace_dir = str(workspace)
    cfg.plugin_dirs = [str(REPO / "examples" / "plugins")]
    cfg.skill_dirs = [str(skill_root)]
    cfg.preload_skills = ["smoke-skill"]
    cfg.skill_bundles = {"smoke": ["smoke-skill"]}
    cfg.save(config_path)
    checks["config_written"] = config_path.exists() and cfg.auto_execute_natural is False

    init_stdout = run_cmd(
        "agent-init",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "init", "--engagement", str(engagement_path)],
    )
    init_json = json.loads(init_stdout)
    checks["agent_init_ok"] = bool(init_json.get("session_id")) and init_json["runtime"]["skill_dirs"] == [str(skill_root)]

    runtime = PhobosAgentRuntime(AgentAppConfig.load(config_path).to_runtime_config(str(engagement_path), str(db_path), "smoke"))
    gateway = None
    try:
        def handle(name: str, message: str) -> str:
            response = runtime.handle_message(message)
            write(name + ".txt", response)
            return response

        tools = handle("tools", "/tools")
        checks["tools_include_core_plugin_and_new_parity"] = all(
            token in tools
            for token in [
                "runtime_status",
                "workspace_write",
                "start_process",
                "operator_briefing",
                "export_session",
                "import_session",
                "add_task",
                "example_echo",
            ]
        )
        status = handle("status", "/status")
        checks["schema_version_ok"] = '"schema_version": 3' in status and '"fts_available"' in status
        skill_list = handle("skills", "/skills")
        skill_load = handle("skill-load", "/skill name=smoke-skill")
        checks["local_skills_ok"] = "Smoke skill for local progressive" in skill_list and "ROE and evidence first" in skill_load
        schema = handle("schema-start-process", "/schemas name=start_process")
        checks["schema_returned"] = "start_process" in schema and "execute" in schema
        plugin = handle("plugin-echo", "/tool name=example_echo value=plugin-ok")
        checks["plugin_loaded_and_executed"] = '"echo": "plugin-ok"' in plugin

        auto_plan = handle("auto-plan", '/auto prompt="remember smoke-client: ACME parity"')
        auto_apply = handle("auto-apply", '/auto apply=true prompt="remember smoke-client: ACME parity"')
        recall = handle("auto-recall", "/recall query=smoke-client")
        checks["auto_memory_recall"] = '"mode": "plan_only"' in auto_plan and '"tool": "remember"' in auto_apply and "ACME parity" in recall

        handle("workspace-write", '/write path=notes/scope.md content="Scope app.example.test authz note"')
        read_back = handle("workspace-read", "/read path=notes/scope.md")
        search = handle("workspace-search", '/workspace-search query=authz glob="**/*.md"')
        patch = handle("workspace-patch", '/patch-file path=notes/scope.md old=authz new=authorization')
        escape = handle("workspace-escape", "/write path=../escape.txt content=nope")
        checks["workspace_roundtrip_and_escape_block"] = "authz note" in read_back and "scope.md" in search and "Patched notes/scope.md" in patch and "escapes the engagement workspace" in escape

        assess = handle("active-scan-assess", '/assess target=10.10.0.5 type=service-enumeration purpose=version-scan command="nmap -sV 10.10.0.5"')
        run = handle("safe-run", '/run target=app.example.test type=host purpose="safe local smoke" command="printf parity-ok" execute=true')
        secret_run = handle("secret-run", '/run target=app.example.test type=host purpose="redaction smoke" command="printf token=supersecret" execute=true')
        state_change = handle("state-change-confirm", '/run target=app.example.test type=web purpose="controlled update" command="printf curl -X POST https://app.example.test/profile" execute=true')
        approvals = handle("approvals", "/approvals")
        destructive = handle("destructive-block", '/run target=app.example.test type=host purpose=blocked command="printf rm -rf /" execute=true')
        dos = handle("dos-block", '/run target=app.example.test type=web purpose=blocked command="printf hping3 --flood app.example.test" execute=true')
        checks["guardrails_execution_approvals_blocks"] = (
            "Guardrail decision: allow" in assess
            and "parity-ok" in run
            and "token=<REDACTED>" in secret_run
            and "needs_approval" in state_change
            and "controlled update" in approvals
            and "blocked" in destructive.lower()
            and "blocked" in dos.lower()
        )

        started = runtime.registry.run(
            "start_process",
            {"target": "app.example.test", "type": "host", "purpose": "background parity smoke", "command": "printf bg-parity-ok", "execute": True},
        )
        write("process-start.json", json.dumps(started.to_dict(), indent=2))
        process_id = int(started.data["process_id"])
        polled = runtime.registry.run("poll_process", {"id": process_id})
        for _ in range(40):
            polled = runtime.registry.run("poll_process", {"id": process_id})
            if polled.status in {"completed", "failed"}:
                break
            time.sleep(0.05)
        log = runtime.registry.run("process_log", {"id": process_id})
        write("process-poll.json", json.dumps(polled.to_dict(), indent=2))
        write("process-log.json", json.dumps(log.to_dict(), indent=2))
        checks["background_process_completed"] = polled.status == "completed" and "bg-parity-ok" in log.data.get("stdout", "")

        job = handle("job", '/job name=memory-check schedule=manual prompt="/recall query=smoke-client"')
        due = runtime.run_due_jobs()
        write("run-due.json", json.dumps(due, indent=2))
        review = handle("subagents", '/subagents prompt="Review controlled IDOR evidence" roles=scope,safety,report')
        checks["jobs_and_subagents"] = "Scheduled job" in job and due and "ACME parity" in due[0]["response"] and "Subagent review complete" in review

        add_task = handle("task-add", '/task-add content="Review parity smoke token=supersecret" status=pending')
        update_task = handle("task-update", "/task-update id=1 status=completed")
        task_list = handle("tasks", "/tasks status=all")
        auto_task = handle("auto-task", '/auto apply=true prompt="task: verify handoff import"')
        checks["task_board_roundtrip"] = "Task 1 added" in add_task and '"status": "completed"' in update_task and "Review parity smoke" in task_list and '"tool": "add_task"' in auto_task

        compact = handle("compact", "/compact limit=80")
        context = handle("context", "/context query=smoke-client limit=8")
        checks["context_compacted"] = "Context summary" in compact and "Context snapshot" in context
        briefing = runtime.registry.run("operator_briefing", {"query": "smoke-client"})
        write("operator-briefing.json", json.dumps(briefing.to_dict(), indent=2))
        briefing_path = Path(briefing.artifacts.get("markdown", ""))
        checks["operator_briefing_created"] = briefing.status == "ok" and briefing_path.exists() and "supersecret" not in briefing_path.read_text(encoding="utf-8")

        exported = runtime.registry.run("export_session", {"out": "session-handoff.json"})
        write("session-export.json", json.dumps(exported.to_dict(), indent=2))
        handoff_path = Path(exported.data["path"])
        imported_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(data / "imported-agent.db"), session_name="imported"))
        try:
            imported = imported_runtime.registry.run("import_session", {"path": str(handoff_path), "merge_memories": False})
            write("session-import.json", json.dumps(imported.to_dict(), indent=2))
            imported_tasks = imported_runtime.registry.run("list_tasks", {"status": "all"})
            imported_recall = imported_runtime.handle_message("/recall query=smoke-client")
            checks["session_export_import_roundtrip"] = (
                exported.status == "ok"
                and handoff_path.exists()
                and "supersecret" not in handoff_path.read_text(encoding="utf-8")
                and imported.status == "ok"
                and bool(imported_tasks.data.get("tasks"))
                and "ACME parity" in imported_recall
            )
        finally:
            imported_runtime.close()

        policy_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "policy-agent.db"),
                session_name="policy",
                confirm_tools=("operator_briefing",),
                blocked_tools=("export_pack",),
            )
        )
        try:
            policy_confirm = policy_runtime.registry.run("operator_briefing", {})
            policy_approved = policy_runtime.registry.run("approve", {"id": policy_confirm.data.get("approval_id")}) if policy_confirm.data.get("approval_id") else policy_confirm
            policy_block = policy_runtime.registry.run("export_pack", {})
            write("policy-confirm.json", json.dumps(policy_confirm.to_dict(), indent=2))
            write("policy-approved.json", json.dumps(policy_approved.to_dict(), indent=2))
            write("policy-block.json", json.dumps(policy_block.to_dict(), indent=2))
            checks["tool_policy_confirm_and_block"] = policy_confirm.status == "needs_approval" and policy_approved.status == "ok" and policy_block.status == "blocked"
        finally:
            policy_runtime.close()

        discord_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="!phobos /status", channel_id="C-smoke", user_id="U-smoke", message_id="M-smoke"),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        slack_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="slack", text="<@B-smoke> /tasks status=all", channel_id="C-smoke", user_id="U-smoke", message_id="1660000000.000100"),
            BridgeConfig(platform="slack", allowed_channel_ids=("C-smoke",), mention_required=True, max_response_chars=300),
            bot_user_id="B-smoke",
        )
        telegram_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="telegram", text="/status", channel_id="private-smoke", user_id="U-smoke", message_id="42", is_private=True),
            BridgeConfig(platform="telegram", max_response_chars=300),
        )
        bridge_approval_block = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="!phobos /approve id=1", channel_id="C-smoke", user_id="U-smoke", message_id="M-approve"),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        write("bridge-discord.json", json.dumps(discord_bridge.to_dict(), indent=2))
        write("bridge-slack.json", json.dumps(slack_bridge.to_dict(), indent=2))
        write("bridge-telegram.json", json.dumps(telegram_bridge.to_dict(), indent=2))
        write("bridge-approval-block.json", json.dumps(bridge_approval_block.to_dict(), indent=2))
        checks["bridges_offline_ok"] = (
            discord_bridge.status == "handled"
            and discord_bridge.normalized_text == "/status"
            and slack_bridge.status == "handled"
            and slack_bridge.normalized_text == "/tasks status=all"
            and telegram_bridge.status == "handled"
            and bridge_approval_block.status == "blocked"
            and bridge_approval_block.reason == "approval-action-disabled"
        )

        gateway = AgentGateway(runtime, port=0)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        host, port = gateway.server_address
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
            dashboard = response.read().decode("utf-8")
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
            health = json.loads(response.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5) as response:
            gateway_status = json.loads(response.read().decode("utf-8"))
        tool_req = urllib.request.Request(
            f"http://{host}:{port}/tool",
            data=json.dumps({"name": "example_echo", "args": {"value": "via-gateway"}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(tool_req, timeout=5) as response:
            gateway_tool = json.loads(response.read().decode("utf-8"))
        write("gateway-dashboard.html", dashboard)
        write("gateway-health.json", json.dumps(health, indent=2))
        write("gateway-status.json", json.dumps(gateway_status, indent=2))
        write("gateway-tool.json", json.dumps(gateway_tool, indent=2))
        checks["gateway_ok"] = "Phobos Agent Gateway" in dashboard and health.get("ok") is True and gateway_status.get("status") == "ok" and gateway_tool["result"]["data"]["echo"] == "via-gateway"

        pack = runtime.registry.run("export_pack", {"out": "closeout-pack.zip"})
        write("pack-export.json", json.dumps(pack.to_dict(), indent=2))
        pack_path = Path(pack.data["pack"])
        with zipfile.ZipFile(pack_path) as archive:
            names = set(archive.namelist())
            combined = "\n".join(
                archive.read(name).decode("utf-8", errors="replace")
                for name in names
                if name.endswith((".json", ".md", ".txt", ".log", ".jsonl", ".html"))
            )
        checks["pack_exported_and_redacted"] = pack.status == "ok" and "MANIFEST.json" in names and "runtime/state.json" in names and "supersecret" not in combined
        checks["db_exists"] = db_path.exists()
        checks["artifact_count"] = len([path for path in root.rglob("*") if path.is_file()])
        checks["pack"] = str(pack_path)
    finally:
        if gateway is not None:
            gateway.shutdown()
        runtime.close()

    summary_lines = ["PHOBOS AGENT PARITY SMOKE SUMMARY"]
    for key, value in checks.items():
        summary_lines.append(f"{key}={value}")
    summary = "\n".join(summary_lines) + "\n"
    write("smoke-summary.txt", summary)
    print(summary, end="")

    failed = [key for key, value in checks.items() if isinstance(value, bool) and not value]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
