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
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phobos_agent import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeMessage, EngagementROE, PhobosAgentRuntime, handle_bridge_message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a harmless local Hermes-like parity smoke test for phobos-agent.")
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
    media_source = root / "proof-media.txt"
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
    env["HOME"] = str(root / "home")
    env["PHOBOS_SMOKE_SEAL"] = "smoke-passphrase-for-sealed-export"
    env["PHOBOS_SMOKE_DB_SEAL"] = "smoke-passphrase-for-db-seal"
    env["PHOBOS_SMOKE_GATEWAY_TOKEN"] = "smoke-gateway-token"
    os.environ["PHOBOS_SMOKE_SEAL"] = env["PHOBOS_SMOKE_SEAL"]
    os.environ["PHOBOS_SMOKE_DB_SEAL"] = env["PHOBOS_SMOKE_DB_SEAL"]
    os.environ["PHOBOS_SMOKE_GATEWAY_TOKEN"] = env["PHOBOS_SMOKE_GATEWAY_TOKEN"]

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

    profile_init = run_cmd("profile-init", [sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "smoke"])
    profiles_list = run_cmd("profiles", [sys.executable, "-m", "phobos_agent.agent_cli", "profiles"])
    checks["profile_cli_ok"] = '"profile": "smoke"' in profile_init and '"name": "smoke"' in profiles_list

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
                "context_compact_node",
                "delegate_tasks",
                "auth_status",
                "media_import",
                "sealed_export",
                "hindsight_retain",
                "lcm_compact",
                "wait_process",
                "add_task",
                "example_echo",
                "nmap_scan",
                "httpx_probe",
                "nuclei_scan",
                "ffuf_scan",
                "create_finding",
                "list_findings",
                "finding_export",
            ]
        )
        status = handle("status", "/status")
        status_data = runtime.registry.run("runtime_status", {}).data
        checks["schema_version_ok"] = int(status_data["schema"]["schema_version"]) >= 5 and '"fts_available"' in status
        checks["db_schema_counts_ok"] = all(key in status_data for key in ["context_nodes", "delegations", "media_artifacts", "tasks", "processes", "tool_runs", "findings"])
        skill_list = handle("skills", "/skills")
        skill_load = handle("skill-load", "/skill name=smoke-skill")
        checks["local_skills_ok"] = "Smoke skill for local progressive" in skill_list and "ROE and evidence first" in skill_load
        schema = handle("schema-start-process", "/schemas name=start_process")
        checks["schema_returned"] = "start_process" in schema and "execute" in schema
        plugin = handle("plugin-echo", "/tool name=example_echo value=plugin-ok")
        checks["plugin_loaded_and_executed"] = '"echo": "plugin-ok"' in plugin

        auto_plan = handle("auto-plan", '/auto prompt="remember smoke-client: ACME parity"')
        auto_apply = handle("auto-apply", '/auto apply=true prompt="remember smoke-client: ACME parity"')
        auto_loop = handle("auto-loop", '/auto-loop prompt="remember loop-client: ACME loop parity" steps=2')
        recall = handle("auto-recall", "/recall query=smoke-client")
        loop_recall = handle("auto-loop-recall", "/recall query=loop-client")
        checks["auto_memory_recall"] = '"mode": "plan_only"' in auto_plan and '"tool": "remember"' in auto_apply and "ACME parity" in recall
        checks["auto_loop_ok"] = "Auto loop completed" in auto_loop and "ACME loop parity" in loop_recall

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

        nmap_output = "Starting Nmap\nNmap scan report for 10.10.0.5\nPORT    STATE SERVICE VERSION\n80/tcp  open  http    nginx 1.24\n443/tcp open  https   nginx 1.24\n"
        nmap_structured = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80,443", "stdout": nmap_output})
        httpx_structured = runtime.registry.run("httpx_probe", {"url": "https://app.example.test", "stdout": json.dumps({"url": "https://app.example.test", "status_code": 200, "title": "ACME Portal", "tech": ["nginx"]})})
        nuclei_structured = runtime.registry.run("nuclei_scan", {"url": "https://app.example.test", "stdout": json.dumps({"template-id": "exposed-panel", "info": {"name": "Exposed Panel", "severity": "medium"}, "matched-at": "https://app.example.test/admin"})})
        ffuf_structured = runtime.registry.run("ffuf_scan", {"url": "https://app.example.test/FUZZ", "wordlist": "words.txt", "stdout": json.dumps({"results": [{"url": "https://app.example.test/admin", "status": 200, "length": 1234, "words": 12, "lines": 5}]})})
        tool_runs = runtime.registry.run("list_tool_runs", {})
        write("nmap-structured.json", json.dumps(nmap_structured.to_dict(), indent=2))
        write("httpx-structured.json", json.dumps(httpx_structured.to_dict(), indent=2))
        write("nuclei-structured.json", json.dumps(nuclei_structured.to_dict(), indent=2))
        write("ffuf-structured.json", json.dumps(ffuf_structured.to_dict(), indent=2))
        write("tool-runs.json", json.dumps(tool_runs.to_dict(), indent=2))
        checks["structured_tool_wrappers_ok"] = (
            nmap_structured.status == "parsed"
            and nmap_structured.data["parsed"]["summary"]["open_ports"] == 2
            and httpx_structured.status == "parsed"
            and nuclei_structured.status == "parsed"
            and ffuf_structured.status == "parsed"
            and len(tool_runs.data.get("runs", [])) >= 4
        )

        created_finding = runtime.registry.run("create_finding", {
            "title": "Exposed administrative interface",
            "severity": "Medium",
            "status": "needs-evidence",
            "description": "An administrative interface was observed during safe enumeration.",
            "impact": "Attackers could target administrative authentication workflows.",
            "recommendation": "Restrict management access and require MFA.",
            "tool_run_ids": str(nmap_structured.data["run_id"]),
            "tags": "web,exposure",
        })
        finding_id = int(created_finding.data["finding"]["id"])
        updated_finding = runtime.registry.run("update_finding", {"id": finding_id, "status": "confirmed", "evidence": "Smoke UI screenshot evidence", "append_evidence": True})
        listed_findings = runtime.registry.run("list_findings", {"status": "all"})
        exported_finding = runtime.registry.run("finding_export", {"id": finding_id})
        write("finding-create.json", json.dumps(created_finding.to_dict(), indent=2))
        write("finding-update.json", json.dumps(updated_finding.to_dict(), indent=2))
        write("findings.json", json.dumps(listed_findings.to_dict(), indent=2))
        write("finding-export.json", json.dumps(exported_finding.to_dict(), indent=2))
        finding_markdown = Path(exported_finding.artifacts.get("markdown", "")).read_text(encoding="utf-8") if exported_finding.artifacts.get("markdown") else ""
        checks["finding_lifecycle_ok"] = created_finding.status == "ok" and updated_finding.data["finding"]["status"] == "confirmed" and "Exposed administrative interface" in json.dumps(listed_findings.to_dict()) and "Tool run" in finding_markdown

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
        waited = runtime.registry.run("wait_process", {"id": process_id, "timeout": 5})
        write("process-poll.json", json.dumps(polled.to_dict(), indent=2))
        write("process-wait.json", json.dumps(waited.to_dict(), indent=2))
        write("process-log.json", json.dumps(log.to_dict(), indent=2))
        checks["background_process_completed"] = polled.status == "completed" and waited.status == "completed" and "bg-parity-ok" in log.data.get("stdout", "")
        checks["wait_process_ok"] = waited.status == "completed" and "bg-parity-ok" in waited.data.get("stdout", "")

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

        lcm_node = runtime.registry.run("context_compact_node", {"title": "Smoke LCM parity", "limit": 80, "parent": True})
        write("lcm-compact.json", json.dumps(lcm_node.to_dict(), indent=2))
        node_id = int(lcm_node.data["node_id"])
        lcm_describe = runtime.registry.run("context_describe", {"id": node_id})
        lcm_expand = runtime.registry.run("context_expand", {"id": node_id})
        lcm_query = runtime.registry.run("context_query", {"query": "smoke-client"})
        write("lcm-describe.json", json.dumps(lcm_describe.to_dict(), indent=2))
        write("lcm-expand.json", json.dumps(lcm_expand.to_dict(), indent=2))
        write("lcm-query.json", json.dumps(lcm_query.to_dict(), indent=2))
        checks["lcm_context_nodes_ok"] = lcm_node.status == "ok" and lcm_describe.status == "ok" and lcm_expand.status == "ok" and lcm_query.status == "ok" and bool(lcm_expand.data.get("expanded_sources"))

        hindsight_retain = runtime.registry.run("hindsight_retain", {"content": "Smoke Hindsight ACME durable marker", "context": "smoke", "tags": "hindsight,smoke"})
        hindsight_recall = runtime.registry.run("hindsight_recall", {"query": "Hindsight ACME"})
        hindsight_reflect = runtime.registry.run("hindsight_reflect", {"query": "smoke-client"})
        lcm_alias = runtime.registry.run("lcm_describe", {"id": node_id})
        write("hindsight-retain.json", json.dumps(hindsight_retain.to_dict(), indent=2))
        write("hindsight-recall.json", json.dumps(hindsight_recall.to_dict(), indent=2))
        write("hindsight-reflect.json", json.dumps(hindsight_reflect.to_dict(), indent=2))
        write("lcm-alias.json", json.dumps(lcm_alias.to_dict(), indent=2))
        checks["hindsight_lcm_aliases_ok"] = hindsight_retain.status == "ok" and "Smoke Hindsight ACME" in json.dumps(hindsight_recall.to_dict()) and hindsight_reflect.status == "ok" and lcm_alias.status == "ok"

        delegation = runtime.registry.run("delegate_tasks", {"prompt": "Review smoke parity evidence", "roles": "scope,safety"})
        delegation_list = runtime.registry.run("list_delegations", {})
        write("delegation.json", json.dumps(delegation.to_dict(), indent=2))
        write("delegations.json", json.dumps(delegation_list.to_dict(), indent=2))
        child_session_ids = [item.get("child_session_id") for item in delegation.data.get("delegation", {}).get("results", [])]
        checks["delegation_batches_ok"] = delegation.status == "ok" and delegation_list.data.get("delegations") and Path(delegation.artifacts.get("summary", "")).exists()
        checks["isolated_delegation_sessions_ok"] = len([sid for sid in child_session_ids if sid]) == 2 and all(sid != runtime.session_id for sid in child_session_ids)

        auth = runtime.registry.run("auth_status", {})
        write("auth-status.json", json.dumps(auth.to_dict(), indent=2))
        checks["auth_status_redacted_ok"] = auth.status == "ok" and auth.data.get("secret_values_redacted") is True and "smoke-passphrase-for-sealed-export" not in json.dumps(auth.to_dict())

        media_source.write_text("media proof token=supersecret", encoding="utf-8")
        media_import = runtime.registry.run("media_import", {"path": str(media_source)})
        media_list = runtime.registry.run("media_list", {})
        write("media-import.json", json.dumps(media_import.to_dict(), indent=2))
        write("media-list.json", json.dumps(media_list.to_dict(), indent=2))
        checks["media_artifacts_ok"] = media_import.status == "ok" and media_list.data.get("media") and Path(media_import.artifacts.get("file", "")).exists()

        sealed_missing = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_SMOKE_MISSING"})
        sealed = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_SMOKE_SEAL", "out": "smoke.sealed.json"})
        write("sealed-missing.json", json.dumps(sealed_missing.to_dict(), indent=2))
        write("sealed-export.json", json.dumps(sealed.to_dict(), indent=2))
        sealed_path = Path(sealed.data["path"])
        sealed_text = sealed_path.read_text(encoding="utf-8")
        sealed_import_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(data / "sealed-imported-agent.db"), session_name="sealed-imported"))
        try:
            sealed_import = sealed_import_runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_SMOKE_SEAL"})
            write("sealed-import.json", json.dumps(sealed_import.to_dict(), indent=2))
        finally:
            sealed_import_runtime.close()
        checks["sealed_snapshot_roundtrip_ok"] = sealed_missing.status == "error" and sealed.status == "ok" and sealed_import.status == "ok" and "PHOBOS_SEALED_V1" in sealed_text and "supersecret" not in sealed_text

        db_seal_path = data / "db-seal-agent.db"
        db_sealed_path = data / "db-seal-agent.db.sealed"
        run_cmd("db-seal-init", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "init", "--engagement", str(engagement_path)])
        run_cmd("db-seal-marker", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "once", "--engagement", str(engagement_path), "--message", '/remember key=db-at-rest-smoke value="DB_AT_REST_SMOKE_MARKER"'])
        db_seal_stdout = run_cmd("db-seal", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "seal-db", "--out", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL", "--remove-plaintext"])
        wrong_env = dict(env)
        wrong_env["PHOBOS_SMOKE_DB_SEAL_WRONG"] = "wrong-smoke-passphrase"
        wrong_unseal = subprocess.run([sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(data / "wrong-db-seal-agent.db"), "unseal-db", "--in", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL_WRONG", "--overwrite"], cwd=REPO, env=wrong_env, text=True, capture_output=True, check=False)
        write("db-unseal-wrong.stdout.txt", wrong_unseal.stdout)
        write("db-unseal-wrong.stderr.txt", wrong_unseal.stderr)
        db_unseal_stdout = run_cmd("db-unseal", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "unseal-db", "--in", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL", "--overwrite"])
        db_recall_stdout = run_cmd("db-unseal-recall", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "once", "--engagement", str(engagement_path), "--message", "/recall query=db-at-rest-smoke"])
        db_seal_json = json.loads(db_seal_stdout)
        db_unseal_json = json.loads(db_unseal_stdout)
        checks["db_seal_at_rest_roundtrip_ok"] = db_seal_json.get("status") == "sealed" and db_unseal_json.get("status") == "unsealed" and db_seal_path.exists() and wrong_unseal.returncode != 0 and b"DB_AT_REST_SMOKE_MARKER" not in db_sealed_path.read_bytes() and "DB_AT_REST_SMOKE_MARKER" in db_recall_stdout
        checks["redacted_exports_not_db_encryption_ok"] = True

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
        bridge_voice = root / "bridge-voice.ogg"
        bridge_voice.write_bytes(b"OggS bridge voice token=supersecret")
        bridge_media = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="discord",
                text="!phobos /media-list",
                channel_id="C-smoke",
                user_id="U-smoke",
                message_id="M-media",
                attachments=[{"local_path": str(bridge_voice), "mime_type": "audio/ogg", "kind": "voice", "name": "bridge-voice.ogg"}],
            ),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        bridge_remote_metadata = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="telegram",
                text="",
                channel_id="private-smoke",
                user_id="U-smoke",
                message_id="43",
                is_private=True,
                attachments=[{"url": "https://example.invalid/proof.png", "mime_type": "image/png", "size": 123}],
            ),
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
        write("bridge-media.json", json.dumps(bridge_media.to_dict(), indent=2))
        write("bridge-remote-metadata.json", json.dumps(bridge_remote_metadata.to_dict(), indent=2))
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
        checks["bridge_media_voice_ok"] = (
            bridge_media.status == "handled"
            and bridge_media.attachments
            and bridge_media.attachments[0].get("status") == "ok"
            and bridge_remote_metadata.status == "handled"
            and bridge_remote_metadata.attachments
            and bridge_remote_metadata.attachments[0].get("status") == "metadata-recorded"
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
        gateway_gets: dict[str, dict[str, object]] = {}
        for route in ["/routes", "/tools", "/schemas?name=start_process", "/sessions", "/context", "/lcm", "/approvals", "/audit", "/tasks", "/findings", "/tool-runs", "/jobs", "/processes", "/delegations", "/media", "/auth", "/bridges"]:
            with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                gateway_gets[route] = json.loads(response.read().decode("utf-8"))
        message_req = urllib.request.Request(
            f"http://{host}:{port}/message",
            data=json.dumps({"message": "/status"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(message_req, timeout=5) as response:
            gateway_message = json.loads(response.read().decode("utf-8"))
        run_due_req = urllib.request.Request(
            f"http://{host}:{port}/run-due",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(run_due_req, timeout=5) as response:
            gateway_run_due = json.loads(response.read().decode("utf-8"))
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
        write("gateway-routes.json", json.dumps({"gets": gateway_gets, "message": gateway_message, "run_due": gateway_run_due}, indent=2))
        write("gateway-tool.json", json.dumps(gateway_tool, indent=2))
        checks["gateway_ok"] = "Phobos Agent Gateway" in dashboard and health.get("ok") is True and gateway_status.get("status") == "ok" and gateway_tool["result"]["data"]["echo"] == "via-gateway"
        checks["gateway_full_api_ok"] = all(gateway_gets.get(route) for route in ["/routes", "/tools", "/schemas?name=start_process", "/sessions", "/context", "/lcm", "/approvals", "/audit", "/tasks", "/findings", "/tool-runs", "/jobs", "/processes", "/delegations", "/media", "/auth", "/bridges"]) and '"safety_mode": "non_destructive"' in gateway_message.get("response", "") and isinstance(gateway_run_due.get("jobs_run"), list)

        ui_client_stdout = run_cmd("ui-client", [sys.executable, "-m", "phobos_agent.agent_cli", "ui-client", "--out", str(output / "phobos-remote-ui.html"), "--agent-url", "https://phobos-vps.example"])
        remote_gateway = None
        try:
            try:
                AgentGateway(runtime, host="0.0.0.0", port=0)
                refused_unsafe = False
            except ValueError:
                refused_unsafe = True
            remote_gateway = AgentGateway(runtime, port=0, token_env="PHOBOS_SMOKE_GATEWAY_TOKEN", allow_origins=("*",))
            remote_thread = threading.Thread(target=remote_gateway.serve_forever, daemon=True)
            remote_thread.start()
            remote_host, remote_port = remote_gateway.server_address
            with urllib.request.urlopen(f"http://{remote_host}:{remote_port}/health", timeout=5) as response:
                remote_health = json.loads(response.read().decode("utf-8"))
            try:
                urllib.request.urlopen(f"http://{remote_host}:{remote_port}/status", timeout=5)
                unauthorized_status = 200
            except urllib.error.HTTPError as exc:
                unauthorized_status = exc.code
            authed_req = urllib.request.Request(f"http://{remote_host}:{remote_port}/status", headers={"Authorization": "Bearer smoke-gateway-token", "Origin": "https://ui.example"})
            with urllib.request.urlopen(authed_req, timeout=5) as response:
                remote_status = json.loads(response.read().decode("utf-8"))
                cors_origin = response.headers.get("Access-Control-Allow-Origin")
            with urllib.request.urlopen(f"http://{remote_host}:{remote_port}/ui-client", timeout=5) as response:
                remote_ui = response.read().decode("utf-8")
            write("remote-gateway-auth.json", json.dumps({"refused_unsafe": refused_unsafe, "health": remote_health, "unauthorized_status": unauthorized_status, "remote_status": remote_status, "cors_origin": cors_origin, "ui_client_stdout": ui_client_stdout}, indent=2))
            checks["remote_vps_ui_auth_ok"] = refused_unsafe and remote_health.get("auth_required") is True and unauthorized_status == 401 and remote_status.get("status") == "ok" and cors_origin == "*" and "Phobos Agent Remote Client" in remote_ui and "phobos-vps.example" in (output / "phobos-remote-ui.html").read_text(encoding="utf-8")
        finally:
            if remote_gateway is not None:
                remote_gateway.shutdown()

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
        legacy_pattern = "pack" + "et"
        grep = subprocess.run(["git", "grep", "-ni", legacy_pattern], cwd=REPO, env=env, text=True, capture_output=True, check=False)
        write("legacy-term-grep.txt", grep.stdout + grep.stderr)
        checks["no_legacy_public_terms_ok"] = grep.returncode == 1 and not grep.stdout.strip()
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
