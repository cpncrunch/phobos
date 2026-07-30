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
from offsec_agent_harness.models import redact_secrets


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
    cfg.operator_name = "Caligo"
    cfg.assistant_style = "direct, concise, practical, evidence-first"
    cfg.plugin_dirs = [str(REPO / "examples" / "plugins")]
    cfg.skill_dirs = [str(skill_root)]
    cfg.preload_skills = ["smoke-skill"]
    cfg.skill_bundles = {"smoke": ["smoke-skill"]}
    cfg.save(config_path)
    checks["config_written"] = config_path.exists() and cfg.auto_execute_natural is False and cfg.operator_name == "Caligo"

    init_stdout = run_cmd(
        "agent-init",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "init", "--engagement", str(engagement_path)],
    )
    init_json = json.loads(init_stdout)
    checks["agent_init_ok"] = bool(init_json.get("session_id")) and init_json["runtime"]["skill_dirs"] == [str(skill_root)]

    runtime = PhobosAgentRuntime(AgentAppConfig.load(config_path).to_runtime_config(str(engagement_path), str(db_path), "smoke", config_path=str(config_path)))
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
                "scope_check",
                "workspace_write",
                "start_process",
                "operator_briefing",
                "export_session",
                "import_session",
                "context_compact_node",
                "delegate_tasks",
                "auth_status",
                "safety_preflight",
                "guardrail_selftest",
                "media_import",
                "sealed_export",
                "hindsight_retain",
                "lcm_compact",
                "list_memories",
                "get_memory",
                "forget_memory",
                "wait_process",
                "add_task",
                "get_task",
                "get_process",
                "get_job",
                "update_job",
                "disable_job",
                "example_echo",
                "nmap_scan",
                "httpx_probe",
                "nuclei_scan",
                "ffuf_scan",
                "create_finding",
                "list_findings",
                "finding_export",
                "finding_review",
                "finding_bundle",
                "evidence_timeline",
                "evidence_manifest",
                "evidence_manifest_verify",
                "evidence_secret_scan",
                "closeout_review",
                "resolve_local_ref",
                "get_audit",
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
        invalid_tool_integer = runtime.registry.run("list_findings", {"limit": "not-an-int"})
        valid_tool_integer = runtime.registry.run("list_findings", {"limit": "2"})
        integer_validation_payload = {
            "invalid": invalid_tool_integer.to_dict(),
            "valid": valid_tool_integer.to_dict(),
        }
        write("tool-schema-integer-validation.json", json.dumps(integer_validation_payload, indent=2))
        checks["tool_schema_integer_validation_ok"] = (
            invalid_tool_integer.status == "error"
            and invalid_tool_integer.message == "limit must be an integer."
            and valid_tool_integer.status == "ok"
            and "invalid literal" not in json.dumps(integer_validation_payload)
            and "Traceback" not in json.dumps(integer_validation_payload)
        )
        invalid_tool_boolean = runtime.registry.run("run_command", {"execute": "maybe"})
        dry_tool_boolean = runtime.registry.run("run_command", {"target": "app.example.test", "type": "local", "purpose": "boolean schema dry-run regression", "command": "printf bool-validation-ok", "execute": "false"})
        runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "old"})
        overwrite_tool_boolean = runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "new", "append": "false"})
        append_tool_boolean = runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "-tail", "append": "true"})
        boolean_workspace_text = (runtime.registry.workspace_root / "notes" / "schema-bool.md").read_text(encoding="utf-8")
        boolean_validation_payload = {
            "invalid": invalid_tool_boolean.to_dict(),
            "dry_run": dry_tool_boolean.to_dict(),
            "overwrite": overwrite_tool_boolean.to_dict(),
            "append": append_tool_boolean.to_dict(),
            "workspace_text": boolean_workspace_text,
        }
        write("tool-schema-boolean-validation.json", json.dumps(boolean_validation_payload, indent=2))
        checks["tool_schema_boolean_validation_ok"] = (
            invalid_tool_boolean.status == "error"
            and invalid_tool_boolean.message == "execute must be a boolean."
            and dry_tool_boolean.status == "dry_run"
            and overwrite_tool_boolean.status == "ok"
            and append_tool_boolean.status == "ok"
            and boolean_workspace_text == "new-tail"
            and "Traceback" not in json.dumps(boolean_validation_payload)
        )

        scope_summary = handle("scope-summary", "/scope")
        scope_allowed = handle("scope-allowed", '/scope target="https://app.example.test/login?token=supersecret"')
        scope_blocked = handle("scope-blocked", "/scope-check target=outside.example.test")
        runtime.roe.in_scope_targets.extend([
            "https://api.example.test:8443",
            "*.scoped.example:443",
            "2001:db8::/126",
            "[2001:db8::8]:9443",
        ])
        scope_url_port_allowed = handle("scope-url-port-allowed", '/scope target="https://api.example.test:8443/v1?token=supersecret"')
        scope_url_port_blocked = handle("scope-url-port-blocked", '/scope target="https://api.example.test:9443/v1"')
        scope_wildcard_port_allowed = handle("scope-wildcard-port-allowed", '/scope target="team.scoped.example:443"')
        scope_ipv6_allowed = handle("scope-ipv6-allowed", '/scope target="http://[2001:db8::1]:8080/"')
        scope_ipv6_port_allowed = handle("scope-ipv6-port-allowed", '/scope target="[2001:db8::8]:9443"')
        scope_schema = handle("schema-scope-check", "/schemas name=scope_check")
        auto_scope = handle("auto-scope", '/auto apply=true prompt="is app.example.test in scope?"')
        checks["scope_check_read_only_ok"] = (
            "Engagement scope summary" in scope_summary
            and '"no_target_activity": true' in scope_summary
            and '"decision": "allow"' in scope_allowed
            and '"decision": "block"' in scope_blocked
            and "scope_check" in scope_schema
            and '"tool": "scope_check"' in auto_scope
            and "supersecret" not in scope_summary + scope_allowed + scope_blocked + scope_schema + auto_scope
        )
        checks["scope_url_port_ipv6_matching_ok"] = (
            '"decision": "allow"' in scope_url_port_allowed
            and '"matched_rule": "https://api.example.test:8443"' in scope_url_port_allowed
            and '"decision": "block"' in scope_url_port_blocked
            and '"decision": "allow"' in scope_wildcard_port_allowed
            and '"decision": "allow"' in scope_ipv6_allowed
            and '"decision": "allow"' in scope_ipv6_port_allowed
            and "supersecret" not in scope_url_port_allowed + scope_url_port_blocked + scope_wildcard_port_allowed + scope_ipv6_allowed + scope_ipv6_port_allowed
        )

        guardrail_selftest = handle("guardrail-selftest", '/guardrail-test target="https://app.example.test/login?token=supersecret"')
        guardrail_selftest_schema = handle("schema-guardrail-selftest", "/schemas name=guardrail_selftest")
        guardrail_selftest_auto = handle("auto-guardrail-selftest", '/auto apply=true prompt="run guardrail self-test target=app.example.test"')
        guardrail_selftest_cli = run_cmd(
            "guardrail-test-cli",
            [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "guardrail-test", "--engagement", str(engagement_path), "--target", "app.example.test", "--out", "smoke-cli-guardrail-selftest.md"],
        )
        guardrail_selftest_json = json.loads(guardrail_selftest_cli)
        checks["guardrail_selftest_ok"] = (
            "Guardrail self-test ready" in guardrail_selftest
            and '"no_target_activity": true' in guardrail_selftest
            and '"executed": false' in guardrail_selftest
            and '"actual": "allow"' in guardrail_selftest
            and '"actual": "confirm"' in guardrail_selftest
            and '"actual": "block"' in guardrail_selftest
            and "guardrail_selftest" in guardrail_selftest_schema
            and '"tool": "guardrail_selftest"' in guardrail_selftest_auto
            and guardrail_selftest_json.get("status") == "ok"
            and guardrail_selftest_json.get("data", {}).get("readiness") == "ready"
            and "supersecret" not in guardrail_selftest + guardrail_selftest_schema + guardrail_selftest_auto + guardrail_selftest_cli
        )

        natural_polish = handle("natural-polish", "What is the safest next step for a controlled IDOR?")
        natural_execution = handle("natural-execution-polish", "Run nmap against app.example.test")
        checks["natural_response_polish_ok"] = (
            "Phobos Agent response" not in natural_polish
            and "pentest assistant" in natural_polish
            and "I didn’t run anything" in natural_execution
        )

        auto_plan = handle("auto-plan", '/auto prompt="remember smoke-client: ACME parity"')
        auto_apply = handle("auto-apply", '/auto apply=true prompt="remember smoke-client: ACME parity"')
        auto_loop = handle("auto-loop", '/auto-loop prompt="remember loop-client: ACME loop parity" steps=2')
        recall = handle("auto-recall", "/recall query=smoke-client")
        loop_recall = handle("auto-loop-recall", "/recall query=loop-client")
        checks["auto_memory_recall"] = '"mode": "plan_only"' in auto_plan and '"tool": "remember"' in auto_apply and "ACME parity" in recall
        checks["auto_loop_ok"] = "Auto loop completed" in auto_loop and "ACME loop parity" in loop_recall
        hygiene_memory = runtime.registry.run("remember", {"key": "smoke-forget", "value": "Temporary memory hygiene marker token=supersecret", "tags": "hygiene"})
        hygiene_id = int(hygiene_memory.data.get("id", 0))
        memory_list = handle("memory-list", "/memories query=smoke-forget")
        memory_detail = handle("memory-detail", f"/memory id={hygiene_id}")
        hygiene_detail_before = runtime.store.get_memory(memory_id=hygiene_id)
        memory_forget = handle("memory-forget", "/forget key=smoke-forget")
        memory_after_forget = handle("memory-after-forget", "/recall query=smoke-forget")
        auto_forget_seed = runtime.registry.run("remember", {"key": "smoke-auto-forget", "value": "Auto forget marker", "tags": "hygiene"})
        auto_forget = handle("auto-forget", '/auto apply=true prompt="forget memory smoke-auto-forget"')
        memory_hygiene_payload = {
            "created": hygiene_memory.to_dict(),
            "detail_before_forget": hygiene_detail_before,
            "after_forget": runtime.store.get_memory(memory_id=hygiene_id),
            "auto_seed": auto_forget_seed.to_dict(),
            "auto_after_forget": runtime.store.get_memory(key="smoke-auto-forget"),
        }
        write("memory-hygiene.json", json.dumps(memory_hygiene_payload, indent=2, sort_keys=True))
        checks["memory_hygiene_forget_ok"] = (
            hygiene_memory.status == "ok"
            and "smoke-forget" in memory_list + memory_detail
            and "Deleted memory" in memory_forget
            and "Found 0 memory entries" in memory_after_forget
            and '"tool": "forget_memory"' in auto_forget
            and runtime.store.get_memory(key="smoke-auto-forget") is None
            and "supersecret" not in memory_list + memory_detail + memory_forget + json.dumps(memory_hygiene_payload)
        )

        storage_message_id = runtime.store.append_message(
            runtime.session_id,
            "user",
            "storage boundary note token=storage-message-secret",
            {"api_key": "storage-message-metadata-key", "nested": ["Cookie: sid=storage-message-cookie"]},
        )
        storage_memory = runtime.registry.run("remember", {
            "key": "client-token=storage-memory-secret",
            "value": "Authorization: Bearer storage-memory-bearer",
            "tags": "api_key=storage-memory-tag",
        })
        storage_summary_id = runtime.store.create_context_summary(runtime.session_id, storage_message_id, storage_message_id, "storage summary password=storage-summary-secret")
        storage_node_id = runtime.store.create_context_node(
            runtime.session_id,
            "storage node token=storage-node-title",
            "storage node summary client_secret=storage-node-summary",
            sources=[{"type": "message", "id": storage_message_id, "note": "token=storage-node-source"}],
            metadata={"client_secret": "storage-node-metadata"},
        )
        storage_media_src = root / "proof-token=storage-media-name.txt"
        storage_media_src.write_text("storage media content token=storage-media-content", encoding="utf-8")
        storage_media = runtime.registry.run("media_import", {"path": str(storage_media_src)})
        storage_media_id = int(storage_media.data.get("media", {}).get("id", 0)) if storage_media.data.get("media") else 0
        storage_audit_id = runtime.store.audit(runtime.session_id, "storage_audit_probe", {"token": "storage-audit-secret", "nested": {"authorization": "Bearer storage-audit-bearer"}})
        storage_raw = {
            "message": dict(runtime.store.conn.execute("SELECT content, metadata_json FROM messages WHERE id=?", (storage_message_id,)).fetchone()),
            "memories": [dict(row) for row in runtime.store.conn.execute("SELECT key, value, tags FROM memories").fetchall()],
            "summary": dict(runtime.store.conn.execute("SELECT summary FROM context_summaries WHERE id=?", (storage_summary_id,)).fetchone()),
            "node": dict(runtime.store.conn.execute("SELECT title, summary, source_json, metadata_json FROM context_nodes WHERE id=?", (storage_node_id,)).fetchone()),
            "media": dict(runtime.store.conn.execute("SELECT source_path, artifact_path, metadata_json FROM media_artifacts WHERE id=?", (storage_media_id,)).fetchone()),
            "audit": dict(runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE id=?", (storage_audit_id,)).fetchone()),
        }
        storage_views = {
            "memory_result": storage_memory.to_dict(),
            "message": runtime.store.get_message(storage_message_id, session_id=runtime.session_id),
            "recall": runtime.registry.run("recall", {"query": "client-token"}).to_dict(),
            "context": runtime.registry.run("context_expand", {"id": storage_node_id}).to_dict(),
            "media": runtime.registry.run("media_get", {"id": storage_media_id}).to_dict(),
            "audit": runtime.registry.run("get_audit", {"id": storage_audit_id}).to_dict(),
        }
        storage_blob = json.dumps({"raw": storage_raw, "views": storage_views}, sort_keys=True)
        storage_leaks = [
            "storage-message-secret",
            "storage-message-metadata-key",
            "storage-message-cookie",
            "storage-memory-secret",
            "storage-memory-bearer",
            "storage-memory-tag",
            "storage-summary-secret",
            "storage-node-title",
            "storage-node-summary",
            "storage-node-source",
            "storage-node-metadata",
            "storage-media-name",
            "storage-audit-secret",
            "storage-audit-bearer",
        ]
        checks["message_memory_context_media_storage_redaction_ok"] = (
            storage_memory.status == "ok"
            and storage_media.status == "ok"
            and all(leak not in storage_blob for leak in storage_leaks)
            and "<REDACTED>" in storage_blob
        )
        write("storage-redaction-boundary.json", redact_secrets(json.dumps({"raw": storage_raw, "views": storage_views}, indent=2)) or "{}")

        handle("workspace-write", '/write path=notes/scope.md content="Scope app.example.test authz note"')
        read_back = handle("workspace-read", "/read path=notes/scope.md")
        search = handle("workspace-search", '/workspace-search query=authz glob="**/*.md"')
        patch = handle("workspace-patch", '/patch-file path=notes/scope.md old=authz new=authorization')
        escape = handle("workspace-escape", "/write path=../escape.txt content=nope")
        symlink_escape_ok = True
        symlink_created = False
        pack_symlink_created = False
        outside_secret = root / "outside-workspace-marker.txt"
        outside_secret.write_text("outside-symlink-marker should not appear in workspace search", encoding="utf-8")
        try:
            link = runtime.registry.workspace_root / "notes" / "outside-link.txt"
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(outside_secret)
            symlink_created = True
            symlink_search = handle("workspace-symlink-search", '/workspace-search query=outside-symlink-marker glob="**/*.txt"')
            symlink_read = handle("workspace-symlink-read", "/read path=notes/outside-link.txt")
            symlink_escape_ok = "Found 0 matches" in symlink_search and "outside-symlink-marker" not in symlink_search and "escapes the engagement workspace" in symlink_read
        except (OSError, NotImplementedError) as exc:
            write("workspace-symlink-skipped.txt", f"symlink creation unavailable: {exc}\n")
        pack_outside_secret = root / "outside-pack-marker.txt"
        pack_outside_secret.write_text("OUTSIDE_PACK_SYMLINK_SENTINEL", encoding="utf-8")
        try:
            pack_link = runtime.registry.harness.store.root / "outside-pack-link.txt"
            if pack_link.exists() or pack_link.is_symlink():
                pack_link.unlink()
            pack_link.symlink_to(pack_outside_secret)
            pack_symlink_created = True
        except (OSError, NotImplementedError) as exc:
            write("pack-symlink-skipped.txt", f"pack symlink creation unavailable: {exc}\n")
        checks["workspace_roundtrip_and_escape_block"] = "authz note" in read_back and "scope.md" in search and "Patched notes/scope.md" in patch and "escapes the engagement workspace" in escape
        checks["workspace_symlink_escape_block"] = symlink_escape_ok

        assess = handle("active-scan-assess", '/assess target=10.10.0.5 type=service-enumeration purpose=version-scan command="nmap -sV 10.10.0.5"')
        run = handle("safe-run", '/run target=app.example.test type=host purpose="safe local smoke" command="printf parity-ok" execute=true')
        secret_run = handle("secret-run", '/run target=app.example.test type=host purpose="redaction smoke" command="printf token=supersecret" execute=true')
        state_change = handle("state-change-confirm", '/run target=app.example.test type=web purpose="controlled update token=supersecret" command="printf curl -X POST https://app.example.test/profile token=supersecret" execute=true')
        approvals = handle("approvals", "/approvals")
        approval_detail = handle("approval-detail", "/approval id=1")
        approval_store_owned = runtime.store.get_approval(1, session_id=runtime.session_id)
        approval_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="approval-scope-foreign"))
        try:
            approval_store_foreign = runtime.store.get_approval(1, session_id=approval_scope_runtime.session_id)
            approval_foreign_detail = approval_scope_runtime.registry.run("get_approval", {"id": 1})
            approval_foreign_approve = approval_scope_runtime.registry.run("approve", {"id": 1})
            approval_foreign_resolve = runtime.store.resolve_approval(1, "denied", "foreign-smoke", {"reason": "foreign"}, session_id=approval_scope_runtime.session_id)
        finally:
            approval_scope_runtime.close()
        approval_after_foreign_resolve = runtime.store.get_approval(1, session_id=runtime.session_id)
        raw_approval_row = runtime.store.conn.execute("SELECT args_json, decision_json FROM approvals WHERE id=1").fetchone()
        raw_approval_text = (raw_approval_row["args_json"] or "") + (raw_approval_row["decision_json"] or "") if raw_approval_row else ""
        approval_scope_results = {
            "owned_lookup_ok": bool(approval_store_owned),
            "foreign_lookup": approval_store_foreign,
            "foreign_detail": approval_foreign_detail.to_dict(),
            "foreign_approve": approval_foreign_approve.to_dict(),
            "foreign_resolve": approval_foreign_resolve,
            "owner_status_after_foreign_resolve": (approval_after_foreign_resolve or {}).get("status"),
            "raw_storage_redacted": "token=<REDACTED>" in raw_approval_text and "supersecret" not in raw_approval_text,
        }
        write("session-bound-approval-store.json", json.dumps(approval_scope_results, indent=2, sort_keys=True))
        destructive = handle("destructive-block", '/run target=app.example.test type=host purpose=blocked command="printf rm -rf /" execute=true')
        dos = handle("dos-block", '/run target=app.example.test type=web purpose=blocked command="printf hping3 --flood app.example.test" execute=true')
        checks["guardrails_execution_approvals_blocks"] = (
            "Guardrail decision: allow" in assess
            and "parity-ok" in run
            and "token=<REDACTED>" in secret_run
            and "needs_approval" in state_change
            and "controlled update" in approvals
            and "token=<REDACTED>" in approvals
            and "token=<REDACTED>" in approval_detail
            and "supersecret" not in approvals + approval_detail
            and "blocked" in destructive.lower()
            and "blocked" in dos.lower()
        )
        checks["session_bound_approval_store_ok"] = (
            bool(approval_store_owned)
            and approval_store_foreign is None
            and approval_foreign_detail.status == "error"
            and approval_foreign_approve.status == "error"
            and approval_foreign_resolve is False
            and (approval_after_foreign_resolve or {}).get("status") == "pending"
            and "not found in this session" in json.dumps(approval_scope_results)
            and "supersecret" not in json.dumps(approval_scope_results)
        )
        replay_probe = runtime.registry.run(
            "run_command",
            {"target": "app.example.test", "type": "web", "purpose": "redacted approval replay token=smoke-replay-secret", "command": "printf curl -X POST https://app.example.test/profile token=smoke-replay-secret", "execute": True},
        )
        replay_id = max(row["id"] for row in runtime.store.list_approvals(runtime.session_id, status="pending") if row["id"] != 1)
        replay_result = runtime.registry.run("approve", {"id": replay_id})
        replay_row = runtime.store.conn.execute("SELECT args_json, result_json, status FROM approvals WHERE id=?", (replay_id,)).fetchone()
        replay_text = "".join(str(replay_row[key] or "") for key in ("args_json", "result_json", "status")) if replay_row else ""
        approval_storage_results = {
            "source_raw_args_redacted": "token=<REDACTED>" in raw_approval_text and "supersecret" not in raw_approval_text,
            "replay_probe": replay_probe.to_dict(),
            "replay_result": replay_result.to_dict(),
            "replay_status": replay_row["status"] if replay_row else "missing",
        }
        write("approval-storage-redaction.json", json.dumps(approval_storage_results, indent=2, sort_keys=True))
        checks["approval_storage_redaction_ok"] = (
            replay_probe.status == "needs_approval"
            and replay_result.status == "blocked"
            and "blocked_redacted_args" in replay_text
            and "token=<REDACTED>" in raw_approval_text + replay_text
            and "supersecret" not in raw_approval_text + replay_text + json.dumps(approval_storage_results)
            and "smoke-replay-secret" not in raw_approval_text + replay_text + json.dumps(approval_storage_results)
        )
        runtime.store.audit(
            runtime.session_id,
            "audit_redaction_smoke",
            {
                "token": "token=smoke-audit-token",
                "api_key": "smoke-audit-key-only",
                "nested": {"authorization": "Authorization: Bearer smoke-audit-bearer"},
                "items": ["password=smoke-audit-password"],
            },
        )
        audit_redaction = handle("audit-redaction", "/audit limit=50")
        raw_audit = runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE event='audit_redaction_smoke'").fetchone()[0]
        checks["audit_redaction_ok"] = (
            "audit_redaction_smoke" in audit_redaction
            and "<REDACTED>" in audit_redaction
            and "smoke-audit-token" not in audit_redaction + raw_audit
            and "smoke-audit-key-only" not in audit_redaction + raw_audit
            and "smoke-audit-bearer" not in audit_redaction + raw_audit
            and "smoke-audit-password" not in audit_redaction + raw_audit
        )
        auth_redaction_sample = (
            "curl -H 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==' "
            "-H 'Cookie: sessionid=smoke-cookie-value; csrftoken=smoke-csrf-value' "
            "-H 'X-API-Key: smoke-header-api-key' "
            "https://app.example.test authorization=Bearer smoke-cli-bearer "
            "api_key='smoke-quoted-key' password=\"smoke-quoted-pass\" "
            "AWS_SECRET_ACCESS_KEY=smoke-aws-secret client_secret=\"smoke-client-secret\" "
            "private_key='-----BEGIN PRIVATE KEY-----\nsmoke-private-key\n-----END PRIVATE KEY-----' "
            '{"session_token":"smoke-session-token"}'
        )
        auth_redacted = redact_secrets(auth_redaction_sample) or ""
        auth_leak_markers = [
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "smoke-cookie-value",
            "smoke-csrf-value",
            "smoke-cli-bearer",
            "smoke-header-api-key",
            "smoke-quoted-key",
            "smoke-quoted-pass",
            "smoke-aws-secret",
            "smoke-client-secret",
            "smoke-private-key",
            "smoke-session-token",
        ]
        auth_redaction_preview = auth_redacted if all(marker not in auth_redacted for marker in auth_leak_markers) else "<redaction failed; preview suppressed>"
        write("auth-header-cookie-redaction.json", json.dumps({"preview": auth_redaction_preview, "leak_free": auth_redaction_preview == auth_redacted}, indent=2, sort_keys=True))
        checks["auth_header_cookie_redaction_ok"] = (
            auth_redaction_preview == auth_redacted
            and "Cookie: <REDACTED>" in auth_redacted
            and "authorization=Bearer <REDACTED>" in auth_redacted
            and "X-API-Key: <REDACTED>" in auth_redacted
            and "api_key='<REDACTED>'" in auth_redacted
            and 'password="<REDACTED>"' in auth_redacted
        )
        checks["cloud_oauth_private_key_redaction_ok"] = (
            auth_redaction_preview == auth_redacted
            and "AWS_SECRET_ACCESS_KEY=<REDACTED>" in auth_redacted
            and 'client_secret="<REDACTED>"' in auth_redacted
            and "private_key='<REDACTED>'" in auth_redacted
            and '"session_token":"<REDACTED>"' in auth_redacted
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
        outside_finding_bundle = root / "outside-finding-bundle-sentinel.txt"
        outside_finding_bundle.write_text("OUTSIDE_FINDING_BUNDLE_SENTINEL", encoding="utf-8")
        bundle_escape_link = runtime.registry.harness.store.root / "reports" / "smoke-bundle-outside-link.txt"
        bundle_escape_link.parent.mkdir(parents=True, exist_ok=True)
        try:
            bundle_escape_link.symlink_to(outside_finding_bundle)
        except (OSError, NotImplementedError):
            bundle_escape_link.write_text("local fallback smoke bundle evidence", encoding="utf-8")
        updated_finding = runtime.registry.run("update_finding", {
            "id": finding_id,
            "status": "confirmed",
            "evidence": [
                {"type": "note", "value": "Smoke UI screenshot evidence token=supersecret"},
                {"type": "artifact", "artifact_path": str(bundle_escape_link)},
            ],
            "append_evidence": True,
        })
        listed_findings = runtime.registry.run("list_findings", {"status": "all"})
        exported_finding = runtime.registry.run("finding_export", {"id": finding_id})
        reviewed_finding = runtime.registry.run("finding_review", {"id": finding_id})
        bundled_finding = runtime.registry.run("finding_bundle", {"id": finding_id, "out": "smoke-finding-bundle.zip"})
        cli_bundle_stdout = run_cmd("finding-bundle-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "finding-bundle", "--engagement", str(engagement_path), "--id", str(finding_id), "--out", "smoke-cli-finding-bundle.zip"])
        cli_bundle = json.loads(cli_bundle_stdout)
        write("finding-create.json", json.dumps(created_finding.to_dict(), indent=2))
        write("finding-update.json", json.dumps(updated_finding.to_dict(), indent=2))
        write("findings.json", json.dumps(listed_findings.to_dict(), indent=2))
        write("finding-export.json", json.dumps(exported_finding.to_dict(), indent=2))
        write("finding-review.json", json.dumps(reviewed_finding.to_dict(), indent=2))
        write("finding-bundle.json", json.dumps(bundled_finding.to_dict(), indent=2))
        finding_markdown = Path(exported_finding.artifacts.get("markdown", "")).read_text(encoding="utf-8") if exported_finding.artifacts.get("markdown") else ""
        finding_review_markdown = Path(reviewed_finding.artifacts.get("markdown", "")).read_text(encoding="utf-8") if reviewed_finding.artifacts.get("markdown") else ""
        finding_bundle_path = Path(bundled_finding.artifacts.get("zip", ""))
        finding_bundle_names: set[str] = set()
        finding_bundle_blob = b""
        finding_bundle_manifest = {}
        if finding_bundle_path.exists():
            with zipfile.ZipFile(finding_bundle_path) as archive:
                finding_bundle_names = set(archive.namelist())
                finding_bundle_blob = b"\n".join(archive.read(name) for name in finding_bundle_names if not name.endswith("/"))
                finding_bundle_manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
        checks["finding_lifecycle_ok"] = created_finding.status == "ok" and updated_finding.data["finding"]["status"] == "confirmed" and "Exposed administrative interface" in json.dumps(listed_findings.to_dict()) and "Tool run" in finding_markdown
        checks["finding_review_ok"] = reviewed_finding.status == "ok" and reviewed_finding.data["review"]["readiness"] in {"ready_with_advisories", "ready_for_operator_review"} and "Phobos Finding Review" in finding_review_markdown and "supersecret" not in json.dumps(reviewed_finding.to_dict()) and "supersecret" not in finding_review_markdown
        checks["finding_evidence_bundle_ok"] = (
            bundled_finding.status == "ok"
            and cli_bundle.get("status") == "ok"
            and bundled_finding.data.get("no_target_activity") is True
            and bundled_finding.data.get("raw_file_contents_emitted") is False
            and {"BUNDLE_README.md", "MANIFEST.json", "finding/finding.md", "finding/review.md", "finding/finding.json"}.issubset(finding_bundle_names)
            and any(name.startswith("evidence/agent/tool-runs/") for name in finding_bundle_names)
            and any("outside evidence root" in str(item.get("reason", "")) for item in finding_bundle_manifest.get("skipped", []) if isinstance(item, dict))
            and b"supersecret" not in finding_bundle_blob
            and b"OUTSIDE_FINDING_BUNDLE_SENTINEL" not in finding_bundle_blob
            and "supersecret" not in cli_bundle_stdout
        )
        current_tool_detail = runtime.registry.run("get_tool_run", {"id": nmap_structured.data["run_id"]})
        current_finding_detail = runtime.registry.run("get_finding", {"id": finding_id})
        other_detail_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-detail-smoke"))
        try:
            other_tool = other_detail_runtime.registry.run("nmap_scan", {"target": "10.10.0.6", "stdout": "80/tcp open http nginx"})
            other_finding = other_detail_runtime.registry.run("create_finding", {"title": "Other session detail sentinel", "tool_run_ids": str(other_tool.data.get("run_id"))})
            other_run_id = int(other_tool.data["run_id"])
            other_finding_id = int(other_finding.data["finding"]["id"])
            cross_tool_detail = runtime.registry.run("get_tool_run", {"id": other_run_id})
            cross_finding_detail = runtime.registry.run("get_finding", {"id": other_finding_id})
            cross_update = runtime.registry.run("update_finding", {"id": other_finding_id, "status": "confirmed"})
            cross_export = runtime.registry.run("finding_export", {"id": other_finding_id})
            cross_review = runtime.registry.run("finding_review", {"id": other_finding_id})
            cross_bundle = runtime.registry.run("finding_bundle", {"id": other_finding_id})
            cross_link_probe = runtime.registry.run("create_finding", {"title": "Cross-session link probe", "tool_run_ids": str(other_run_id)})
            reverse_tool_detail = other_detail_runtime.registry.run("get_tool_run", {"id": nmap_structured.data["run_id"]})
            reverse_finding_detail = other_detail_runtime.registry.run("get_finding", {"id": finding_id})
            session_bound_detail = {
                "current_tool_detail": current_tool_detail.to_dict(),
                "current_finding_detail": current_finding_detail.to_dict(),
                "cross_tool_detail": cross_tool_detail.to_dict(),
                "cross_finding_detail": cross_finding_detail.to_dict(),
                "cross_update": cross_update.to_dict(),
                "cross_export": cross_export.to_dict(),
                "cross_review": cross_review.to_dict(),
                "cross_bundle": cross_bundle.to_dict(),
                "cross_link_probe": cross_link_probe.to_dict(),
                "reverse_tool_detail": reverse_tool_detail.to_dict(),
                "reverse_finding_detail": reverse_finding_detail.to_dict(),
            }
        finally:
            other_detail_runtime.close()
        write("session-bound-detail.json", json.dumps(session_bound_detail, indent=2))
        checks["session_bound_finding_tool_detail_ok"] = (
            current_tool_detail.status == "ok"
            and current_finding_detail.status == "ok"
            and cross_tool_detail.status == "error"
            and cross_finding_detail.status == "error"
            and cross_update.status == "error"
            and cross_export.status == "error"
            and cross_review.status == "error"
            and cross_bundle.status == "error"
            and "not found in this session" in json.dumps(session_bound_detail)
            and (cross_link_probe.data.get("finding", {}).get("evidence") == [])
            and reverse_tool_detail.status == "error"
            and reverse_finding_detail.status == "error"
        )

        storage_run_id = runtime.store.create_tool_run(
            runtime.session_id,
            "httpx_probe",
            "https://app.example.test token=storage-smoke-secret",
            "httpx -json https://app.example.test token=storage-smoke-secret",
            "parsed",
            decision={"status": "allow", "api_key": "storage-smoke-secret", "reason": "token=storage-smoke-secret"},
            parsed={"responses": [{"url": "https://app.example.test", "title": "token=storage-smoke-secret", "headers": {"token": "storage-smoke-secret"}}]},
            metadata={"token": "storage-smoke-secret", "note": "secret=storage-smoke-secret"},
        )
        storage_finding_id = runtime.store.create_finding(
            runtime.session_id,
            "Stored finding token=storage-smoke-secret",
            severity="Medium",
            status="needs-evidence",
            description="Description includes password=storage-smoke-secret for redaction testing.",
            impact="Impact includes secret=storage-smoke-secret for redaction testing.",
            recommendation="Recommendation includes api_key=storage-smoke-secret for redaction testing.",
            evidence=[{"type": "tool_run", "id": storage_run_id, "note": "token=storage-smoke-secret", "api_key": "storage-smoke-secret"}],
            tags="token=storage-smoke-secret",
        )
        runtime.store.update_finding(
            storage_finding_id,
            session_id=runtime.session_id,
            description="Updated description secret=storage-smoke-secret",
            evidence=[{"type": "manual", "note": "password=storage-smoke-secret", "token": "storage-smoke-secret"}],
        )
        raw_storage_tool = runtime.store.conn.execute(
            "SELECT target, command, decision_json, parsed_json, metadata_json FROM tool_runs WHERE id=?",
            (storage_run_id,),
        ).fetchone()
        raw_storage_finding = runtime.store.conn.execute(
            "SELECT title, description, impact, recommendation, evidence_json, tags FROM findings WHERE id=?",
            (storage_finding_id,),
        ).fetchone()
        storage_detail = {
            "raw_tool": dict(raw_storage_tool) if raw_storage_tool else {},
            "raw_finding": dict(raw_storage_finding) if raw_storage_finding else {},
            "tool_detail": runtime.registry.run("get_tool_run", {"id": storage_run_id}).to_dict(),
            "finding_detail": runtime.registry.run("get_finding", {"id": storage_finding_id}).to_dict(),
        }
        storage_blob = json.dumps(storage_detail, sort_keys=True)
        write("finding-tool-run-storage-redaction.json", json.dumps(storage_detail, indent=2, sort_keys=True))
        checks["finding_tool_run_storage_redaction_ok"] = "storage-smoke-secret" not in storage_blob and "<REDACTED>" in storage_blob

        outside_artifact = root / "outside-artifact-output.md"
        outside_bundle_artifact = root / "outside-finding-bundle.zip"
        artifact_escape = runtime.registry.run("finding_review", {"id": finding_id, "out": str(outside_artifact)})
        bundle_artifact_escape = runtime.registry.run("finding_bundle", {"id": finding_id, "out": str(outside_bundle_artifact)})
        scoped_briefing = runtime.registry.run("operator_briefing", {"out": "containment-briefing.md"})
        write("artifact-output-escape.json", json.dumps({"finding_review": artifact_escape.to_dict(), "finding_bundle": bundle_artifact_escape.to_dict()}, indent=2))
        write("artifact-output-scoped.json", json.dumps(scoped_briefing.to_dict(), indent=2))
        briefing_dir = (runtime.registry.harness.store.root / "agent" / "briefings").resolve()
        scoped_path = Path(scoped_briefing.artifacts.get("markdown", "")).resolve() if scoped_briefing.artifacts.get("markdown") else Path("/")
        checks["artifact_output_containment_ok"] = (
            artifact_escape.status == "error"
            and "escapes" in artifact_escape.message
            and bundle_artifact_escape.status == "error"
            and "escapes" in bundle_artifact_escape.message
            and not outside_artifact.exists()
            and not outside_bundle_artifact.exists()
            and scoped_briefing.status == "ok"
            and os.path.commonpath([str(briefing_dir), str(scoped_path)]) == str(briefing_dir)
        )

        started = runtime.registry.run(
            "start_process",
            {"target": "app.example.test", "type": "host", "purpose": "background parity smoke token=supersecret", "command": "printf 'bg-parity-ok token=supersecret'", "execute": True},
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
        process_detail = runtime.registry.run("get_process", {"id": process_id})
        raw_process_row = runtime.store.conn.execute("SELECT command, purpose, decision_json FROM processes WHERE id=?", (process_id,)).fetchone()
        raw_process_text = "".join(str(raw_process_row[key] or "") for key in ["command", "purpose", "decision_json"]) if raw_process_row else ""
        write("process-poll.json", json.dumps(polled.to_dict(), indent=2))
        write("process-wait.json", json.dumps(waited.to_dict(), indent=2))
        write("process-log.json", json.dumps(log.to_dict(), indent=2))
        write("process-detail.json", json.dumps(process_detail.to_dict(), indent=2))
        checks["background_process_completed"] = polled.status == "completed" and waited.status == "completed" and "bg-parity-ok" in log.data.get("stdout", "")
        checks["wait_process_ok"] = waited.status == "completed" and "bg-parity-ok" in waited.data.get("stdout", "")
        process_storage_blob = json.dumps({"start": started.to_dict(), "poll": polled.to_dict(), "wait": waited.to_dict(), "log": log.to_dict(), "detail": process_detail.to_dict(), "raw": raw_process_text})
        checks["process_detail_storage_redaction_ok"] = process_detail.status == "ok" and "token=<REDACTED>" in process_storage_blob and "supersecret" not in process_storage_blob

        process_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-process-smoke"))
        try:
            other_process = process_scope_runtime.registry.run("start_process", {"target": "app.example.test", "type": "host", "purpose": "other session process scope", "command": "sleep 5", "execute": True})
            other_process_id = int(other_process.data.get("process_id", 0)) if other_process.data.get("process_id") else 0
            cross_process_results = {
                "start": other_process.to_dict(),
                "poll": runtime.registry.run("poll_process", {"id": other_process_id}).to_dict(),
                "log": runtime.registry.run("process_log", {"id": other_process_id}).to_dict(),
                "wait": runtime.registry.run("wait_process", {"id": other_process_id, "timeout": 0}).to_dict(),
                "detail": runtime.registry.run("get_process", {"id": other_process_id}).to_dict(),
                "kill": runtime.registry.run("kill_process", {"id": other_process_id}).to_dict(),
                "owner_poll_after_cross_kill": process_scope_runtime.registry.run("poll_process", {"id": other_process_id}).to_dict(),
            }
        finally:
            for process in process_scope_runtime.store.list_processes(process_scope_runtime.session_id, limit=10):
                process_scope_runtime.registry.run("kill_process", {"id": process["id"]})
            process_scope_runtime.close()
        write("session-bound-process.json", json.dumps(cross_process_results, indent=2))
        process_scope_ok = (
            other_process_id > 0
            and all(cross_process_results[name]["status"] == "error" for name in ["poll", "log", "wait", "detail", "kill"])
            and "not found in this session" in json.dumps(cross_process_results)
            and cross_process_results["owner_poll_after_cross_kill"]["status"] != "error"
        )

        job = handle("job", '/job name=memory-check schedule=manual prompt="/recall query=smoke-client"')
        due = runtime.run_due_jobs()
        write("run-due.json", json.dumps(due, indent=2))
        job_id = int(due[0]["job_id"]) if due else 0
        job_detail = runtime.registry.run("get_job", {"id": job_id})
        job_update = runtime.registry.run("update_job", {"id": job_id, "name": "memory-check token=supersecret", "prompt": "/recall query=smoke-client token=supersecret", "enabled": False})
        disabled_due = runtime.run_due_jobs()
        job_enable = runtime.registry.run("enable_job", {"id": job_id})
        job_disable = runtime.registry.run("disable_job", {"id": job_id})
        job_list = runtime.registry.run("list_jobs", {})
        other_job_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-job-smoke"))
        try:
            other_job = other_job_runtime.registry.run("schedule_job", {"name": "Other job token=supersecret", "prompt": "/status token=supersecret", "schedule": "manual"})
            other_job_id = int(other_job.data.get("job_id", 0)) if other_job.data.get("job_id") else 0
            cross_job_detail = runtime.registry.run("get_job", {"id": other_job_id})
            cross_job_disable = runtime.registry.run("disable_job", {"id": other_job_id})
            owner_job_detail = other_job_runtime.registry.run("get_job", {"id": other_job_id})
        finally:
            other_job_runtime.close()
        job_control_results = {
            "detail": job_detail.to_dict(),
            "update": job_update.to_dict(),
            "enable": job_enable.to_dict(),
            "disable": job_disable.to_dict(),
            "list": job_list.to_dict(),
            "disabled_due": disabled_due,
            "cross_detail": cross_job_detail.to_dict(),
            "cross_disable": cross_job_disable.to_dict(),
            "owner_detail": owner_job_detail.to_dict(),
        }
        write("job-controls.json", json.dumps(job_control_results, indent=2))
        review = handle("subagents", '/subagents prompt="Review controlled IDOR evidence" roles=scope,safety,report')
        checks["jobs_and_subagents"] = "Scheduled job" in job and due and "ACME parity" in due[0]["response"] and "Subagent review complete" in review
        checks["job_controls_session_bound_redacted_ok"] = (
            job_detail.status == "ok"
            and job_update.status == "ok"
            and job_update.data.get("job", {}).get("enabled") is False
            and disabled_due == []
            and job_enable.data.get("job", {}).get("enabled") is True
            and job_disable.data.get("job", {}).get("enabled") is False
            and job_list.data.get("secret_values_redacted") is True
            and cross_job_detail.status == "error"
            and cross_job_disable.status == "error"
            and "not found in this session" in json.dumps(job_control_results)
            and owner_job_detail.status == "ok"
            and owner_job_detail.data.get("job", {}).get("enabled") is True
            and "supersecret" not in json.dumps(job_control_results)
            and "token=<REDACTED>" in json.dumps(job_control_results)
        )

        add_task = handle("task-add", '/task-add content="Review parity smoke token=supersecret" status=pending')
        update_task = handle("task-update", "/task-update id=1 status=completed")
        task_detail = handle("task-detail", "/task-detail id=1")
        task_list = handle("tasks", "/tasks status=all")
        auto_task = handle("auto-task", '/auto apply=true prompt="task: verify handoff import"')
        raw_task_row = runtime.store.conn.execute("SELECT content, metadata_json FROM tasks WHERE id=1").fetchone()
        raw_task_text = "".join(str(raw_task_row[key] or "") for key in ["content", "metadata_json"]) if raw_task_row else ""
        checks["task_board_roundtrip"] = "Task 1 added" in add_task and '"status": "completed"' in update_task and "Task 1 returned" in task_detail and "Review parity smoke" in task_list and '"tool": "add_task"' in auto_task
        task_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-task-smoke"))
        try:
            other_task = task_scope_runtime.registry.run("add_task", {"content": "Other session task scope sentinel", "status": "pending"})
            other_task_id = int(other_task.data.get("task", {}).get("id", 0))
            cross_task_update = runtime.registry.run("update_task", {"id": other_task_id, "status": "completed"})
            cross_task_detail = runtime.registry.run("get_task", {"id": other_task_id})
            unchanged_task = task_scope_runtime.store.get_task(other_task_id, session_id=task_scope_runtime.session_id) or {}
            cross_task_results = {"other_task": other_task.to_dict(), "cross_update": cross_task_update.to_dict(), "cross_detail": cross_task_detail.to_dict(), "owner_task_after_cross_update": unchanged_task}
        finally:
            task_scope_runtime.close()
        write("session-bound-task.json", json.dumps(cross_task_results, indent=2))
        task_scope_ok = other_task_id > 0 and cross_task_update.status == "error" and cross_task_detail.status == "error" and "not found in this session" in cross_task_update.message + cross_task_detail.message and unchanged_task.get("status") == "pending"
        checks["session_bound_task_process_ok"] = bool(process_scope_ok and task_scope_ok)
        task_storage_blob = json.dumps({"add": add_task, "update": update_task, "detail": task_detail, "list": task_list, "raw": raw_task_text})
        checks["task_detail_storage_redaction_ok"] = "token=<REDACTED>" in task_storage_blob and "supersecret" not in task_storage_blob

        compact = handle("compact", "/compact limit=80")
        context = handle("context", "/context query=smoke-client limit=8")
        checks["context_compacted"] = "Context summary" in compact and "Context snapshot" in context

        lcm_node = runtime.registry.run("context_compact_node", {"title": "Smoke LCM parity", "limit": 80, "parent": True})
        write("lcm-compact.json", json.dumps(lcm_node.to_dict(), indent=2))
        node_id = int(lcm_node.data["node_id"])
        lcm_describe = runtime.registry.run("context_describe", {"id": node_id})
        lcm_expand = runtime.registry.run("context_expand", {"id": node_id})
        lcm_query = runtime.registry.run("context_query", {"query": "smoke-client"})
        context_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-context-smoke"))
        try:
            foreign_message_id = context_scope_runtime.store.append_message(context_scope_runtime.session_id, "user", "foreign-context-scope-secret")
            foreign_node_id = context_scope_runtime.store.create_context_node(
                context_scope_runtime.session_id,
                "Foreign smoke LCM node",
                "foreign-context-scope-secret",
                sources=[{"type": "message", "id": foreign_message_id}],
            )
            context_scope_runtime.store.create_context_node(
                context_scope_runtime.session_id,
                "Foreign smoke child",
                "foreign-context-child-secret",
                parent_id=node_id,
                depth=1,
            )
        finally:
            context_scope_runtime.close()
        lcm_cross_describe = runtime.registry.run("context_describe", {"id": foreign_node_id})
        lcm_cross_expand = runtime.registry.run("context_expand", {"id": foreign_node_id})
        lcm_owned_describe_after_foreign_child = runtime.registry.run("context_describe", {"id": node_id})
        write("lcm-describe.json", json.dumps(lcm_describe.to_dict(), indent=2))
        write("lcm-expand.json", json.dumps(lcm_expand.to_dict(), indent=2))
        write("lcm-query.json", json.dumps(lcm_query.to_dict(), indent=2))
        write("lcm-session-scope.json", json.dumps({
            "foreign_node_id": foreign_node_id,
            "cross_describe": lcm_cross_describe.to_dict(),
            "cross_expand": lcm_cross_expand.to_dict(),
            "owned_describe_after_foreign_child": lcm_owned_describe_after_foreign_child.to_dict(),
        }, indent=2))
        checks["lcm_context_nodes_ok"] = lcm_node.status == "ok" and lcm_describe.status == "ok" and lcm_expand.status == "ok" and lcm_query.status == "ok" and bool(lcm_expand.data.get("expanded_sources"))
        lcm_scope_serialized = json.dumps({
            "cross_describe": lcm_cross_describe.to_dict(),
            "cross_expand": lcm_cross_expand.to_dict(),
            "owned_describe_after_foreign_child": lcm_owned_describe_after_foreign_child.to_dict(),
        })
        checks["session_bound_context_nodes_ok"] = (
            lcm_cross_describe.status == "error"
            and lcm_cross_expand.status == "error"
            and "not found in this session" in lcm_cross_describe.message
            and lcm_owned_describe_after_foreign_child.status == "ok"
            and "foreign-context-scope-secret" not in lcm_scope_serialized
            and "foreign-context-child-secret" not in lcm_scope_serialized
        )

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
        delegation_id = int(delegation.data.get("delegation", {}).get("id", 0)) if delegation.data.get("delegation") else 0
        delegation_detail = runtime.registry.run("get_delegation", {"id": delegation_id})
        other_delegation_id = runtime.store.create_delegation("foreign-delegation-smoke", "foreign delegation token=supersecret", [{"role": "scope", "prompt": "foreign delegation token=supersecret"}])
        runtime.store.complete_delegation(
            other_delegation_id,
            "ok",
            [{"role": "scope", "content": "foreign delegation token=supersecret"}],
            {"note": "foreign delegation artifact token=supersecret", "api_key": "foreign-delegation-key"},
            session_id="foreign-delegation-smoke",
        )
        cross_complete_delegation = runtime.store.complete_delegation(
            other_delegation_id,
            "error",
            [{"role": "scope", "content": "cross delegation mutation token=supersecret"}],
            {"note": "cross delegation artifact token=supersecret"},
            session_id=runtime.session_id,
        )
        raw_delegation_row = runtime.store.conn.execute(
            "SELECT status, prompt, tasks_json, results_json, artifacts_json FROM delegations WHERE id=?",
            (other_delegation_id,),
        ).fetchone()
        raw_delegation = dict(raw_delegation_row) if raw_delegation_row else {}
        raw_delegation_text = "".join(str(raw_delegation.get(key) or "") for key in ["prompt", "tasks_json", "results_json", "artifacts_json"])
        cross_delegation_detail = runtime.registry.run("get_delegation", {"id": other_delegation_id})
        write("delegation.json", json.dumps(delegation.to_dict(), indent=2))
        write("delegations.json", json.dumps(delegation_list.to_dict(), indent=2))
        write("delegation-storage.json", json.dumps({"cross_complete": cross_complete_delegation, "raw_delegation": raw_delegation}, indent=2))
        child_session_ids = [item.get("child_session_id") for item in delegation.data.get("delegation", {}).get("results", [])]
        checks["delegation_batches_ok"] = delegation.status == "ok" and delegation_list.data.get("delegations") and Path(delegation.artifacts.get("summary", "")).exists()
        checks["isolated_delegation_sessions_ok"] = len([sid for sid in child_session_ids if sid]) == 2 and all(sid != runtime.session_id for sid in child_session_ids)
        checks["delegation_detail_session_bound_ok"] = delegation_detail.status == "ok" and cross_delegation_detail.status == "error" and "not found in this session" in cross_delegation_detail.message and "supersecret" not in json.dumps(cross_delegation_detail.to_dict())
        checks["delegation_storage_redaction_ok"] = (
            cross_complete_delegation is None
            and raw_delegation.get("status") == "ok"
            and "supersecret" not in raw_delegation_text
            and "cross delegation mutation" not in raw_delegation_text
            and "<REDACTED>" in raw_delegation_text
        )

        auth = runtime.registry.run("auth_status", {})
        write("auth-status.json", json.dumps(auth.to_dict(), indent=2))
        checks["auth_status_redacted_ok"] = auth.status == "ok" and auth.data.get("secret_values_redacted") is True and "smoke-passphrase-for-sealed-export" not in json.dumps(auth.to_dict())

        preflight = runtime.registry.run("safety_preflight", {"out": "smoke-preflight.md"})
        cli_preflight_stdout = run_cmd("preflight-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "preflight", "--engagement", str(engagement_path), "--out", "smoke-cli-preflight.md"])
        cli_preflight = json.loads(cli_preflight_stdout)
        write("safety-preflight.json", json.dumps(preflight.to_dict(), indent=2))
        preflight_path = Path(preflight.artifacts.get("markdown", ""))
        preflight_markdown = preflight_path.read_text(encoding="utf-8") if preflight_path.exists() else ""
        checks["safety_preflight_ok"] = (
            preflight.status == "ok"
            and preflight.data.get("readiness") in {"ready", "review"}
            and preflight.data.get("no_target_activity") is True
            and preflight.data.get("secret_values_redacted") is True
            and "Phobos Safety Preflight" in preflight_markdown
            and cli_preflight.get("status") == "ok"
            and "smoke-passphrase-for-sealed-export" not in json.dumps(preflight.to_dict()) + preflight_markdown + cli_preflight_stdout
        )

        media_source.write_text("media proof token=supersecret", encoding="utf-8")
        media_import = runtime.registry.run("media_import", {"path": str(media_source)})
        media_list = runtime.registry.run("media_list", {})
        media_id = int(media_import.data.get("media", {}).get("id", 0)) if media_import.data.get("media") else 0
        media_detail = runtime.registry.run("media_get", {"id": media_id})
        other_media_id = runtime.store.create_media_artifact("foreign-media-smoke", "file", "/tmp/foreign-media-token-supersecret.txt", "/tmp/foreign-media-token-supersecret.txt", "text/plain", "0" * 64, 1, {"note": "foreign media token=supersecret"})
        cross_media_detail = runtime.registry.run("media_get", {"id": other_media_id})
        write("media-import.json", json.dumps(media_import.to_dict(), indent=2))
        write("media-list.json", json.dumps(media_list.to_dict(), indent=2))
        checks["media_artifacts_ok"] = media_import.status == "ok" and media_list.data.get("media") and Path(media_import.artifacts.get("file", "")).exists()
        checks["media_detail_session_bound_ok"] = media_detail.status == "ok" and media_detail.data.get("media", {}).get("no_file_content_read") is True and cross_media_detail.status == "error" and "not found in this session" in cross_media_detail.message and "supersecret" not in json.dumps(cross_media_detail.to_dict())

        preflight_rel = preflight_path.relative_to(runtime.registry.harness.store.root).as_posix() if preflight_path.exists() else "agent/preflight/missing.md"
        local_ref_results = {
            "task": runtime.registry.run("resolve_local_ref", {"ref": "task:1"}),
            "process": runtime.registry.run("resolve_local_ref", {"ref": f"process:{process_id}"}),
            "job": runtime.registry.run("resolve_local_ref", {"ref": f"job:{job_id}"}),
            "audit": runtime.registry.run("resolve_local_ref", {"ref": f"audit:{storage_audit_id}"}),
            "finding": runtime.registry.run("resolve_local_ref", {"ref": f"finding:{finding_id}"}),
            "tool_run": runtime.registry.run("resolve_local_ref", {"ref": f"tool-run:{nmap_structured.data['run_id']}"}),
            "delegation": runtime.registry.run("resolve_local_ref", {"ref": f"delegation:{delegation_id}"}),
            "media": runtime.registry.run("resolve_local_ref", {"ref": f"media:{media_id}"}),
            "context": runtime.registry.run("resolve_local_ref", {"ref": f"context-node:{node_id}"}),
            "preflight": runtime.registry.run("resolve_local_ref", {"ref": f"preflight:{preflight_rel}"}),
            "cross_task": runtime.registry.run("resolve_local_ref", {"ref": f"task:{other_task_id}"}),
            "blocked_artifact": runtime.registry.run("resolve_local_ref", {"ref": "artifact:../outside.txt"}),
            "symlink_artifact": runtime.registry.run("resolve_local_ref", {"ref": "artifact:outside-pack-link.txt"}) if pack_symlink_created else runtime.registry.run("resolve_local_ref", {"ref": "artifact:agent/preflight/missing-symlink-check.txt"}),
        }
        local_ref_auto = handle("local-ref-auto", '/auto apply=true prompt="show task:1"')
        local_ref_payload = {name: result.to_dict() for name, result in local_ref_results.items()} | {"auto": local_ref_auto}
        write("local-ref-resolver.json", json.dumps(local_ref_payload, indent=2))
        checks["local_ref_resolver_ok"] = (
            all(local_ref_results[name].status == "ok" for name in ["task", "process", "job", "audit", "finding", "tool_run", "delegation", "media", "context", "preflight"])
            and local_ref_results["preflight"].data.get("artifact", {}).get("no_file_content_emitted") is True
            and local_ref_results["cross_task"].status == "error"
            and "not found in this session" in local_ref_results["cross_task"].message
            and local_ref_results["blocked_artifact"].status == "blocked"
            and (not pack_symlink_created or local_ref_results["symlink_artifact"].status == "blocked")
            and '"tool": "resolve_local_ref"' in local_ref_auto
            and "supersecret" not in json.dumps(local_ref_payload)
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(local_ref_payload)
        )

        audit_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="audit-scope-foreign"))
        try:
            foreign_audit_id = audit_scope_runtime.store.audit(audit_scope_runtime.session_id, "foreign_audit_probe", {"token": "foreign-audit-secret"})
            audit_detail = runtime.registry.run("get_audit", {"id": storage_audit_id})
            audit_slash = handle("audit-detail", f"/audit-detail id={storage_audit_id}")
            audit_ref = runtime.registry.run("resolve_local_ref", {"ref": f"audit:{storage_audit_id}"})
            audit_cross = runtime.registry.run("get_audit", {"id": foreign_audit_id})
            audit_owner = audit_scope_runtime.registry.run("get_audit", {"id": foreign_audit_id})
        finally:
            audit_scope_runtime.close()
        audit_detail_payload = {"detail": audit_detail.to_dict(), "slash": audit_slash, "ref": audit_ref.to_dict(), "cross": audit_cross.to_dict(), "owner": audit_owner.to_dict()}
        write("audit-detail.json", json.dumps(audit_detail_payload, indent=2, sort_keys=True))
        checks["audit_detail_session_bound_redacted_ok"] = (
            audit_detail.status == "ok"
            and audit_ref.status == "ok"
            and audit_cross.status == "error"
            and audit_owner.status == "ok"
            and "not found in this session" in json.dumps(audit_detail_payload)
            and "storage-audit-secret" not in json.dumps(audit_detail_payload)
            and "storage-audit-bearer" not in json.dumps(audit_detail_payload)
            and "foreign-audit-secret" not in json.dumps(audit_detail_payload)
        )

        timeline = runtime.registry.run("evidence_timeline", {"limit": 300, "include_audit": True})
        write("evidence-timeline.json", json.dumps(timeline.to_dict(), indent=2))
        timeline_path = Path(timeline.artifacts.get("markdown", ""))
        timeline_text = timeline_path.read_text(encoding="utf-8") if timeline_path.exists() else ""
        timeline_categories = {entry.get("category") for entry in timeline.data.get("entries", [])}
        checks["evidence_timeline_ok"] = (
            timeline.status == "ok"
            and {"tool_run", "finding", "approval", "task", "media", "process", "audit"}.issubset(timeline_categories)
            and "Phobos Evidence Timeline" in timeline_text
            and "supersecret" not in json.dumps(timeline.to_dict())
            and "supersecret" not in timeline_text
        )

        manifest = runtime.registry.run("evidence_manifest", {"limit": 1000, "out": "smoke-manifest.json"})
        write("evidence-manifest.json", json.dumps(manifest.to_dict(), indent=2))
        manifest_path = Path(manifest.artifacts.get("markdown", ""))
        manifest_text = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
        manifest_hashes = {entry.get("sha256") for entry in manifest.data.get("entries", [])}
        checks["evidence_manifest_ok"] = (
            manifest.status == "ok"
            and manifest.data.get("no_target_activity") is True
            and manifest.data.get("secret_values_redacted") is True
            and any(len(str(digest or "")) == 64 for digest in manifest_hashes)
            and "Phobos Evidence Manifest" in manifest_text
            and "supersecret" not in json.dumps(manifest.to_dict())
            and "supersecret" not in manifest_text
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest.to_dict()) + manifest_text
            and (not pack_symlink_created or any(item.get("reason") == "symlink target outside evidence root" for item in manifest.data.get("skipped", [])))
        )

        manifest_verify = runtime.registry.run("evidence_manifest_verify", {"path": "smoke-manifest.json", "out": "smoke-manifest-verify.json", "detect_new": False})
        cli_manifest_verify_stdout = run_cmd("manifest-verify-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "manifest-verify", "--engagement", str(engagement_path), "--path", "smoke-manifest.json", "--out", "smoke-cli-manifest-verify.json", "--no-detect-new"])
        cli_manifest_verify = json.loads(cli_manifest_verify_stdout)
        write("evidence-manifest-verify.json", json.dumps(manifest_verify.to_dict(), indent=2))
        manifest_verify_path = Path(manifest_verify.artifacts.get("markdown", ""))
        manifest_verify_text = manifest_verify_path.read_text(encoding="utf-8") if manifest_verify_path.exists() else ""
        checks["evidence_manifest_verify_ok"] = (
            manifest_verify.status == "ok"
            and manifest_verify.data.get("verification_status") == "verified"
            and manifest_verify.data.get("no_target_activity") is True
            and manifest_verify.data.get("secret_values_redacted") is True
            and cli_manifest_verify.get("status") == "ok"
            and cli_manifest_verify.get("data", {}).get("verification_status") == "verified"
            and "Phobos Evidence Manifest Verification" in manifest_verify_text
            and "supersecret" not in json.dumps(manifest_verify.to_dict()) + manifest_verify_text + cli_manifest_verify_stdout
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest_verify.to_dict()) + manifest_verify_text
        )
        manifest_probe_path = Path(manifest.artifacts["json"]).parent / "smoke-manifest-missing-unsafe.json"
        manifest_probe_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_probe_path.write_text(json.dumps({
            "created_at": "2026-01-01T00:00:00Z",
            "engagement": "Smoke Manifest Probe",
            "include_agent": True,
            "entries": [
                {"path": "reports/smoke-missing-artifact.txt", "category": "finding", "bytes": 10, "sha256": "0" * 64},
                {"path": "../outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "1" * 64},
                {"path": "/tmp/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "2" * 64},
                {"path": "C:/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "3" * 64},
            ],
        }), encoding="utf-8")
        manifest_verify_probe = runtime.registry.run("evidence_manifest_verify", {"path": manifest_probe_path.name, "out": "smoke-manifest-missing-unsafe-verify.json", "detect_new": False})
        write("evidence-manifest-verify-flags.json", json.dumps(manifest_verify_probe.to_dict(), indent=2))
        manifest_verify_probe_text = Path(manifest_verify_probe.artifacts.get("markdown", "")).read_text(encoding="utf-8") if manifest_verify_probe.artifacts.get("markdown") else ""
        checks["evidence_manifest_verify_flags_ok"] = (
            manifest_verify_probe.status == "ok"
            and manifest_verify_probe.data.get("verification_status") == "changed"
            and manifest_verify_probe.data.get("counts", {}).get("missing", 0) >= 1
            and manifest_verify_probe.data.get("counts", {}).get("unsafe", 0) >= 3
            and manifest_verify_probe.data.get("no_target_activity") is True
            and "manifest entry path is not evidence-root relative" in manifest_verify_probe_text
            and "supersecret" not in json.dumps(manifest_verify_probe.to_dict()) + manifest_verify_probe_text
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest_verify_probe.to_dict()) + manifest_verify_probe_text
        )

        secret_scan_proof = runtime.registry.harness.store.root / "reports" / "secret-scan-proof.txt"
        secret_scan_proof.parent.mkdir(parents=True, exist_ok=True)
        secret_scan_proof.write_text(
            "Authorization: Bearer supersecret-smoke-token\n"
            "Cookie: sessionid=supersecret-smoke-cookie\n"
            "password=supersecret-smoke-password\n",
            encoding="utf-8",
        )
        secret_scan = runtime.registry.run("evidence_secret_scan", {"out": "smoke-secret-scan.json", "limit": 100})
        cli_secret_scan_stdout = run_cmd("secret-scan-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "secret-scan", "--engagement", str(engagement_path), "--out", "smoke-cli-secret-scan.json", "--limit", "100"])
        cli_secret_scan = json.loads(cli_secret_scan_stdout)
        secret_scan_text = Path(secret_scan.artifacts.get("markdown", "")).read_text(encoding="utf-8") if secret_scan.artifacts.get("markdown") else ""
        auto_secret_scan = handle("auto-secret-scan", '/auto apply=true prompt="scan evidence for secrets"')
        write("evidence-secret-scan.json", json.dumps(secret_scan.to_dict(), indent=2))
        checks["evidence_secret_scan_ok"] = (
            secret_scan.status == "ok"
            and secret_scan.data.get("review_status") == "review"
            and secret_scan.data.get("no_target_activity") is True
            and secret_scan.data.get("raw_file_contents_emitted") is False
            and secret_scan.data.get("secret_values_redacted") is True
            and secret_scan.data.get("counts", {}).get("total_secret_like_matches", 0) >= 3
            and cli_secret_scan.get("status") == "ok"
            and cli_secret_scan.get("data", {}).get("review_status") == "review"
            and "Phobos Evidence Secret Scan" in secret_scan_text
            and '"tool": "evidence_secret_scan"' in auto_secret_scan
            and "supersecret" not in json.dumps(secret_scan.to_dict()) + secret_scan_text + cli_secret_scan_stdout + auto_secret_scan
        )

        closeout = runtime.registry.run("closeout_review", {"out": "smoke-closeout.md"})
        cli_closeout_stdout = run_cmd("closeout-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "closeout", "--engagement", str(engagement_path), "--out", "smoke-cli-closeout.md"])
        cli_closeout = json.loads(cli_closeout_stdout)
        write("closeout-review.json", json.dumps(closeout.to_dict(), indent=2))
        closeout_path = Path(closeout.artifacts.get("markdown", ""))
        closeout_text = closeout_path.read_text(encoding="utf-8") if closeout_path.exists() else ""
        checks["closeout_review_ok"] = (
            closeout.status == "ok"
            and closeout.data.get("readiness") == "blocked"
            and closeout.data.get("summary", {}).get("pending_approvals", 0) >= 1
            and closeout.data.get("no_target_activity") is True
            and closeout.data.get("secret_values_redacted") is True
            and "Phobos Closeout Review" in closeout_text
            and cli_closeout.get("status") == "ok"
            and cli_closeout.get("data", {}).get("readiness") == "blocked"
            and "supersecret" not in json.dumps(closeout.to_dict()) + closeout_text + cli_closeout_stdout
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(closeout.to_dict()) + closeout_text
        )
        closeout_related_refs = {
            str(item.get("ref") or "")
            for check in closeout.data.get("checks", [])
            for item in (check.get("related") or [])
            if isinstance(item, dict)
        }
        checks["closeout_drilldown_links_ok"] = (
            any(ref.startswith("approval:") for ref in closeout_related_refs)
            and "artifact:agent/exports/" in closeout_related_refs
            and "## Drill-down" in closeout_text
            and closeout.data.get("summary", {}).get("drilldown_links", 0) >= 2
            and "supersecret" not in json.dumps(closeout.to_dict()) + closeout_text
        )

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
        thread_bridge_config = BridgeConfig.from_dict(
            "discord",
            {"allowed_channel_ids": ["C-smoke"], "allowed_user_ids": ["U-smoke"], "command_prefix": "!phobos", "max_response_chars": 300, "discord_thread_mode": "per-message"},
        )
        discord_thread_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="/status", channel_id="T-smoke", user_id="U-smoke", message_id="M-thread", raw={"channel_type": 11, "parent_id": "C-smoke"}),
            thread_bridge_config,
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
                attachments=[{"url": "https://example.invalid/proof.png", "mime_type": "image/png", "size": 123, "name": "token=supersecret-remote.png"}],
            ),
            BridgeConfig(platform="telegram", max_response_chars=300),
        )
        bridge_oversized = root / "bridge-oversized.bin"
        bridge_oversized.write_bytes(b"x" * 64)
        media_count_before_oversized = len(runtime.store.list_media_artifacts(runtime.session_id, limit=200))
        bridge_size_guard = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="discord",
                text="!phobos /status",
                channel_id="C-smoke",
                user_id="U-smoke",
                message_id="M-too-large",
                attachments=[{"local_path": str(bridge_oversized), "mime_type": "application/octet-stream", "name": "token=supersecret-too-large.bin"}],
            ),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300, max_attachment_bytes=8),
        )
        media_count_after_oversized = len(runtime.store.list_media_artifacts(runtime.session_id, limit=200))
        bridge_approval_block = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="!phobos /approve id=1", channel_id="C-smoke", user_id="U-smoke", message_id="M-approve"),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        write("bridge-discord.json", json.dumps(discord_bridge.to_dict(), indent=2))
        write("bridge-discord-thread.json", json.dumps(discord_thread_bridge.to_dict(), indent=2))
        write("bridge-slack.json", json.dumps(slack_bridge.to_dict(), indent=2))
        write("bridge-telegram.json", json.dumps(telegram_bridge.to_dict(), indent=2))
        write("bridge-media.json", json.dumps(bridge_media.to_dict(), indent=2))
        write("bridge-remote-metadata.json", json.dumps(bridge_remote_metadata.to_dict(), indent=2))
        write("bridge-attachment-size-guard.json", json.dumps(bridge_size_guard.to_dict(), indent=2))
        write("bridge-approval-block.json", json.dumps(bridge_approval_block.to_dict(), indent=2))
        checks["chat_response_polish_ok"] = (
            "Phobos is up" in discord_bridge.response
            and '"safety_mode": "non_destructive"' in discord_bridge.raw_response
            and '"session_id"' not in discord_bridge.response
            and discord_bridge.response != discord_bridge.raw_response
        )
        checks["bridges_offline_ok"] = (
            discord_bridge.status == "handled"
            and discord_bridge.normalized_text == "/status"
            and discord_thread_bridge.status == "handled"
            and discord_thread_bridge.normalized_text == "/status"
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
            and "supersecret" not in json.dumps(bridge_remote_metadata.to_dict())
        )
        checks["bridge_attachment_size_guard_ok"] = (
            bridge_size_guard.status == "blocked"
            and bridge_size_guard.reason == "attachment-too-large"
            and bridge_size_guard.attachments
            and bridge_size_guard.attachments[0].get("status") == "skipped"
            and bridge_size_guard.attachments[0].get("reason") == "attachment-too-large"
            and bridge_size_guard.attachments[0].get("size") == 64
            and media_count_after_oversized == media_count_before_oversized
            and "no text command was executed" in bridge_size_guard.response
            and "supersecret" not in json.dumps(bridge_size_guard.to_dict())
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
        finding_route = f"/finding?id={finding_id}"
        tool_run_route = f"/tool-run?id={nmap_structured.data['run_id']}"
        delegation_route = f"/delegation?id={delegation_id}"
        media_detail_route = f"/media-detail?id={media_id}"
        job_route = f"/job?id={job_id}"
        task_route = "/task?id=1"
        process_route = f"/process?id={process_id}"
        memory_route = f"/memory?id={storage_memory.data['id']}"
        ref_route = "/ref?ref=task:1"
        gateway_route_matrix = ["/routes", "/tools", "/schemas?name=start_process", "/scope-check?target=app.example.test", "/guardrail-test?target=app.example.test", "/sessions", "/context", "/memories?query=smoke-client", memory_route, "/memory-detail?id=%s" % storage_memory.data["id"], "/preflight", "/timeline?limit=25&include_audit=false", "/manifest?limit=50&include_agent=false", "/manifest-verify?path=smoke-manifest.json&detect_new=false", "/secret-scan?limit=50", "/closeout", ref_route, "/detail?ref=finding:%s" % finding_id, "/lcm", "/approvals", "/approval?id=1", "/audit?limit=25", "/audit-detail?id=%s" % storage_audit_id, "/tasks", task_route, "/task-detail?id=1", "/findings", finding_route, "/finding-detail?id=%s" % finding_id, "/finding-bundle?id=%s" % finding_id, "/tool-runs", tool_run_route, "/tool-run-detail?run_id=%s" % nmap_structured.data["run_id"], "/jobs", job_route, "/job-detail?id=%s" % job_id, "/processes", process_route, "/process-detail?id=%s" % process_id, "/delegations", delegation_route, "/media", media_detail_route, "/auth", "/bridges", "/guardrails"]
        for route in gateway_route_matrix:
            with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                gateway_gets[route] = json.loads(response.read().decode("utf-8"))
        invalid_gateway_expected = {
            "/timeline?limit=not-an-int": "limit must be an integer",
            "/timeline?include_audit=maybe": "include_audit must be a boolean",
            "/manifest?max_bytes=not-an-int": "max_bytes must be an integer",
            "/manifest?include_agent=perhaps": "include_agent must be a boolean",
            "/manifest-verify?path=smoke-manifest.json&detect_new=sometimes": "detect_new must be a boolean",
            f"/finding-bundle?id={finding_id}&max_bytes=not-an-int": "max_bytes must be an integer",
            "/task?id=not-an-int": "id must be an integer",
            "/tool-run?run_id=not-an-int": "id must be an integer",
            "/media-detail?media_id=not-an-int": "id must be an integer",
            "/ref?kind=artifact&id=not-an-int": "id must be an integer",
            "/ref?ref=artifact:agent/preflight/report.md&max_bytes=not-an-int": "max_bytes must be an integer",
        }
        invalid_gateway_queries: dict[str, dict[str, object]] = {}
        for route in invalid_gateway_expected:
            try:
                with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                    invalid_gateway_queries[route] = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                invalid_gateway_queries[route] = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
        invalid_gateway_post_expected = {
            "/approve": ({"id": "not-an-int"}, "id must be an integer"),
            "/deny": ({"approval_id": True}, "id must be an integer"),
            "/message": (["/status"], "JSON body must be an object"),
        }
        invalid_gateway_posts: dict[str, dict[str, object]] = {}
        for route, (body, _expected_error) in invalid_gateway_post_expected.items():
            req = urllib.request.Request(
                f"http://{host}:{port}{route}",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    invalid_gateway_posts[route] = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                invalid_gateway_posts[route] = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
        limited_gateway = None
        gateway_body_limit: dict[str, object] = {}
        try:
            limited_gateway = AgentGateway(runtime, port=0, max_body_bytes=64)
            limited_thread = threading.Thread(target=limited_gateway.serve_forever, daemon=True)
            limited_thread.start()
            limited_host, limited_port = limited_gateway.server_address
            with urllib.request.urlopen(f"http://{limited_host}:{limited_port}/health", timeout=5) as response:
                limited_health = json.loads(response.read().decode("utf-8"))
            oversized_req = urllib.request.Request(
                f"http://{limited_host}:{limited_port}/message",
                data=json.dumps({"message": "x" * 128}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(oversized_req, timeout=5) as response:
                    oversized_payload = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                oversized_payload = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
            gateway_body_limit = {"health": limited_health, "oversized": oversized_payload}
        finally:
            if limited_gateway is not None:
                limited_gateway.shutdown()
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
        invalid_tool_req = urllib.request.Request(
            f"http://{host}:{port}/tool",
            data=json.dumps({"name": "list_findings", "args": {"limit": "not-an-int"}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(invalid_tool_req, timeout=5) as response:
            gateway_invalid_tool = json.loads(response.read().decode("utf-8"))
        guardrail_update_req = urllib.request.Request(
            f"http://{host}:{port}/guardrails",
            data=json.dumps({
                "safety_mode": "standard",
                "testing_window": "business hours with client lead online",
                "notes": "Smoke guardrail UI note; no secrets.",
                "in_scope_targets": ["app.example.test", "10.10.0.0/24"],
                "allowed_techniques": ["web", "api", "service-enumeration", "offline-analysis"],
                "prohibited_techniques": ["dos", "destructive", "persistence", "evasion", "malware", "credential-dumping"],
                "stop_conditions": ["Stop before destructive actions or denial-of-service conditions.", "Stop before production state changes."],
                "confirm_tools": ["nmap_scan"],
                "blocked_tools": [],
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(guardrail_update_req, timeout=5) as response:
            gateway_guardrail_update = json.loads(response.read().decode("utf-8"))
        write("gateway-dashboard.html", dashboard)
        write("gateway-health.json", json.dumps(health, indent=2))
        write("gateway-status.json", json.dumps(gateway_status, indent=2))
        write("gateway-guardrails.json", json.dumps({"before": gateway_gets.get("/guardrails"), "after": gateway_guardrail_update}, indent=2))
        write("gateway-routes.json", json.dumps({"gets": gateway_gets, "message": gateway_message, "run_due": gateway_run_due}, indent=2))
        write("gateway-invalid-query.json", json.dumps(invalid_gateway_queries, indent=2))
        write("gateway-invalid-post.json", json.dumps(invalid_gateway_posts, indent=2))
        write("gateway-body-limit.json", json.dumps(gateway_body_limit, indent=2))
        write("gateway-tool.json", json.dumps({"valid": gateway_tool, "invalid_schema_integer": gateway_invalid_tool}, indent=2))
        preflight_route_obj = gateway_gets.get("/preflight")
        preflight_route: dict[str, object] = preflight_route_obj if isinstance(preflight_route_obj, dict) else {}
        preflight_data_obj = preflight_route.get("data")
        preflight_route_data: dict[str, object] = preflight_data_obj if isinstance(preflight_data_obj, dict) else {}
        guardrail_route_obj = gateway_gets.get("/guardrail-test?target=app.example.test")
        guardrail_route: dict[str, object] = guardrail_route_obj if isinstance(guardrail_route_obj, dict) else {}
        guardrail_data_obj = guardrail_route.get("data")
        guardrail_route_data: dict[str, object] = guardrail_data_obj if isinstance(guardrail_data_obj, dict) else {}
        manifest_route_obj = gateway_gets.get("/manifest?limit=50&include_agent=false")
        manifest_route: dict[str, object] = manifest_route_obj if isinstance(manifest_route_obj, dict) else {}
        manifest_data_obj = manifest_route.get("data")
        manifest_route_data: dict[str, object] = manifest_data_obj if isinstance(manifest_data_obj, dict) else {}
        manifest_verify_route_obj = gateway_gets.get("/manifest-verify?path=smoke-manifest.json&detect_new=false")
        manifest_verify_route: dict[str, object] = manifest_verify_route_obj if isinstance(manifest_verify_route_obj, dict) else {}
        manifest_verify_data_obj = manifest_verify_route.get("data")
        manifest_verify_route_data: dict[str, object] = manifest_verify_data_obj if isinstance(manifest_verify_data_obj, dict) else {}
        secret_scan_route_obj = gateway_gets.get("/secret-scan?limit=50")
        secret_scan_route: dict[str, object] = secret_scan_route_obj if isinstance(secret_scan_route_obj, dict) else {}
        secret_scan_data_obj = secret_scan_route.get("data")
        secret_scan_route_data: dict[str, object] = secret_scan_data_obj if isinstance(secret_scan_data_obj, dict) else {}
        closeout_route_obj = gateway_gets.get("/closeout")
        closeout_route: dict[str, object] = closeout_route_obj if isinstance(closeout_route_obj, dict) else {}
        closeout_route_data_obj = closeout_route.get("data")
        closeout_route_data: dict[str, object] = closeout_route_data_obj if isinstance(closeout_route_data_obj, dict) else {}
        approval_route = gateway_gets.get("/approval?id=1") or {}
        finding_route_payload = gateway_gets.get(finding_route) or {}
        finding_bundle_route_payload = gateway_gets.get("/finding-bundle?id=%s" % finding_id) or {}
        tool_run_route_payload = gateway_gets.get(tool_run_route) or {}
        task_route_payload = gateway_gets.get(task_route) or {}
        memory_route_payload = gateway_gets.get(memory_route) or {}
        ref_route_payload = gateway_gets.get(ref_route) or {}
        ref_route_data_obj = ref_route_payload.get("data") if isinstance(ref_route_payload, dict) else {}
        ref_route_data = ref_route_data_obj if isinstance(ref_route_data_obj, dict) else {}
        job_route_payload = gateway_gets.get(job_route) or {}
        process_route_payload = gateway_gets.get(process_route) or {}
        delegation_route_payload = gateway_gets.get(delegation_route) or {}
        media_route_payload = gateway_gets.get(media_detail_route) or {}
        audit_route_payload = gateway_gets.get("/audit-detail?id=%s" % storage_audit_id) or {}
        audit_route_data_obj = audit_route_payload.get("data") if isinstance(audit_route_payload, dict) else {}
        audit_route_data = audit_route_data_obj if isinstance(audit_route_data_obj, dict) else {}
        gateway_routes_present = all(bool(gateway_gets.get(route)) for route in gateway_route_matrix)
        checks["gateway_ok"] = "Phobos Agent Gateway" in dashboard and "Granular Guardrails" in dashboard and health.get("ok") is True and gateway_status.get("status") == "ok" and gateway_tool["result"]["data"]["echo"] == "via-gateway" and gateway_invalid_tool["result"]["status"] == "error" and gateway_invalid_tool["result"]["message"] == "limit must be an integer."
        checks["gateway_full_api_ok"] = gateway_routes_present and preflight_route_data.get("no_target_activity") is True and guardrail_route_data.get("no_target_activity") is True and guardrail_route_data.get("readiness") == "ready" and manifest_route_data.get("no_target_activity") is True and manifest_verify_route_data.get("verification_status") == "verified" and secret_scan_route_data.get("review_status") == "review" and secret_scan_route_data.get("no_target_activity") is True and closeout_route_data.get("no_target_activity") is True and '"safety_mode": "non_destructive"' in gateway_message.get("response", "") and isinstance(gateway_run_due.get("jobs_run"), list) and (approval_route or {}).get("status") == "ok" and memory_route_payload.get("status") == "ok" and ref_route_payload.get("status") == "ok" and ref_route_data.get("no_target_activity") is True and finding_route_payload.get("status") == "ok" and finding_bundle_route_payload.get("status") == "ok" and tool_run_route_payload.get("status") == "ok" and task_route_payload.get("status") == "ok" and job_route_payload.get("status") == "ok" and process_route_payload.get("status") == "ok" and delegation_route_payload.get("status") == "ok" and media_route_payload.get("status") == "ok" and "supersecret" not in json.dumps(approval_route) + json.dumps(guardrail_route) + json.dumps(manifest_verify_route) + json.dumps(secret_scan_route) + json.dumps(memory_route_payload) + json.dumps(ref_route_payload) + json.dumps(finding_route_payload) + json.dumps(finding_bundle_route_payload) + json.dumps(tool_run_route_payload) + json.dumps(task_route_payload) + json.dumps(job_route_payload) + json.dumps(process_route_payload) + json.dumps(delegation_route_payload) + json.dumps(media_route_payload)
        invalid_gateway_blob = json.dumps(invalid_gateway_queries)
        invalid_gateway_ok = True
        for route, item in invalid_gateway_queries.items():
            payload_obj = item.get("payload")
            expected_error = invalid_gateway_expected.get(route)
            if not isinstance(payload_obj, dict) or item.get("status_code") != 400 or payload_obj.get("error") != expected_error:
                invalid_gateway_ok = False
        checks["gateway_invalid_query_handling_ok"] = invalid_gateway_ok and "Traceback" not in invalid_gateway_blob
        invalid_post_blob = json.dumps(invalid_gateway_posts)
        invalid_post_ok = True
        for route, item in invalid_gateway_posts.items():
            payload_obj = item.get("payload")
            expected_error = invalid_gateway_post_expected.get(route, ({}, ""))[1]
            if not isinstance(payload_obj, dict) or item.get("status_code") != 400 or payload_obj.get("error") != expected_error:
                invalid_post_ok = False
        checks["gateway_invalid_post_handling_ok"] = invalid_post_ok and "Traceback" not in invalid_post_blob
        body_limit_health = gateway_body_limit.get("health") if isinstance(gateway_body_limit, dict) else {}
        body_limit_oversized = gateway_body_limit.get("oversized") if isinstance(gateway_body_limit, dict) else {}
        body_limit_payload = body_limit_oversized.get("payload") if isinstance(body_limit_oversized, dict) else {}
        checks["gateway_body_size_limit_ok"] = (
            isinstance(body_limit_health, dict)
            and body_limit_health.get("max_body_bytes") == 64
            and isinstance(body_limit_oversized, dict)
            and body_limit_oversized.get("status_code") == 413
            and isinstance(body_limit_payload, dict)
            and body_limit_payload.get("error") == "JSON body too large; limit is 64 bytes"
            and "Traceback" not in json.dumps(gateway_body_limit)
        )
        checks["gateway_audit_detail_route_ok"] = audit_route_payload.get("status") == "ok" and audit_route_data.get("no_target_activity") is True and "storage-audit-secret" not in json.dumps(audit_route_payload) and "storage-audit-bearer" not in json.dumps(audit_route_payload)
        checks["granular_guardrail_ui_ok"] = (
            (gateway_gets.get("/guardrails") or {}).get("engagement", {}).get("safety_mode") == "non_destructive"
            and gateway_guardrail_update.get("status") == "updated"
            and gateway_guardrail_update.get("engagement", {}).get("safety_mode") == "standard"
            and any(tool.get("name") == "nmap_scan" and tool.get("policy") == "confirm" for tool in gateway_guardrail_update.get("tools", []))
            and gateway_guardrail_update.get("persisted", {}).get("engagement") is True
            and gateway_guardrail_update.get("persisted", {}).get("runtime_policy") is True
            and EngagementROE.load(engagement_path).safety_mode == "standard"
            and EngagementROE.load(engagement_path).testing_window == "business hours with client lead online"
            and "Smoke guardrail UI note" in EngagementROE.load(engagement_path).notes
            and "nmap_scan" in AgentAppConfig.load(config_path).confirm_tools
        )

        ui_client_stdout = run_cmd("ui-client", [sys.executable, "-m", "phobos_agent.agent_cli", "ui-client", "--out", str(output / "phobos-remote-ui.html"), "--agent-url", "https://phobos-vps.example"])
        deploy_kit_dir = root / "deploy-kit"
        deploy_kit_stdout = run_cmd(
            "deploy-kit",
            [
                sys.executable,
                "-m",
                "phobos_agent.agent_cli",
                "deploy-kit",
                "--out",
                str(deploy_kit_dir),
                "--domain",
                "phobos-vps.example",
                "--agent-url",
                "https://phobos-vps.example",
                "--allow-origin",
                "https://ui.example",
                "--token-env",
                "PHOBOS_SMOKE_GATEWAY_TOKEN",
            ],
        )
        deploy_kit = json.loads(deploy_kit_stdout)
        bad_deploy_kit_dir = root / "bad-deploy-kit"
        bad_deploy_kit = subprocess.run(
            [
                sys.executable,
                "-m",
                "phobos_agent.agent_cli",
                "deploy-kit",
                "--out",
                str(bad_deploy_kit_dir),
                "--domain",
                "phobos-vps.example",
                "--token-env",
                "BAD-NAME;--unsafe-no-auth",
            ],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        write("deploy-kit-invalid.stdout.txt", bad_deploy_kit.stdout)
        write("deploy-kit-invalid.stderr.txt", bad_deploy_kit.stderr)
        deploy_service = (deploy_kit_dir / "phobos-agent.service").read_text(encoding="utf-8")
        deploy_env = (deploy_kit_dir / "phobos-agent.env.template").read_text(encoding="utf-8")
        deploy_ui = (deploy_kit_dir / "phobos-remote-ui.html").read_text(encoding="utf-8")
        deploy_readme = (deploy_kit_dir / "README.md").read_text(encoding="utf-8")
        checks["deploy_kit_ok"] = (
            deploy_kit.get("status") == "written"
            and deploy_kit.get("auth_required") is True
            and deploy_kit.get("bind_host") == "127.0.0.1"
            and deploy_kit.get("token_value_written") is False
            and "--host 127.0.0.1" in deploy_service
            and "--token-env PHOBOS_SMOKE_GATEWAY_TOKEN" in deploy_service
            and "--allow-origin https://ui.example" in deploy_service
            and "PHOBOS_SMOKE_GATEWAY_TOKEN=REPLACE_WITH_LONG_RANDOM_SECRET" in deploy_env
            and "smoke-gateway-token" not in deploy_service + deploy_env + deploy_ui + deploy_readme
            and "Phobos Agent Remote Client" in deploy_ui
            and "Authorization: Bearer &lt;token&gt;</code>" in deploy_ui
            and "not a multi-user RBAC console" in deploy_readme
            and bad_deploy_kit.returncode != 0
            and not bad_deploy_kit_dir.exists()
        )
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
        checks["pack_exported_and_redacted"] = (
            pack.status == "ok"
            and "MANIFEST.json" in names
            and "runtime/state.json" in names
            and "supersecret" not in combined
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in combined
            and (not pack_symlink_created or any(item.get("reason") == "symlink target outside evidence root" for item in pack.data.get("manifest", {}).get("skipped", [])))
        )
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
