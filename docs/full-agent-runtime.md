# Standalone Phobos Agent Runtime

The project now includes a local standalone agent runtime exposed as `phobos-agent`. It is separate from Hermes and runs on top of the pentest harness core, with offensive-security workflows, ROE awareness, evidence logging, and the user's preferred `non_destructive` default safety mode. The legacy `offsec-agent` and `offsec-harness` entry points are kept as compatibility aliases.

## Runtime components

- **Session management:** SQLite-backed sessions keyed by engagement path and session name, with schema-version metadata for local migrations; current runtime schema is v5.
- **Persistent memory:** local SQLite memory table with `/remember` and `/recall`; Hindsight-style aliases (`/hindsight-retain`, `/hindsight-recall`, `/hindsight-reflect`) store/search/synthesize through the same local memory and context stores; memory and current/cross-session search use FTS5 when available and fall back to LIKE otherwise.
- **Task board:** `/tasks`, `/task-add`, and `/task-update` provide durable local task tracking in SQLite.
- **Context recovery:** `/compact` writes model/heuristic summaries to SQLite and Markdown; `/context` returns the latest summary plus recent session state; `/lcm-compact`, `/lcm-describe`, `/lcm-expand`, `/lcm-query`, and snake_case `lcm_*` tool aliases add explicit LCM-style context nodes that can be described, expanded, queried, exported, and imported.
- **Tool registry and schemas:** every built-in/plugin tool has a named registry entry and JSON-style schema; inspect with `/tools` and `/schemas`. `/timeline` assembles a redacted evidence/action timeline across tool runs, findings, approvals, tasks, processes, media, delegations, and selected audit events; `/manifest` writes a read-only SHA-256 inventory of evidence artifacts without emitting file contents; `/closeout` composes local readiness signals into a redacted closeout review with bounded local drill-down refs and without target activity.
- **Structured scanner wrappers:** ROE-gated `nmap_scan`, `httpx_probe`, `nuclei_scan`, and `ffuf_scan` wrappers can parse captured output without scanner binaries for demos/tests, or execute only with explicit `execute=true`; every run creates durable `tool_runs` records and redacted evidence artifacts. `nuclei_scan` requires an explicit operator-selected template path for execution so default template sets are never invoked accidentally.
- **Finding lifecycle:** DB-backed findings track severity/status, narrative fields, linked tool runs, appended evidence, deterministic QA/readiness reviews, and Markdown exports for report drafting.
- **Local skills:** Hermes-style `SKILL.md` files can be discovered with `/skills`, loaded with `/skill`, preloaded from config, or grouped into bundles without loading every skill body into context.
- **Guarded auto-planner:** `/auto` converts common natural-language operator requests into explicit tool calls; optional model-assisted JSON planning and `/auto-loop` are bounded, registry-filtered, and never bypass ROE or runtime tool policy.
- **Plugin architecture:** load explicit Python plugin directories with `--plugin-dir` or `agent.config.json`; plugins expose `register(registry)` and can add tools.
- **Profiles, auth status, and preflight:** `profile-init`, `profiles`, and `--profile <name>` provide local config/DB roots; `/auth-status` checks model/bridge token env vars without revealing values; `/preflight` performs a read-only ROE/runtime readiness check and writes a redacted Markdown report.
- **Approvals:** confirm-level commands are queued in SQLite and require `/approve id=<n>` before execution/start.
- **Runtime tool policy:** config/CLI and the authenticated gateway UI/API can block or approval-gate arbitrary tool names, independent of ROE guardrails.
- **Non-destructive execution policy:** default `safety_mode` is `non_destructive`; routine active testing is allowed when in scope, while destructive/DoS/disruptive actions block and state-changing or lockout-sensitive actions queue for approval.
- **Foreground execution:** `/run` runs short ROE-gated commands when `execute=true`.
- **Background processes:** `/start`, `/poll`, `/wait`, `/log`, `/kill`, and `/processes` provide Hermes-like process management with stdout/stderr artifacts.
- **Job scheduling:** local durable job table with simple schedules such as `manual`, `every 15 m`, `every 1 h`, and `every 1 d`; run via `phobos-agent run-due` or external cron.
- **Subagent orchestration:** parallel role reviews plus durable local `/delegate` batches with per-task artifacts and child session records by default.
- **Model fallback chain:** `agent.config.json` can define ordered providers; the runtime tries them in order.
- **Workspace file tools:** `/read`, `/write`, `/workspace-search`, and `/patch-file` are constrained to the engagement workspace and resolve symlink candidates before reading/searching.
- **Media/artifact registry:** `/media-import` copies local evidence/media into the engagement evidence tree with SHA-256, size, MIME, and kind metadata; `/media-list` lists it.
- **Operator briefing, handoff, sealed snapshots, and sealed DB backups:** `/timeline` creates a redacted Markdown evidence/action chronology; `/manifest` creates JSON/Markdown SHA-256 artifact inventories for chain-of-custody review; `/closeout` reviews local ROE/preflight, approvals, tasks, findings, process state, tool runs, and artifact presence into a ready/review/blocked Markdown checklist with redacted local refs such as `approval:<id>`, `task:<id>`, `process:<id>`, `finding:<id>`, `tool-run:<id>`, and `artifact:<relative-agent-path>`; `/briefing` creates a redacted Markdown operator summary; `/handoff`/`/export-session` and `/import-session` move redacted context/tasks/memory between local DBs; `/sealed-export` and `/sealed-import` wrap handoffs in passphrase-env sealed snapshots; CLI `seal-db`/`unseal-db` creates authenticated encrypted backups of a closed SQLite DB and can remove plaintext DB/WAL/SHM files after a successful seal.
- **Local/VPS HTTP gateway:** `phobos-agent serve` exposes a simple web UI plus JSON endpoints on `127.0.0.1` by default. Remote/VPS binds require an environment-backed bearer token unless `--unsafe-no-auth` is explicitly supplied for isolated throwaway networks. The gateway includes route discovery, CORS support, a standalone `/ui-client` browser client, a validated `deploy-kit` template generator, granular guardrail/ROE policy editing, and views for schemas, preflight readiness, findings, tool runs, timelines, evidence manifests, closeout reviews, LCM nodes, jobs, processes, delegations, media, auth status, and bridge config.
- **Messaging bridges:** `phobos-agent discord`, `phobos-agent slack`, and `phobos-agent telegram` connect the same runtime to allowlisted chat surfaces while keeping tokens in environment variables, neutralizing mass-ping text in responses, importing local bridge-test attachments, recording remote attachment metadata without blind downloads, and preserving ROE/tool-policy approvals. Remote `/approve` and `/deny` are disabled by default per bridge. Bridge responses are chat-polished by default while raw runtime output is retained in local session/audit state.
- **Redacted engagement packs:** `/export-pack` and `phobos-agent export-pack` build a ZIP with redacted evidence, runtime state, and a manifest for closeout/review. Symlinked evidence paths are packaged only when their resolved target stays inside the evidence root; user-supplied artifact `out=` paths are likewise resolved before writing and must stay inside their specific `agent/` artifact directory.
- **Evidence workspace:** all target-affecting decisions and outputs are written under the engagement evidence directory, with secret redaction applied to logged commands/tool args.

## Agent commands

```text
/help
/tools
/schemas name=<optional-tool>
/tool name=<tool_name> key=value ...
/auto prompt=<natural request> apply=false execute=false model=false
/auto-loop prompt=<goal> steps=5 execute=false model=false
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
/reflect query=<question>
/hindsight-retain content=<fact> context=<label> tags=<optional>
/hindsight-recall query=<text>
/hindsight-reflect query=<question>
/search query=<text>
/search-all query=<text>
/context query=<optional> limit=8
/compact limit=40
/lcm-compact limit=60 parent=false
/lcm-describe id=<optional-node-id>
/lcm-expand id=<node-id>
/lcm-query query=<question>
/read path=<workspace-relative-file>
/write path=<workspace-relative-file> content=<text> append=false
/workspace-search query=<regex> glob="**/*.md"
/patch-file path=<file> old=<text> new=<text> replace_all=false
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/poll id=<process-id>
/wait id=<process-id> timeout=30
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals
/approve id=<approval-id>
/deny id=<approval-id> reason=<why>
/plan finding=<observed weakness>
/burp-tab target=<host> tab_name=<name> request_file=<path> mcp_url=<url> create=false
/bloodhound input=<json|dir|zip> principal=<USER@DOMAIN>
/cve component=<product> version=<version> catalog=<catalog.json> online=false
/nmap target=<host> ports=80,443 stdout=<optional-captured-output> execute=false
/httpx url=<url> stdout=<optional-jsonl-output> execute=false
/nuclei url=<url> templates=<safe-template-or-dir> stdout=<optional-jsonl-output> execute=false
/ffuf url=<url/FUZZ> wordlist=<path> stdout=<optional-json-output> execute=false
/tool-runs limit=20 tool_name=<optional>
/tool-run id=<run-id>
/finding finding_file=<finding.json>
/findings status=all
/finding-create title=<title> severity=Medium status=draft tool_run_ids=1,2
/finding-update id=<finding-id> status=confirmed append_evidence=true
/finding-get id=<finding-id>
/finding-export id=<finding-id> out=<optional.md>
/finding-review id=<finding-id> out=<optional.md>
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/delegate prompt=<task> roles=scope,safety,report
/delegations limit=20
/auth-status
/preflight out=<optional.md>
/media-import path=<local-file> kind=<optional>
/media-list
/sealed-export passphrase_env=<ENV_NAME> out=<optional.sealed.json>
/sealed-import path=<sealed.json> passphrase_env=<ENV_NAME>
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/run-due
/status
/briefing query=<optional> out=<optional.md>
/timeline limit=100 category=<optional> include_audit=true out=<optional.md>
/manifest limit=1000 max_bytes=50000000 include_agent=true out=<optional.json>
/closeout out=<optional.md>
/tasks status=all
/task-add content=<task> status=pending
/task-update id=<task-id> status=completed content=<optional>
/handoff out=<optional.json>
/export-session out=<optional.json>
/import-session path=<handoff.json> merge_memories=false
/export-pack out=<optional.zip>
/audit limit=50
```

## Start a standalone agent workspace

```bash
cd /root/Documents/Tools/phobos-agent
. .venv/bin/activate

# Create/load an engagement first.
phobos-harness init \
  --name "Client Assessment" \
  --scope app.example.test,10.10.0.0/24 \
  --safety-mode non_destructive \
  --evidence-dir evidence \
  --out engagement.json

# Optional runtime config with fallback providers, workspace, and plugins.
phobos-agent config-init --out agent.config.json

# Initialize a runtime DB/session.
phobos-agent --db data/phobos-agent.db --config agent.config.json init --engagement engagement.json

# Handle one message.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/assess target=app.example.test type=web purpose="headers" command="curl -I https://app.example.test"'

# Or enter the local chat loop.
phobos-agent --db data/phobos-agent.db --config agent.config.json chat --engagement engagement.json
```

## Config file

`phobos-agent config-init` writes a stdlib JSON config:

```json
{
  "workspace_dir": "agent-workspace",
  "operator_name": "operator",
  "assistant_style": "direct, concise, practical, evidence-first",
  "plugin_dirs": [],
  "max_context_messages": 12,
  "tool_timeout": 30,
  "auto_execute_natural": false,
  "auto_model_planning": false,
  "max_auto_steps": 5,
  "blocked_tools": [],
  "confirm_tools": [],
  "skill_dirs": [],
  "preload_skills": [],
  "skill_bundles": {},
  "bridges": {
    "discord": {"enabled": false, "token_env": "PHOBOS_DISCORD_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false, "allow_approval_actions": false, "import_attachments": true, "max_attachment_bytes": 10000000, "discord_thread_mode": "off", "discord_thread_name_prefix": "Phobos", "discord_thread_auto_archive_duration": 1440, "discord_thread_continue_without_trigger": true, "response_polish": true},
    "slack": {"enabled": false, "bot_token_env": "PHOBOS_SLACK_BOT_TOKEN", "app_token_env": "PHOBOS_SLACK_APP_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false, "allow_approval_actions": false, "import_attachments": true, "max_attachment_bytes": 10000000, "response_polish": true},
    "telegram": {"enabled": false, "token_env": "PHOBOS_TELEGRAM_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false, "allow_approval_actions": false, "import_attachments": true, "max_attachment_bytes": 10000000, "response_polish": true}
  },
  "providers": [
    {
      "provider": "heuristic",
      "model": "gpt-4o-mini",
      "base_url": null,
      "key_env": "OPENAI_API_KEY",
      "command_template": null
    }
  ]
}
```

`providers` is ordered. For example, a local OpenAI-compatible endpoint with heuristic fallback:

```json
"providers": [
  {"provider": "openai-compatible", "model": "offsec-local", "base_url": "http://127.0.0.1:11434/v1", "key_env": "OPENAI_API_KEY"},
  {"provider": "heuristic", "model": "heuristic-fallback"}
]
```

Runtime policy, local skills, and chat bridge allowlists are configured in the same file:

```json
{
  "operator_name": "Caligo",
  "assistant_style": "direct, concise, practical, evidence-first",
  "blocked_tools": ["export_pack"],
  "confirm_tools": ["operator_briefing"],
  "skill_dirs": ["./skills"],
  "preload_skills": ["finding-reporting"],
  "skill_bundles": {"reporting": ["finding-reporting"]},
  "bridges": {
    "discord": {
      "allowed_channel_ids": ["123456789012345678"],
      "allowed_user_ids": ["234567890123456789"],
      "command_prefix": "!phobos",
      "discord_thread_mode": "per-message",
      "discord_thread_name_prefix": "Phobos",
      "discord_thread_auto_archive_duration": 1440,
      "response_polish": true
    },
    "telegram": {"allowed_channel_ids": ["-1001234567890"], "allowed_user_ids": ["123456789"]}
  }
}
```

## Plugin example

A plugin is a Python file containing `register(registry)`:

```python
from offsec_agent_harness.agent_tools import ToolResult


def register(registry):
    def echo(args):
        return ToolResult("ok", "plugin echo", {"echo": args.get("value", "")})

    registry.register_tool(
        "plugin_echo",
        echo,
        {"description": "Echo from a local plugin.", "schema": {"type": "object"}},
    )
```

Load plugins with either:

```bash
phobos-agent --plugin-dir examples/plugins --db data/phobos-agent.db tools --engagement engagement.json
```

or put the directory in `agent.config.json`.

Invoke plugin tools generically:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/tool name=example_echo value=plugin-ok'
```

Plugins should keep target-affecting activity behind the built-in ROE-gated tools rather than implementing unmanaged traffic/execution paths.

## Guarded auto-planner

Use `/auto` when you want Hermes-like natural-language convenience without hiding what the agent is about to do:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/auto prompt="remember client: ACME internal assessment"'
```

Without `apply=true`, `/auto` returns a plan only. With `apply=true`, recognized non-command tools are invoked. If the plan contains `run_command` or `start_process`, the generated command still passes through normal ROE guardrails and is left as `execute=false` unless `/auto execute=true` is also supplied. Confirm-level actions still queue for approval.

## Read-only safety preflight

Run a preflight before opening a new operator session, enabling a bridge, or handing the agent to a teammate:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json preflight \
  --engagement engagement.json \
  --out operator-preflight.md
```

The same check is available as `/preflight`, generic tool `safety_preflight`, and gateway `GET /preflight`. It performs no target activity. The report checks ROE authorization/scope, default hard-stop technique classes, stop conditions, evidence/workspace paths, SQLite schema/FTS status, the plaintext live-DB caveat, core tool registration, runtime tool policy, natural-language execution flags, provider env-var presence metadata, plugin/skill directories, and enabled bridge allowlist/token-gate posture. Output is JSON plus a redacted Markdown file under `agent/preflight/`.

## Evidence manifest / chain-of-custody inventory

Use `/manifest` or the CLI command when preparing closeout, handoff, or report QA:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json evidence-manifest \
  --engagement engagement.json \
  --out closeout-manifest.json
```

The manifest is read-only and performs no target activity. It resolves every candidate artifact before `stat()`/hashing, skips symlink targets outside the engagement evidence root, writes JSON and Markdown under `agent/manifests/`, and records relative path, category, byte count, MIME, modified time, and SHA-256. It never emits file contents; secret-like values in paths or metadata are redacted before JSON/Markdown output.

## Non-destructive policy examples

```bash
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/assess target=10.10.0.5 type=service-enumeration purpose="version scan" command="nmap -sV 10.10.0.5"'
```

In the default `non_destructive` mode, routine active enumeration is allowed when it is in scope and does not match destructive/disruptive patterns.

State-changing actions still queue for approval:

```bash
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/run target=app.example.test type=web purpose="controlled test update" command="curl -X POST https://app.example.test/profile" execute=true'
```

```text
[needs_approval] Command requires approval before execution. Approval ID: 1
```

Review and approve/deny:

```bash
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approvals'
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/deny id=1 reason="outside window"'
# or, when ROE permits:
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approve id=1'
```

Destructive and denial-of-service-like commands still block and are never executed, even if an approval is attempted later.

If you want the original conservative behaviour where active scans also require approval, create the engagement with `--safety-mode standard`.

## Structured scanner wrappers and finding lifecycle

The productized runtime includes scanner-style wrapper tools for common pentest enumeration outputs. They are structured tools, not raw remote shells: target-affecting execution is still ROE-gated and requires explicit `execute=true`; parser/demo paths can pass captured `stdout` or `input_file` and do not require the scanner binary to be installed. Real scanner execution requires the binary on `PATH` (`nmap`, ProjectDiscovery `httpx`, ProjectDiscovery `nuclei`, and/or `ffuf`). `nuclei_scan` additionally requires `templates=`/`template=` when `execute=true`, which prevents accidental execution of the broad default public template set.

```bash
# Parse captured nmap-style output into a durable tool run and evidence artifact.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/nmap target=10.10.0.5 ports=80,443 stdout="80/tcp open http nginx"'

# Parse captured JSON/JSONL-style outputs from HTTP probing, nuclei, and ffuf.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/httpx url=https://app.example.test stdout="{\"url\":\"https://app.example.test\",\"status_code\":200}"'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/nuclei url=https://app.example.test templates=./safe-templates/ execute=true rate_limit=1'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/tool-runs limit=20'
```

For a local binary/readiness check that avoids customer targets, run:

```bash
python scripts/smoke_live_integrations.py --require-scanners
```

The live smoke creates a temporary local HTTP server, runs the four wrappers only against `127.0.0.1`, generates a one-request Nuclei template, writes artifacts under `demo-phobos-live/`, and checks bridge auth readiness without sending any platform messages. Its scanner lookup uses the same ProjectDiscovery `httpx` preference/`PHOBOS_HTTPX_BIN` override described above. If real bridge token env vars are present and should be mandatory, add `--require-bridge-tokens`.

When a scanner run supports a finding, create and promote a lifecycle record instead of treating every scanner hit as report-ready:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/finding-create title="Exposed administrative interface" severity=Medium status=needs-evidence tool_run_ids=1'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/finding-update id=1 status=confirmed append_evidence=true evidence="Validated with scoped admin panel screenshot"'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/finding-review id=1'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/finding-export id=1'
```

Finding statuses are intentionally lifecycle-oriented (`draft`, `needs-evidence`, `confirmed`, `resolved`, `accepted-risk`, `false-positive`) so imports/parser hits remain candidate evidence until the operator confirms impact. `/finding-review` is a deterministic, local-only QA pass: it does not execute target actions, and it writes a Markdown review that separates blocking report-readiness gaps from advisory improvements such as missing negative controls, reproduction notes, or cleanup/side-effect statements.

## Workspace, process, and context examples

```bash
# Workspace file tools are confined to the engagement workspace.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/write path=notes/scope.md content="Scope app.example.test authz notes"'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/workspace-search query=authz glob="**/*.md"'

# Workspace read/search/patch resolves symlinks and refuses paths whose real
# target leaves the engagement workspace.

# Background process management is ROE-gated and artifact-backed.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/start target=app.example.test type=host purpose="background smoke" command="printf bg-agent-ok" execute=true'

phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/processes'
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/poll id=1'
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/log id=1'

# Compact and recover session context.
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/compact limit=60'
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/context limit=6'

# Local Hindsight/LCM-style aliases over the same SQLite memory/context layer.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/hindsight-retain content="ACME durable operator note" context=engagement tags=memory'
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/hindsight-recall query=ACME'
phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/hindsight-reflect query="what do we know about ACME?"'
```

## Job example

```bash
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/job name=memory-check schedule=manual prompt="/recall query=client"'

phobos-agent --db data/phobos-agent.db run-due --engagement engagement.json
```

For recurring use, run `phobos-agent run-due` from cron/systemd/Task Scheduler. The agent itself keeps job state in SQLite.

## Task board, skills, briefing, and handoff

```bash
# Durable task board.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/task-add content="Review closeout evidence" status=pending'

phobos-agent --db data/phobos-agent.db --config agent.config.json once --engagement engagement.json --message '/tasks status=all'

# Progressive local skills from configured SKILL.md directories.
phobos-agent --skill-dir ./skills --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/skills'

phobos-agent --skill-dir ./skills --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/skill name=finding-reporting'

# Redacted operator briefing and portable handoff bundle.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/timeline limit=50 include_audit=false'

phobos-agent --db data/phobos-agent.db --config agent.config.json evidence-manifest \
  --engagement engagement.json \
  --out closeout-manifest.json

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/briefing query=client'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/handoff out=session-handoff.json'

phobos-agent --db imported/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/import-session path=evidence/<engagement>/agent/session-exports/session-handoff.json merge_memories=false'
```

## Sealed DB backup/restore

`seal-db`/`unseal-db` protect a closed SQLite DB backup with the stdlib authenticated sealed format used by Phobos snapshots. Passphrases come from environment variables and are never printed. This is useful for archiving or moving a local Phobos DB, but it is **not** transparent live SQLite page encryption.

```bash
export PHOBOS_DB_SEAL='...'

# Close running Phobos runtimes before using --remove-plaintext.
phobos-agent --db data/phobos-agent.db seal-db \
  --out data/phobos-agent.db.sealed \
  --passphrase-env PHOBOS_DB_SEAL \
  --remove-plaintext

phobos-agent --db data/phobos-agent.db unseal-db \
  --in data/phobos-agent.db.sealed \
  --passphrase-env PHOBOS_DB_SEAL \
  --overwrite

phobos-agent --db data/phobos-agent.db db-status
```

Use filesystem encryption, SQLCipher, or an equivalent deployment control if the active working DB itself must remain encrypted while the agent is running.


## Messaging bridges

Phobos can run connector processes for Discord, Slack, and Telegram. The bridges do not create a second execution path: accepted messages are normalized and passed to the same `OffSecAgentRuntime.handle_message()` path used by CLI/gateway messages, so ROE guardrails, runtime tool policy, approvals, audit logging, workspace containment, and redaction still apply.

Tokens are read only from environment variables:

```bash
export PHOBOS_DISCORD_TOKEN='...'        # Discord bot token
export PHOBOS_SLACK_BOT_TOKEN='...'      # Slack bot token, xoxb-...
export PHOBOS_SLACK_APP_TOKEN='...'      # Slack Socket Mode app token, xapp-...
export PHOBOS_TELEGRAM_TOKEN='...'       # Telegram bot token
```

Offline bridge dispatch test, no network token required:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json bridge-test \
  --engagement engagement.json \
  --platform discord \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos' \
  --channel-id <channel-or-thread-id> \
  --user-id <operator-user-id> \
  --message '!phobos /status'
```

Offline bridge media/voice test, still no platform token required:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json bridge-test \
  --engagement engagement.json \
  --platform discord \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos' \
  --channel-id <channel-or-thread-id> \
  --user-id <operator-user-id> \
  --message '!phobos /media-list' \
  --attachment-local-path ./operator-note.ogg \
  --attachment-mime audio/ogg \
  --attachment-kind voice
```

Local attachment paths are imported through the existing `media_import` tool. Remote-only platform attachment references are recorded as redacted metadata and are not downloaded automatically.

Run live bridges:

```bash
# Discord Gateway bridge. The bot needs the Message Content intent if you want normal text commands in guild channels.
# Add --discord-thread-mode per-message for Hermes-like top-level request threads;
# the bot then also needs Create Public Threads and Send Messages in Threads.
phobos-agent --db data/phobos-agent.db --config agent.config.json discord \
  --engagement engagement.json \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos' \
  --discord-thread-mode per-message

# Slack Socket Mode bridge. Enable Socket Mode on the Slack app and provide both xapp and xoxb tokens.
phobos-agent --db data/phobos-agent.db --config agent.config.json slack \
  --engagement engagement.json \
  --allow-channel <channel-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos'

# Telegram long-polling bridge.
phobos-agent --db data/phobos-agent.db --config agent.config.json telegram \
  --engagement engagement.json \
  --allow-channel <chat-id> \
  --allow-user <operator-user-id>
```

For non-private channels, use `--allow-channel` plus optional `--allow-user`, or explicit `--allow-all`; a user allowlist alone does not authorize arbitrary public channels. The safe default accepts only private messages when no allowlist is configured. `--prefix` and `--mention-required` reduce accidental activation in busy channels. `/approve` and `/deny` are blocked by default over bridges; opt in only with `allow_approval_actions=true` or `--allow-approval-actions` after weighing chat-account compromise risk. Bot tokens and platform payloads are never written to config by `config-init`.

## Local HTTP gateway

Start a local gateway:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json serve \
  --engagement engagement.json \
  --host 127.0.0.1 \
  --port 8765
```

Endpoints:

```text
GET  /              local web dashboard
GET  /ui-client     standalone browser client for local/VPS gateway use
GET  /health
GET  /routes
GET  /status
GET  /preflight
GET  /tools
GET  /schemas?name=<optional-tool>
GET  /sessions
GET  /context
GET  /timeline?limit=100&include_audit=false
GET  /manifest?limit=1000&include_agent=true
GET  /evidence-manifest?limit=1000&include_agent=true
GET  /closeout
GET  /closeout-review
GET  /lcm
GET  /tasks
GET  /findings
GET  /tool-runs
GET  /jobs
GET  /processes
GET  /approvals
GET  /delegations
GET  /media
GET  /auth
GET  /bridges
GET  /guardrails
GET  /audit
POST /message   {"message": "/tools"}
POST /tool      {"name": "tool_name", "args": {}}
POST /finding   {"title": "Finding title", "severity": "Medium", "description": "..."}
POST /guardrails {"safety_mode": "standard", "confirm_tools": ["nmap_scan"], "blocked_tools": []}
POST /approve   {"id": 1, "by": "gateway"}
POST /deny      {"id": 1, "by": "gateway", "reason": "outside window"}
POST /run-due   {}
```

The dashboard and remote browser client include a **Granular Guardrails** editor. It can adjust `safety_mode`, scope targets, allowed/prohibited techniques, testing windows, stop conditions, and operator notes, and per-tool `confirm_tools` / `blocked_tools`. ROE fields persist to the engagement JSON. Tool policy persists to `agent.config.json` when the runtime was started with `--config`; otherwise the tool policy applies to the running session and the API response warns that it is in-memory only.

Bind to localhost unless you have a clear reason to expose the agent on another interface.

### VPS / remote browser client

For a VPS-hosted agent, keep the browser UI separate from the running agent and make remote access explicit and authenticated:

```bash
# Generate a static browser client you can host separately or open locally.
phobos-agent ui-client \
  --out phobos-remote-ui.html \
  --agent-url https://phobos-vps.example

# Generate a deploy kit with static UI, systemd unit, nginx reverse-proxy stub,
# .env.example, and operator README. This writes files; it does not install them.
# Inputs are validated as simple hostnames/URLs/service identifiers before any
# templates are written, and only token env-var names/placeholders are emitted.
phobos-agent deploy-kit \
  --out phobos-deploy-kit \
  --domain phobos-vps.example \
  --agent-url https://phobos-vps.example \
  --port 8765

# On the VPS, bind publicly only with a long random token from an env var.
export PHOBOS_GATEWAY_TOKEN='use-a-long-random-secret-from-your-password-manager'
phobos-agent --db data/phobos-agent.db --config agent.config.json serve \
  --engagement engagement.json \
  --host 0.0.0.0 \
  --port 8765 \
  --token-env PHOBOS_GATEWAY_TOKEN \
  --allow-origin https://your-ui-origin.example
```

`/health` remains unauthenticated so load balancers and operators can confirm liveness, but operational endpoints require `Authorization: Bearer <token>` when a token is configured. Non-local binds refuse to start without `--token-env` unless `--unsafe-no-auth` is supplied; that override is only for isolated throwaway test networks. For real VPS deployments, put the stdlib gateway behind a firewall plus TLS reverse proxy, VPN, or SSH tunnel. Do not expose it directly as a multi-user production web application.

### Bridge doctor

`bridge-doctor` checks platform token/API readiness without connecting long-lived bridge streams or sending chat messages:

```bash
phobos-agent bridge-doctor --platform discord --platform slack --platform telegram
```

It reports token env presence and basic auth metadata using redacted output. Missing token env vars are reported as `status: missing`; this is expected on machines where live bridge credentials have not been supplied.

## Verified smoke coverage

Final verification for the standalone runtime was run from `/root/Documents/Tools/phobos-agent`:

```text
python -m compileall -q src tests examples/plugins scripts
python -m unittest discover -s tests -v

Ran 42 tests
OK
```

The committed Hermes-like local parity smoke demo is:

```bash
python scripts/smoke_hermes_parity.py
```

It recreates `demo-phobos-parity/` with `agent.config.json`, `phobos-parity.engagement.json`, `data/phobos-agent.db`, `output/`, local skills, workspace files, evidence, an operator briefing, a session handoff, and a redacted closeout pack. The smoke assertions passed for:

```text
PHOBOS AGENT PARITY SMOKE SUMMARY
profile_cli_ok=True
default_non_destructive=True
config_written=True
agent_init_ok=True
tools_include_core_plugin_and_new_parity=True
schema_version_ok=True
db_schema_counts_ok=True
local_skills_ok=True
schema_returned=True
plugin_loaded_and_executed=True
natural_response_polish_ok=True
auto_memory_recall=True
auto_loop_ok=True
workspace_roundtrip_and_escape_block=True
workspace_symlink_escape_block=True
guardrails_execution_approvals_blocks=True
structured_tool_wrappers_ok=True
finding_lifecycle_ok=True
finding_review_ok=True
artifact_output_containment_ok=True
background_process_completed=True
wait_process_ok=True
jobs_and_subagents=True
task_board_roundtrip=True
context_compacted=True
lcm_context_nodes_ok=True
hindsight_lcm_aliases_ok=True
delegation_batches_ok=True
isolated_delegation_sessions_ok=True
auth_status_redacted_ok=True
safety_preflight_ok=True
media_artifacts_ok=True
evidence_timeline_ok=True
evidence_manifest_ok=True
closeout_review_ok=True
closeout_drilldown_links_ok=True
sealed_snapshot_roundtrip_ok=True
db_seal_at_rest_roundtrip_ok=True
redacted_exports_not_db_encryption_ok=True
operator_briefing_created=True
session_export_import_roundtrip=True
tool_policy_confirm_and_block=True
chat_response_polish_ok=True
bridges_offline_ok=True
bridge_media_voice_ok=True
gateway_ok=True
gateway_full_api_ok=True
granular_guardrail_ui_ok=True
deploy_kit_ok=True
remote_vps_ui_auth_ok=True
pack_exported_and_redacted=True
no_legacy_public_terms_ok=True
db_exists=True
artifact_count=208
pack=/root/Documents/Tools/phobos-agent/demo-phobos-parity/evidence/phobos-agent-parity-smoke/agent/exports/closeout-pack.zip
```



Live local integration smoke is available as `scripts/smoke_live_integrations.py`. It verifies scanner binary resolution and real wrapper execution against only a temporary `127.0.0.1` HTTP server; it uses a generated one-request Nuclei template and never sends chat messages. Current local run with scanner execution required produced:

```text
PHOBOS LIVE INTEGRATION SMOKE SUMMARY
bridge_doctor_ran=True
live_bridge_auth_ready=missing-or-error
live_bridge_no_message_send=True
scanner_binaries_present=True
scanner_wrapper_live_execution_ok=True
scanner_wrapper_live_artifacts_ok=True
safety_posture_preserved=True
```

`live_bridge_auth_ready=missing-or-error` reflects this machine's current environment: Discord/Slack/Telegram token env vars were not set during verification. Re-run with `--require-bridge-tokens` after setting `PHOBOS_DISCORD_TOKEN`, `PHOBOS_SLACK_BOT_TOKEN`, `PHOBOS_SLACK_APP_TOKEN`, and/or `PHOBOS_TELEGRAM_TOKEN` to make live platform auth mandatory.

Representative smoke outputs are stored under `demo-phobos-parity/output/`:

```text
active-scan-assess.txt
agent-init.stdout.txt
approvals.txt
auth-status.json
auto-apply.txt
auto-loop.txt
auto-loop-recall.txt
auto-plan.txt
auto-recall.txt
bridge-approval-block.json
bridge-discord.json
bridge-media.json
bridge-remote-metadata.json
bridge-slack.json
bridge-telegram.json
compact.txt
config-init.stdout.txt
context.txt
closeout-cli.command.txt
closeout-cli.stderr.txt
closeout-cli.stdout.txt
closeout-review.json
delegation.json
delegations.json
deploy-kit.stdout.txt
deploy-kit-invalid.stderr.txt
db-seal.stdout.txt
db-unseal.stdout.txt
db-unseal-recall.stdout.txt
db-unseal-wrong.stderr.txt
destructive-block.txt
dos-block.txt
gateway-dashboard.html
gateway-health.json
gateway-routes.json
gateway-status.json
gateway-guardrails.json
gateway-tool.json
remote-gateway-auth.json
ui-client.stdout.txt
hindsight-retain.json
hindsight-recall.json
hindsight-reflect.json
lcm-alias.json
lcm-compact.json
lcm-describe.json
lcm-expand.json
lcm-query.json
legacy-term-grep.txt
media-import.json
media-list.json
evidence-manifest.json
nmap-structured.json
httpx-structured.json
nuclei-structured.json
ffuf-structured.json
tool-runs.json
finding-create.json
finding-update.json
findings.json
finding-export.json
finding-review.json
artifact-output-escape.json
artifact-output-scoped.json
operator-briefing.json
pack-export.json
plugin-echo.txt
policy-approved.json
policy-block.json
policy-confirm.json
process-log.json
process-poll.json
process-start.json
process-wait.json
profile-init.stdout.txt
profiles.stdout.txt
schema-start-process.txt
sealed-export.json
sealed-import.json
sealed-missing.json
session-export.json
session-import.json
skill-load.txt
skills.txt
smoke-summary.txt
status.txt
task-add.txt
task-update.txt
tasks.txt
tools.txt
workspace-escape.txt
workspace-patch.txt
workspace-read.txt
workspace-search.txt
workspace-write.txt
```

## Current limitations

This is now a real local Hermes-like offsec agent runtime, but it is still not a full production Hermes replacement. Missing or intentionally minimal areas include:

- Discord/Slack/Telegram bridges are implemented as local connector processes, but live operation still requires operator-created platform apps/bots, tokens in environment variables, and channel/user allowlists;
- bridge media handling imports explicit local files and records remote platform attachment metadata, but does not blindly download remote attachments or transcribe voice/audio;
- web UI is intentionally minimal and single-operator oriented, not a production multi-user console; remote/VPS use requires bearer-token auth plus TLS/reverse proxy, firewall, VPN, or SSH tunnel controls, and there is no RBAC/session management;
- `/auto` has deterministic planning plus optional model-returned JSON plans and a bounded `/auto-loop`, but it is not Hermes' full native function-calling autonomy or general-purpose task computer;
- local `/delegate` persists batches, artifacts, and child session records, but it is not Hermes' true isolated subagent runtime with separate tool/terminal sandboxes;
- sealed snapshots and `seal-db`/`unseal-db` provide authenticated passphrase-env protected exports/backups; this is not transparent live SQLite page encryption unless the operator also uses filesystem encryption, SQLCipher, or another deployment control;
- Phobos now has explicit LCM-style context nodes and Hindsight-style aliases over local memory/context, but it does not implement Hermes' live long-context compression DAG or full Hindsight/Obsidian memory system;

The important pieces for a standalone pentest agent are working: sessions, memory, Hindsight aliases, task board, local skills, context snapshots/compaction, LCM-style context nodes, tool schemas, structured scanner wrapper evidence, finding lifecycle records, plugin loading, runtime policy, approvals, foreground/background process handling, jobs, model fallback, subagent role reviews, durable local delegation batches with child sessions, media/artifact import, bridge media metadata/import, auth/profile status, operator briefings, handoff export/import, sealed portable snapshots, sealed DB backup/restore, authenticated local/VPS gateway/dashboard and remote browser client, Discord/Slack/Telegram bridge dispatch, ROE-gated non-destructive execution, evidence logging, and the pentest-specific tools.
