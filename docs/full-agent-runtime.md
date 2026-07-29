# Standalone Phobos Agent Runtime

The project now includes a local standalone agent runtime exposed as `phobos-agent`. It is separate from Hermes and runs on top of the pentest harness core, with offensive-security workflows, ROE awareness, evidence logging, and the user's preferred `non_destructive` default safety mode. The legacy `offsec-agent` and `offsec-harness` entry points are kept as compatibility aliases.

## Runtime components

- **Session management:** SQLite-backed sessions keyed by engagement path and session name, with schema-version metadata for local migrations; current runtime schema is v3.
- **Persistent memory:** local SQLite memory table with `/remember` and `/recall`; memory and session search use FTS5 when available and fall back to LIKE otherwise.
- **Task board:** `/tasks`, `/task-add`, and `/task-update` provide durable local task tracking in SQLite.
- **Context recovery:** `/compact` writes model/heuristic summaries to SQLite and Markdown; `/context` returns the latest summary plus recent session state.
- **Tool registry and schemas:** every built-in/plugin tool has a named registry entry and JSON-style schema; inspect with `/tools` and `/schemas`.
- **Local skills:** Hermes-style `SKILL.md` files can be discovered with `/skills`, loaded with `/skill`, preloaded from config, or grouped into bundles without loading every skill body into context.
- **Guarded auto-planner:** `/auto` converts common natural-language operator requests into explicit tool calls; it never bypasses ROE and does not execute commands unless `execute=true` is supplied.
- **Plugin architecture:** load explicit Python plugin directories with `--plugin-dir` or `agent.config.json`; plugins expose `register(registry)` and can add tools.
- **Approvals:** confirm-level commands are queued in SQLite and require `/approve id=<n>` before execution/start.
- **Runtime tool policy:** config/CLI can block or approval-gate arbitrary tool names, independent of ROE guardrails.
- **Non-destructive execution policy:** default `safety_mode` is `non_destructive`; routine active testing is allowed when in scope, while destructive/DoS/disruptive actions block and state-changing or lockout-sensitive actions queue for approval.
- **Foreground execution:** `/run` runs short ROE-gated commands when `execute=true`.
- **Background processes:** `/start`, `/poll`, `/log`, `/kill`, and `/processes` provide Hermes-like process management with stdout/stderr artifacts.
- **Job scheduling:** local durable job table with simple schedules such as `manual`, `every 15 m`, `every 1 h`, and `every 1 d`; run via `phobos-agent run-due` or external cron.
- **Subagent orchestration:** parallel role reviews for scope, safety, evidence, impact, CVE, and report-writing roles.
- **Model fallback chain:** `agent.config.json` can define ordered providers; the runtime tries them in order.
- **Workspace file tools:** `/read`, `/write`, `/workspace-search`, and `/patch-file` are constrained to the engagement workspace.
- **Operator briefing and handoff:** `/briefing` creates a redacted Markdown operator summary; `/handoff`/`/export-session` and `/import-session` move redacted context/tasks/memory between local DBs.
- **Local HTTP gateway:** `phobos-agent serve` exposes a simple web UI plus JSON endpoints on `127.0.0.1` by default.
- **Messaging bridges:** `phobos-agent discord`, `phobos-agent slack`, and `phobos-agent telegram` connect the same runtime to allowlisted chat surfaces while keeping tokens in environment variables and preserving ROE/tool-policy approvals.
- **Redacted engagement packs:** `/export-pack` and `phobos-agent export-pack` build a ZIP with redacted evidence, runtime state, and a manifest for closeout/review.
- **Evidence workspace:** all target-affecting decisions and outputs are written under the engagement evidence directory, with secret redaction applied to logged commands/tool args.

## Agent commands

```text
/help
/tools
/schemas name=<optional-tool>
/tool name=<tool_name> key=value ...
/auto prompt=<natural request> apply=false execute=false
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
/search query=<text>
/context query=<optional> limit=8
/compact limit=40
/read path=<workspace-relative-file>
/write path=<workspace-relative-file> content=<text> append=false
/workspace-search query=<regex> glob="**/*.md"
/patch-file path=<file> old=<text> new=<text> replace_all=false
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/poll id=<process-id>
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals
/approve id=<approval-id>
/deny id=<approval-id> reason=<why>
/plan finding=<observed weakness>
/burp-tab target=<host> tab_name=<name> request_file=<path> mcp_url=<url> create=false
/bloodhound input=<json|dir|zip> principal=<USER@DOMAIN>
/cve component=<product> version=<version> catalog=<catalog.json> online=false
/finding finding_file=<finding.json>
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/run-due
/status
/briefing query=<optional> out=<optional.md>
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
  "plugin_dirs": [],
  "max_context_messages": 12,
  "tool_timeout": 30,
  "auto_execute_natural": false,
  "blocked_tools": [],
  "confirm_tools": [],
  "skill_dirs": [],
  "preload_skills": [],
  "skill_bundles": {},
  "bridges": {
    "discord": {"enabled": false, "token_env": "PHOBOS_DISCORD_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false},
    "slack": {"enabled": false, "bot_token_env": "PHOBOS_SLACK_BOT_TOKEN", "app_token_env": "PHOBOS_SLACK_APP_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false},
    "telegram": {"enabled": false, "token_env": "PHOBOS_TELEGRAM_TOKEN", "allowed_channel_ids": [], "allowed_user_ids": [], "command_prefix": "", "mention_required": false, "allow_all": false}
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
  "blocked_tools": ["export_pack"],
  "confirm_tools": ["operator_briefing"],
  "skill_dirs": ["./skills"],
  "preload_skills": ["finding-reporting"],
  "skill_bundles": {"reporting": ["finding-reporting"]},
  "bridges": {
    "discord": {"allowed_channel_ids": ["123456789012345678"], "allowed_user_ids": ["234567890123456789"], "command_prefix": "!phobos"},
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

## Workspace, process, and context examples

```bash
# Workspace file tools are confined to the engagement workspace.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/write path=notes/scope.md content="Scope app.example.test authz notes"'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/workspace-search query=authz glob="**/*.md"'

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
  --message '/briefing query=client'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/handoff out=session-handoff.json'

phobos-agent --db imported/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/import-session path=evidence/<engagement>/agent/session-exports/session-handoff.json merge_memories=false'
```


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

Run live bridges:

```bash
# Discord Gateway bridge. The bot needs the Message Content intent if you want normal text commands in guild channels.
phobos-agent --db data/phobos-agent.db --config agent.config.json discord \
  --engagement engagement.json \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos'

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

For non-private channels, use `--allow-channel`/`--allow-user` or explicit `--allow-all`; the safe default accepts only private messages when no allowlist is configured. `--prefix` and `--mention-required` reduce accidental activation in busy channels. Bot tokens and platform payloads are never written to config by `config-init`.

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
GET  /health
GET  /status
GET  /tools
GET  /sessions
GET  /context
GET  /approvals
GET  /audit
GET  /tasks
POST /message   {"message": "/tools"}
POST /tool      {"name": "tool_name", "args": {}}
POST /run-due   {}
```

Bind to localhost unless you have a clear reason to expose the agent on another interface.

## Verified smoke coverage

Final verification for the standalone runtime was run from `/root/Documents/Tools/phobos-agent`:

```text
python -m compileall -q src tests examples/plugins scripts
python -m unittest discover -s tests -v

Ran 28 tests in 3.882s
OK
```

The committed Hermes-clone smoke demo is:

```bash
python scripts/smoke_hermes_parity.py
```

It recreates `demo-phobos-parity/` with `agent.config.json`, `phobos-parity.engagement.json`, `data/phobos-agent.db`, `output/`, local skills, workspace files, evidence, an operator briefing, a session handoff, and a redacted closeout pack. The smoke assertions passed for:

```text
PHOBOS AGENT PARITY SMOKE SUMMARY
default_non_destructive=True
config_written=True
agent_init_ok=True
tools_include_core_plugin_and_new_parity=True
schema_version_ok=True
local_skills_ok=True
schema_returned=True
plugin_loaded_and_executed=True
auto_memory_recall=True
workspace_roundtrip_and_escape_block=True
guardrails_execution_approvals_blocks=True
background_process_completed=True
jobs_and_subagents=True
task_board_roundtrip=True
context_compacted=True
operator_briefing_created=True
session_export_import_roundtrip=True
tool_policy_confirm_and_block=True
bridges_offline_ok=True
gateway_ok=True
pack_exported_and_redacted=True
db_exists=True
artifact_count=79
pack=/root/Documents/Tools/phobos-agent/demo-phobos-parity/evidence/phobos-agent-parity-smoke/agent/exports/closeout-pack.zip
```

Representative smoke outputs are stored under `demo-phobos-parity/output/`:

```text
active-scan-assess.txt
agent-init.stdout.txt
approvals.txt
auto-apply.txt
auto-plan.txt
auto-recall.txt
compact.txt
config-init.stdout.txt
context.txt
destructive-block.txt
dos-block.txt
gateway-dashboard.html
gateway-health.json
gateway-status.json
gateway-tool.json
operator-briefing.json
pack-export.json
plugin-echo.txt
policy-approved.json
policy-block.json
policy-confirm.json
bridge-discord.json
bridge-slack.json
bridge-telegram.json
process-log.json
process-poll.json
process-start.json
schema-start-process.txt
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

This is now a real local Hermes-like offsec agent runtime, but it is still not a full production clone of Hermes. Missing or intentionally minimal areas include:

- Discord/Slack/Telegram bridges are implemented as local connector processes, but live operation still requires operator-created platform apps/bots, tokens in environment variables, and channel/user allowlists;
- web UI is intentionally minimal/local, not a production console;
- deterministic slash-command grammar plus a guarded heuristic `/auto` planner, not a full LLM function-calling planner;
- no distributed worker pool beyond local background processes and role subagent reviews;
- no encrypted database layer yet;
- context compaction is explicit via `/compact`, not a live long-context DAG comparable to Hermes LCM.

The important pieces for a standalone pentest agent are working: sessions, memory, task board, local skills, context snapshots/compaction, tool schemas, plugin loading, runtime policy, approvals, foreground/background execution, jobs, model fallback, subagent role reviews, operator briefings, handoff export/import, local gateway/dashboard, Discord/Slack/Telegram bridge dispatch, ROE-gated non-destructive execution, evidence logging, and the pentest-specific tools.
