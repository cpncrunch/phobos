# Standalone Phobos Agent Runtime

The project now includes a local standalone agent runtime exposed as `phobos-agent`. It is separate from Hermes and runs on top of the pentest harness core, with offensive-security workflows, ROE awareness, evidence logging, and the user's preferred `non_destructive` default safety mode. The legacy `offsec-agent` and `offsec-harness` entry points are kept as compatibility aliases.

## Runtime components

- **Session management:** SQLite-backed sessions keyed by engagement path and session name, with schema-version metadata for local migrations; current runtime schema is v5.
- **Persistent memory:** local SQLite memory table with `/remember`, `/recall`, `/memories`, `/memory`, and `/forget`; Hindsight-style aliases (`/hindsight-retain`, `/hindsight-recall`, `/hindsight-reflect`) store/search/synthesize through the same local memory and context stores; memory list/detail/delete controls support local hygiene without target activity, memory keys/values/tags are redacted before SQLite writes, and memory plus current/cross-session search use FTS5 when available and fall back to LIKE otherwise.
- **Task board:** `/tasks`, `/task-detail`, `/task-add`, and `/task-update` provide durable local task tracking in SQLite with redacted current-session detail views.
- **Context recovery:** `/compact` writes model/heuristic summaries to SQLite and Markdown; `/context` returns the latest summary plus recent session state; `/lcm-compact`, `/lcm-describe`, `/lcm-expand`, `/lcm-query`, and snake_case `lcm_*` tool aliases add explicit LCM-style context nodes that can be described, expanded, queried, exported, and imported. Context summary/node text, sources, and metadata are redacted before SQLite writes. Node describe/expand by integer ID is scoped to the active session.
- **Tool registry and schemas:** every built-in/plugin tool has a named registry entry and JSON-style schema; inspect with `/tools` and `/schemas`. Config and bridge scalar parsing is strict enough that string `false`/`off` values stay false and malformed booleans/integers fail with clean config errors before runtime startup. The generic registry boundary validates schema-declared string, integer, number, integer/number minimum/maximum, string/array/object size bounds, string patterns (including env-var-name arguments such as sealed snapshot passphrase env refs), array item schemas, nested object properties, nested required fields, nested enum/bound violations, boolean, required, blank required scalar, enum, and `additionalProperties: false` closed-object extra arguments before dispatch or approval queueing, so malformed paths/targets/env refs, malformed IDs/limits, non-integral integer values such as `limit=1.5`, out-of-range limits/byte caps/log-tail sizes/timeouts/rates, ambiguous numeric strings such as `threshold=nan`, ambiguous truthy strings such as `execute=maybe`, invalid lifecycle states, and invalid output ordering return clean operator errors instead of Python exception text, accidental execution, silent integer truncation, or replayable bad approval records. `/scope`/`scope_check` gives operators a read-only ROE summary plus optional target-to-scope match decision before they queue scanner or command work; scope matching normalizes URL rules, userinfo/path/query fragments, explicit host ports, wildcard host:port rules, CIDR ranges, and bracketed IPv6 literals without doing target activity. `/guardrail-test`/`guardrail_selftest` runs synthetic allow/confirm/block simulations through the live guardrail engine without executing commands or sending traffic. `/timeline` assembles a redacted evidence/action timeline across tool runs, findings, approvals, tasks, processes, media, delegations, and selected audit events; `/manifest` writes a read-only SHA-256 inventory of evidence artifacts without emitting file contents; `/manifest-verify` re-hashes a prior manifest to flag changed, missing, unsafe, or new local artifacts; `/secret-scan` scans local evidence-root text artifacts for secret-like material with redacted previews only; `/closeout` composes local readiness signals into a redacted closeout review with bounded local drill-down refs; `/ref`/`/detail` resolves those refs to session-bound metadata without target activity.
- **Structured scanner wrappers:** ROE-gated `nmap_scan`, `httpx_probe`, `nuclei_scan`, and `ffuf_scan` wrappers can parse captured output without scanner binaries for demos/tests, or execute only with explicit `execute=true`; native model-planned scanner-wrapper calls are forced back to `execute=false` unless the operator supplied `/auto execute=true`; every run creates durable, session-bound `tool_runs` records and redacted evidence artifacts. Tool-run targets, commands, decisions, parsed data, and metadata are redacted before SQLite storage. `nuclei_scan` requires an explicit operator-selected template path for execution so it never runs the broad default template set accidentally.
- **Finding lifecycle records:** `/finding-create`, `/finding-update`, `/finding-get`, `/findings`, `/finding-export`, `/finding-review`, and `/finding-bundle` persist, review, export, and package candidate/reportable findings. Scanner-imported evidence stays candidate/non-reportable until the operator moves a finding to `confirmed`, `resolved`, or `accepted-risk`. Finding fields and evidence refs are redacted before SQLite storage; finding bundles include only redacted generated files plus safely linked text evidence.
- **Local skills:** Hermes-style `SKILL.md` files can be discovered with `/skills`, loaded with `/skill`, preloaded from config, or grouped into bundles without loading every skill body into context.
- **Guarded auto-planner:** `/auto` converts common natural-language operator requests into explicit tool calls; `phobos-agent auto` and `phobos-agent auto-loop` expose the same dry-run-first native tool-call boundaries from the public CLI; optional model-assisted planning accepts JSON-content plans even when providers wrap them in fenced/prose output, and OpenAI-compatible Chat-Completions, direct OpenAI Responses API, Gemini GenerateContent function calls, and Anthropic Messages `tool_use` blocks (including streaming-style choice-delta fragments that assemble split argument JSON before validation, including nested `functionCall`/`toolUse` fragment aliases, nested `functionCall`/`toolUse` wrappers inside tool-call entries, nested function calls, single-object top-level `tool_calls`, singular `tool_call` aliases, camelCase `toolCalls`/`toolCall` aliases, flattened top-level `name`/`arguments` variants, provider tool-name aliases such as `toolName`/`functionName`, and argument aliases such as `arguments_json`/`inputJson`), top-level or list/single-object content-block `tool_use`/`toolUse`/`function_call`/`functionCall`, `content.parts` `toolUse`/`functionCall` objects, Responses-style top-level `output`/`function_call` including single-object `output` shims, nested `function`/`functionCall` output items, typed or typeless direct or nested `output[].message` `tool_calls`/`toolCalls`/`tool_call`/`toolCall`/`functionCall`/`functionCalls`/`function_calls` aliases, and `output[].message.content` `function_call`/`tool_use`/`functionCall` blocks (including nested Gemini-style `parts` `functionCall` blocks), candidate list-or-single `parts` `functionCall`, root-level `message` wrappers carrying `tool_calls`/aliases plus content `functionCall` and nested `parts` `functionCall` blocks, `choices[].message` `toolUse`/`toolUses`/`tool_use`/`tool_uses` aliases, root or `choices[].message` `functionCall`/`functionCalls`/`function_calls` aliases (including flat, nested `function`, and nested `functionCall` items), or legacy `function_call` payloads through the configured provider fallback chain, preserves provider tool-call IDs (`id`, `call_id`, `tool_call_id`, `tool_use_id`, `callId`, `toolCallId`, or `toolUseId`) in plan/result ledgers, ignores provider-side `tool_result`/`functionResponse` echoes instead of summarizing or dispatching them, rejects custom/freeform/provider-hosted native calls such as `custom_tool_call`, `server_tool_use`, and `mcp_tool_use` without surfacing their input, receives bounded redacted runtime context, and keeps `/auto-loop` bounded, registry-filtered, schema-validated, ROE-guarded, and runtime-policy-aware. Native slash flags are parsed explicitly, target-affecting plans get read-only guardrail previews, explicit natural-message auto-execution is tagged as `trigger=natural_auto` in audit/transcript metadata and still keeps command/process execution dry-run unless an explicit slash `execute=true` path is used, `confirm_tools`/`blocked_tools` annotations appear in redacted execution ledgers, approval-control tools are hidden from model specs and rejected if returned, confirm-gated plans execute only after direct `/approve`, one-shot `/auto` plan/apply transcripts include a bounded redacted planner/provider trace, each applied loop step records an execution-ledger delta plus a redacted planner/provider trace beside the global ledger, machine-readable execution summaries separate claimable command/process activity from dry-runs, approvals, blocks, handler errors, and local-only completions, repeated or same-step duplicate model plans stop before dispatch/re-dispatch of the same call, post-feedback terminal no-tool model responses stop the loop without deterministic re-planning from the original prompt, post-feedback provider failures stop with an explicit `model_error` state, post-feedback all-invalid model plans stop with `invalid_plan` before dispatch, explicit max-step budget exhaustion is surfaced in payloads/chat/transcripts, and transcripts/chat/gateway summaries never claim tool or command execution unless the registry result proves it.
- **Plugin architecture:** load explicit Python plugin directories with `--plugin-dir` or `agent.config.json`; plugins expose `register(registry)` and can add tools.
- **Profiles, auth status, preflight, and guardrail self-tests:** `profile-init`, `profiles`, and `--profile <name>` provide local config/DB roots; `/auth-status` checks model/bridge token env vars without revealing values; `/preflight` performs a read-only ROE/runtime readiness check and writes a redacted Markdown report; `/guardrail-test` writes a redacted Markdown simulation report under `agent/guardrails/`.
- **Approvals:** confirm-level commands are queued in SQLite, `/approval id=<n>` returns redacted current-session detail for review, and `/approve id=<n>` is required before execution/start. Approval args/results are redacted before SQLite storage; if redaction changed the queued arguments, replay is blocked so the operator can re-submit fresh execution input instead of running an altered command. Approval lookup and resolution helpers accept the active `session_id`, so future gateway/CLI replay surfaces inherit the same ownership boundary instead of relying on caller-side filtering.
- **Runtime tool policy:** config/CLI and the authenticated gateway UI/API can block or approval-gate arbitrary tool names, independent of ROE guardrails.
- **Non-destructive execution policy:** default `safety_mode` is `non_destructive`; routine active testing is allowed when in scope, while destructive/DoS/disruptive actions block and state-changing or lockout-sensitive actions queue for approval.
- **Foreground execution:** `/run` runs short ROE-gated commands when `execute=true`.
- **Background processes:** `/start`, `/poll`, `/wait`, `/log`, `/kill`, `/process-detail`, and `/processes` provide Hermes-like process management with stdout/stderr artifacts and redacted current-session drill-down views.
- **Job scheduling:** local durable job table with simple schedules such as `manual`, `every 15 m`, `every 1 h`, and `every 1 d`; redacted session-bound detail/update/enable/disable controls; run via `phobos-agent run-due` or external cron.
- **Subagent orchestration:** parallel role reviews plus durable local `/delegate` batches with session-bound detail/completion paths, per-task artifacts, and child session records by default. `delegate_tasks sandbox=process` runs tasks through separate bounded stdlib worker processes with redacted worker input/output artifacts, per-task child workspaces, and parent-only SQLite completion. Delegation prompts, task specs, results, and artifact metadata are redacted before SQLite storage.
- **Model fallback chain:** `agent.config.json` can define ordered providers; the runtime tries them in order for both natural responses and native/JSON tool-call planning, preserving fallback attempt metadata in redacted auto transcripts.
- **Native tool-calling status contract:** `/status` now exposes read-only native autonomy safety metadata plus a milestone acceptance matrix: model-planning enablement, wrapped/fenced JSON plan extraction support, the bounded loop-step and per-step model tool-call budgets, follow-up prompt redaction, terminal no-tool/no-dispatch markers, execution-summary claim-count support, and max-step/model-error/invalid-plan/duplicate/same-step-duplicate stop enforcement, plan-only and explicit-`execute=true` defaults, one-shot and per-step planner traces, per-step execution-ledger delta support, supported provider-native tool-call variants, provider tool-name aliases such as `toolName`/`functionName`, provider argument aliases such as `arguments_json`/`inputJson`, provider tool-call ID aliases such as `call_id`/`tool_use_id`/`callId`/`toolCallId`, bounded/redacted provider tool-call ID provenance in plan/result ledgers and transcript review summaries, provider `tool_result`/`toolResult`/`function_result`/`functionResult`/`function_call_output`/`functionCallOutput`/`functionResponse`/`function_response`/`toolCallResult` echo suppression plus role=`tool`/`function` result-message suppression, provider-hosted/custom/freeform tool-call rejection, model-hidden approval controls, execution-capable and target-affecting tool classes, local native-loop contract completion flags, and local transcript counts without reading target systems or raw transcript contents.
- **Workspace file tools:** `/read`, `/write`, `/workspace-search`, and `/patch-file` are constrained to the engagement workspace and resolve symlink candidates before reading/searching.
- **Media/artifact registry:** `/media-import` copies local evidence/media into the engagement evidence tree with SHA-256, size, MIME, and kind metadata; stored/displayed paths and original names are redacted, `/media-list` lists metadata, and `/media-get` returns session-bound metadata without reading file contents.
- **Operator briefing, handoff, sealed snapshots, and sealed DB backups:** `/guardrail-test` writes redacted synthetic guardrail simulation reports under `agent/guardrails/`; `/timeline` creates a redacted Markdown evidence/action chronology; `/manifest` creates JSON/Markdown SHA-256 artifact inventories for chain-of-custody review; `/manifest-verify` writes JSON/Markdown verification reports comparing a prior manifest to current local artifacts; `/secret-scan` writes redacted JSON/Markdown evidence hygiene reports under `agent/secret-scans/`; `/closeout` reviews local ROE/preflight, approvals, tasks, findings, process state, tool runs, and artifact presence into a ready/review/blocked Markdown checklist with redacted local refs such as `approval:<id>`, `task:<id>`, `process:<id>`, `finding:<id>`, `tool-run:<id>`, and `artifact:<relative-agent-path>`; `/ref` resolves those refs using existing current-session detail handlers or evidence-root artifact metadata, never file contents; `/briefing` creates a redacted Markdown operator summary; `/handoff`/`/export-session` and `/import-session` move redacted context/tasks/memory between local DBs; `/sealed-export` and `/sealed-import` wrap handoffs in passphrase-env sealed snapshots; CLI `seal-db`/`unseal-db` creates authenticated encrypted backups of a closed SQLite DB and can remove plaintext DB/WAL/SHM files after a successful seal.
- **Local/VPS HTTP gateway:** `phobos-agent serve` exposes a simple web UI plus JSON endpoints on `127.0.0.1` by default. Remote/VPS binds require an environment-backed bearer token unless `--unsafe-no-auth` is explicitly supplied for isolated throwaway networks. The gateway includes route discovery, CORS support, a standalone `/ui-client` browser client, a validated `deploy-kit` template generator, granular guardrail/ROE policy editing, typed query/body validation with clean JSON `400` errors for malformed IDs/limits/booleans and approval-action JSON bodies, schema-backed `/tool` argument validation that returns structured tool errors before handler dispatch, and views for schemas, read-only scope checks, synthetic guardrail self-tests, memory hygiene, preflight readiness, findings, tool runs, timelines, evidence manifests/verification, evidence secret scans, closeout reviews, local ref resolution, LCM nodes, tasks/task details, jobs, processes/process details, delegations, delegation details, media metadata, auth status, and bridge config.
- **Messaging bridges:** `phobos-agent discord`, `phobos-agent slack`, and `phobos-agent telegram` connect the same runtime to allowlisted chat surfaces while keeping tokens in environment variables, neutralizing mass-ping text in responses, checking actual local bridge-test attachment size before dispatch, recording remote attachment metadata without blind downloads, and preserving ROE/tool-policy approvals. Remote `/approve` and `/deny` are disabled by default per bridge. Bridge responses are chat-polished by default with `--no-response-polish` available for raw diagnostics.
- **Redacted engagement packs:** `/export-pack` and `phobos-agent export-pack` build a ZIP with redacted evidence, runtime state, and a manifest for closeout/review. Symlinked evidence paths are packaged only when their resolved target stays inside the evidence root; user-supplied artifact `out=` paths are likewise resolved before writing and must stay inside their specific `agent/` artifact directory.
- **Evidence workspace:** all target-affecting decisions and outputs are written under the engagement evidence directory, with secret redaction applied to session messages, memories, context summaries/nodes, media metadata, logged commands/tool args, and audit event payloads before storage/display; redaction covers common Authorization bearer/basic headers, authorization assignments, cookie headers, quoted password/token/API-key values, cloud/OAuth secret fields such as client secrets and AWS secret access keys, and pasted PEM private-key blocks.

## Agent commands

```text
/help
/tools
/schemas name=<optional-tool>
/tool name=<tool_name> key=value ...
/auto prompt=<natural request> apply=false execute=false model=false
/auto-loop prompt=<goal> steps=5 execute=false model=false
/auto-transcripts kind=plan|loop|all limit=50
/auto-transcript path=agent/auto-loops/<file>.json max_ledger=20
/plugins
/skills
/skill name=<skill-name>
/skill bundle=<bundle-name>
/sessions limit=20 recent=8
/remember key=<name> value=<fact> tags=<optional>
/recall query=<text>
/memories query=<optional> limit=50
/memory id=<memory-id> or key=<name>
/forget id=<memory-id> or key=<name>
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
/scope target=<optional-host-or-url>
/guardrail-test target=<optional-host-or-url> out=<optional.md>
/assess target=<host> type=<web|api|host> purpose=<why> command=<cmd>
/run target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/start target=<host> type=<host|web|api> purpose=<why> command=<cmd> execute=true
/processes
/process-detail id=<process-id>
/poll id=<process-id>
/wait id=<process-id> timeout=30
/log id=<process-id> limit=4000
/kill id=<process-id>
/approvals status=pending|all
/approval id=<approval-id>
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
/finding-bundle id=<finding-id> out=<optional.zip>
/subagents prompt=<task> roles=scope,safety,evidence,impact,cve,report
/delegate prompt=<task> roles=scope,safety,report
/delegations limit=20
/delegation id=<delegation-id>
/auth-status
/preflight out=<optional.md>
/media-import path=<local-file> kind=<optional>
/media-list
/media-get id=<media-id>
/sealed-export passphrase_env=<ENV_NAME> out=<optional.sealed.json>
/sealed-import path=<sealed.json> passphrase_env=<ENV_NAME>
/job name=<name> schedule="every 1 h" prompt=<agent prompt>
/jobs
/job-detail id=<job-id>
/job-update id=<job-id> enabled=false schedule=<optional> prompt=<optional>
/job-enable id=<job-id>
/job-disable id=<job-id>
/run-due
/status
/briefing query=<optional> out=<optional.md>
/timeline limit=100 category=<optional> include_audit=true out=<optional.md>
/manifest limit=1000 max_bytes=50000000 include_agent=true out=<optional.json>
/manifest-verify path=<manifest.json> detect_new=true out=<optional.json>
/secret-scan limit=200 max_bytes=2000000 include_agent=true out=<optional.json>
/closeout out=<optional.md>
/ref ref=<task:1|finding:1|tool-run:1|artifact:agent/path>
/detail ref=<approval:1|process:1|job:1|delegation:1|media:1|context-node:1>
/tasks status=all
/task-detail id=<task-id>
/task-add content=<task> status=pending
/task-update id=<task-id> status=completed content=<optional>
/handoff out=<optional.json>
/export-session out=<optional.json>
/import-session path=<handoff.json> merge_memories=false
/export-pack out=<optional.zip>
/audit limit=50
/audit-detail id=<n>
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

# Plan or apply guarded native tool calls from the public CLI; plan-only is the default.
phobos-agent --db data/phobos-agent.db --config agent.config.json auto \
  --engagement engagement.json \
  --prompt 'remember cli-note: validate this without running target tools'
phobos-agent --db data/phobos-agent.db --config agent.config.json auto-loop \
  --engagement engagement.json \
  --steps 3 \
  --prompt 'build a bounded safe plan from current local context'

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

Use `provider: "openai-responses"` for direct `/v1/responses` endpoints; Phobos sends flattened Responses API function specs and still routes returned calls through the same schema/ROE/runtime-policy boundary.

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

Without `apply=true`, `/auto` returns a plan only. With `apply=true`, recognized non-command tools are invoked. If the plan contains `run_command`, `start_process`, or an execution-capable scanner wrapper (`nmap_scan`, `httpx_probe`, `nuclei_scan`, or `ffuf_scan`), the generated action still passes through normal ROE guardrails and is left as `execute=false` unless `/auto execute=true` is also supplied. Confirm-level actions still queue for approval.

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

## Evidence secret hygiene scan

Use `/secret-scan`, `evidence_secret_scan`, gateway `GET /secret-scan`, or the CLI command before closeout/handoff/export when you want a local-only hygiene pass over collected evidence:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json secret-scan \
  --engagement engagement.json \
  --out closeout-secret-scan.json \
  --limit 200
```

The scan is read-only and performs no target activity. It walks only files that resolve under the engagement evidence root, skips symlink escapes, oversized files, binary-like artifacts, and its own `agent/secret-scans/` output directory, then writes redacted JSON and Markdown under `agent/secret-scans/`. Results include metadata and redacted previews only: raw file contents and raw secret values are not emitted. Use `--exclude-agent` or `include_agent=false` when you want to scan operator/client evidence while ignoring Phobos-generated artifacts.

## Local drill-down refs

Closeout and timeline rows include redacted refs such as `task:1`, `process:1`, `finding:1`, `tool-run:1`, `delegation:1`, `media:1`, `context-node:1`, `audit:1`, and `artifact:agent/closeout/review.md`. Resolve them with `/ref`, `/detail`, generic `resolve_local_ref`, or gateway `GET /ref?ref=...`:

```bash
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/ref ref=task:1'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/detail ref=artifact:agent/preflight/operator-preflight.md'
```

Entity refs reuse the existing session-bound detail handlers, so foreign integer IDs return `not found in this session`. Audit refs return one redacted current-session audit event only, which makes `/timeline include_audit=true` drill-down rows actionable without exposing another local session. Artifact refs are evidence-root relative, block traversal/absolute/drive-letter/symlink escapes, emit path/category/type/size/MIME/mtime/SHA-256 metadata only, and never read or return file contents.

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
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approval id=1'
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/deny id=1 reason="outside window"'
# or, when ROE permits:
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approve id=1'
```

Approval records redact secret-like arguments and resolution payloads before they are stored. If the queued arguments contain redacted placeholders, `/approve` treats the record as review-only and asks the operator to re-submit fresh execution input rather than replaying an altered command.

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

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/finding-bundle id=1 out=finding-1-handoff.zip'
```

Finding statuses are intentionally lifecycle-oriented (`draft`, `needs-evidence`, `confirmed`, `resolved`, `accepted-risk`, `false-positive`) so imports/parser hits remain candidate evidence until the operator confirms impact. Finding and structured-tool-run detail operations are scoped to the active session: `/finding-get`, `/finding-update`, `/finding-export`, `/finding-review`, `/finding-bundle`, `/tool-run`, and their gateway detail routes return `not found in this session` rather than exposing or mutating records from another local session in the same SQLite DB. LCM-style context-node detail operations are session-scoped too: `/lcm-describe id=...` and `/lcm-expand id=...` refuse IDs owned by another local session, and child-node listings filter to the active session before returning summaries. Task updates and process controls are session-scoped as well: `/task-update`, `/poll`, `/wait`, `/log`, and `/kill` refuse IDs owned by another local session instead of leaking process logs, changing task state, or terminating another operator's process. `/finding-review` is a deterministic, local-only QA pass: it does not execute target actions, and it writes a Markdown review that separates blocking report-readiness gaps from advisory improvements such as missing negative controls, reproduction notes, or cleanup/side-effect notes. `/finding-bundle` (also exposed as `/finding-package`, gateway `/finding-package`, and CLI `finding-package`) is read-only/no-target-activity: it writes a ZIP under `agent/findings/` containing a report draft, QA review, redacted finding JSON, linked redacted text evidence, and `MANIFEST.json`; binary, oversized, missing, duplicate, and symlink/out-of-evidence-root artifacts are skipped rather than embedded.

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

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/job-detail id=1'

# Pause automation without deleting job history or last-run metadata.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/job-disable id=1'

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/job-enable id=1'

phobos-agent --db data/phobos-agent.db run-due --engagement engagement.json
```

For recurring use, run `phobos-agent run-due` from cron/systemd/Task Scheduler. The agent keeps job state in SQLite, lists/detail views are session-bound and redacted, and disabled jobs are skipped by `run-due` until re-enabled.

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

Local attachment paths are checked against the bridge's `max_attachment_bytes` limit using filesystem metadata before any text command is dispatched, then imported through the existing `media_import` tool when allowed. Blocked/imported attachment metadata is redacted before display/audit, and remote-only platform attachment references are recorded as redacted metadata rather than downloaded automatically.

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
GET  /scope-check?target=<host-or-url>
GET  /sessions
GET  /context
GET  /timeline?limit=100&include_audit=false
GET  /manifest?limit=1000&include_agent=true
GET  /evidence-manifest?limit=1000&include_agent=true
GET  /closeout
GET  /closeout-review
GET  /ref?ref=task:1
GET  /detail?ref=finding:1
GET  /resolve-ref?kind=artifact&path=agent/preflight/operator-preflight.md
GET  /lcm
GET  /tasks
GET  /task?id=<task-id>
GET  /task-detail?id=<task-id>
GET  /findings
GET  /finding?id=<finding-id>
GET  /finding-detail?id=<finding-id>
GET  /tool-runs
GET  /tool-run?id=<tool-run-id>
GET  /tool-run-detail?run_id=<tool-run-id>
GET  /jobs
GET  /job?id=<job-id>
GET  /job-detail?id=<job-id>
GET  /processes
GET  /process?id=<process-id>
GET  /process-detail?id=<process-id>
GET  /approvals
GET  /approval?id=<approval-id>
GET  /delegations
GET  /delegation?id=<delegation-id>
GET  /delegation-detail?id=<delegation-id>
GET  /media
GET  /media-detail?id=<media-id>
GET  /media-artifact?id=<media-id>
GET  /auth
GET  /bridges
GET  /guardrails
GET  /auto-transcripts?kind=all&limit=50
GET  /auto-transcript?path=agent/auto-loops/<file>.json&max_ledger=20
GET  /audit
POST /auto      {"prompt": "...", "apply": false, "execute": false, "model": false}
POST /auto-loop {"prompt": "...", "steps": 5, "execute": false, "model": false}
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
  --allow-origin https://your-ui-origin.example \
  --max-body-bytes 1048576
```

`/health` remains unauthenticated so load balancers and operators can confirm liveness, but operational endpoints require `Authorization: Bearer ***` when a token is configured. Non-local binds refuse to start without `--token-env` unless `--unsafe-no-auth` is supplied; that override is only for isolated throwaway test networks. JSON `POST` endpoints reject non-object bodies, malformed typed IDs, and oversized request bodies before dispatching to runtime tools; the default body limit is 1 MiB and can be tightened with `--max-body-bytes`. For real VPS deployments, put the stdlib gateway behind a firewall plus TLS reverse proxy, VPN, or SSH tunnel. Do not expose it directly as a multi-user production web application.

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

Ran 126 tests
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
config_scalar_validation_ok=True
agent_init_ok=True
native_tool_call_cli_entrypoints_ok=True
tools_include_core_plugin_and_new_parity=True
schema_version_ok=True
db_schema_counts_ok=True
local_skills_ok=True
schema_returned=True
plugin_loaded_and_executed=True
tool_schema_integer_validation_ok=True
tool_schema_integer_bounds_validation_ok=True
tool_schema_resource_ceiling_ok=True
tool_schema_boolean_validation_ok=True
tool_schema_string_validation_ok=True
tool_schema_number_validation_ok=True
tool_schema_blank_required_validation_ok=True
tool_schema_array_object_validation_ok=True
tool_schema_nested_validation_ok=True
tool_schema_size_bounds_validation_ok=True
tool_schema_pattern_validation_ok=True
tool_schema_additional_properties_validation_ok=True
tool_schema_required_validation_ok=True
tool_schema_enum_validation_ok=True
scope_check_read_only_ok=True
scope_url_port_ipv6_matching_ok=True
guardrail_selftest_ok=True
natural_response_polish_ok=True
auto_memory_recall=True
auto_loop_ok=True
native_tool_call_plan_validation_ok=True
native_tool_call_plan_transcript_ok=True
native_tool_call_one_shot_planner_trace_ok=True
native_tool_call_per_step_budget_ok=True
native_tool_call_wrapped_json_plan_ok=True
native_tool_call_context_handoff_ok=True
native_tool_call_fallback_chain_ok=True
native_tool_call_allowed_execution_ok=True
native_tool_call_apply_transcript_ok=True
native_tool_call_scanner_execute_boundary_ok=True
native_tool_call_slash_flag_safety_ok=True
native_tool_call_status_contract_ok=True
native_tool_call_natural_auto_provenance_ok=True
native_openai_tool_call_adapter_ok=True
native_openai_responses_adapter_ok=True
native_gemini_adapter_ok=True
native_anthropic_adapter_ok=True
native_provider_flat_tool_call_ok=True
native_tool_call_provider_call_id_provenance_ok=True
native_provider_call_id_redaction_bounds_ok=True
native_provider_call_id_uniqueness_ok=True
native_tool_call_transcript_provenance_ok=True
native_provider_choice_delta_tool_call_ok=True
native_provider_choice_delta_fragment_merge_ok=True
native_provider_choice_delta_function_call_fragment_ok=True
native_provider_choice_delta_tool_use_fragment_ok=True
native_provider_tool_calls_nested_aliases_ok=True
native_provider_single_top_level_tool_call_ok=True
native_provider_singular_tool_call_alias_ok=True
native_provider_camel_case_tool_call_alias_ok=True
native_provider_root_function_call_ok=True
native_provider_root_function_calls_alias_ok=True
native_provider_root_function_calls_nested_function_call_alias_ok=True
native_provider_root_message_wrapper_ok=True
native_provider_root_message_alias_matrix_ok=True
native_provider_root_function_calls_snake_alias_ok=True
native_provider_root_function_calls_snake_nested_function_call_alias_ok=True
native_provider_root_tool_use_aliases_ok=True
native_provider_message_tool_use_aliases_ok=True
native_provider_message_function_call_alias_ok=True
native_provider_message_function_calls_alias_ok=True
native_provider_message_function_calls_nested_function_call_alias_ok=True
native_provider_tool_call_edge_cases_ok=True
native_provider_legacy_function_call_ok=True
native_provider_content_block_tool_call_ok=True
native_provider_content_block_call_id_alias_ok=True
native_provider_content_block_function_call_alias_ok=True
native_provider_content_block_tool_use_alias_ok=True
native_provider_content_parts_function_call_ok=True
native_provider_top_level_content_block_tool_call_ok=True
native_provider_argument_aliases_ok=True
native_provider_tool_name_aliases_ok=True
native_provider_single_content_block_tool_call_ok=True
native_provider_responses_output_tool_call_ok=True
native_provider_responses_stream_event_ok=True
native_provider_responses_sse_stream_event_ok=True
native_provider_responses_output_nested_function_call_ok=True
native_provider_responses_output_message_aliases_ok=True
native_provider_responses_output_message_typeless_wrapper_ok=True
native_provider_responses_output_message_typeless_direct_ok=True
native_provider_responses_output_message_typeless_direct_aliases_ok=True
native_provider_responses_message_tool_call_alias_ok=True
native_provider_responses_message_function_calls_alias_ok=True
native_provider_responses_message_toolcalls_plural_alias_ok=True
native_provider_responses_message_tool_call_singular_alias_ok=True
native_provider_responses_message_content_tool_call_ok=True
native_provider_responses_message_content_function_call_alias_ok=True
native_provider_responses_message_content_parts_function_call_ok=True
native_provider_single_responses_output_tool_call_ok=True
native_provider_candidate_function_call_ok=True
native_provider_single_candidate_part_function_call_ok=True
native_provider_hosted_tool_call_reject_ok=True
native_provider_custom_tool_call_reject_ok=True
native_provider_tool_result_ignore_ok=True
native_provider_result_role_message_ignore_ok=True
native_tool_call_guardrail_approval_ok=True
native_tool_call_loop_approval_stop_ok=True
native_tool_call_operator_approval_replay_ok=True
native_tool_call_approval_action_guard_ok=True
native_tool_call_runtime_policy_ok=True
native_tool_call_terminal_no_tool_stop_ok=True
native_tool_call_no_tool_no_dispatch_ok=True
native_tool_call_duplicate_loop_stop_ok=True
native_tool_call_partial_duplicate_loop_stop_ok=True
native_tool_call_same_step_duplicate_stop_ok=True
native_tool_call_max_steps_budget_ok=True
native_tool_call_model_error_stop_ok=True
native_tool_call_invalid_plan_stop_ok=True
native_tool_call_feedback_loop_ok=True
native_tool_call_step_ledger_delta_ok=True
native_tool_call_planner_trace_ok=True
native_tool_call_cumulative_feedback_ok=True
native_tool_call_feedback_prompt_redaction_ok=True
native_tool_call_transcript_index_detail_ok=True
native_tool_call_execution_ledger_ok=True
native_tool_call_execution_summary_ok=True
native_tool_call_gateway_chat_ok=True
native_tool_call_milestone_contract_ok=True
memory_hygiene_forget_ok=True
message_memory_context_media_storage_redaction_ok=True
workspace_roundtrip_and_escape_block=True
workspace_symlink_escape_block=True
guardrails_execution_approvals_blocks=True
session_bound_approval_store_ok=True
approval_storage_redaction_ok=True
audit_redaction_ok=True
auth_header_cookie_redaction_ok=True
cloud_oauth_private_key_redaction_ok=True
structured_tool_wrappers_ok=True
finding_lifecycle_ok=True
finding_review_ok=True
finding_evidence_bundle_ok=True
session_bound_finding_tool_detail_ok=True
finding_tool_run_storage_redaction_ok=True
artifact_output_containment_ok=True
background_process_completed=True
wait_process_ok=True
process_detail_storage_redaction_ok=True
jobs_and_subagents=True
job_controls_session_bound_redacted_ok=True
task_board_roundtrip=True
session_bound_task_process_ok=True
task_detail_storage_redaction_ok=True
context_compacted=True
lcm_context_nodes_ok=True
session_bound_context_nodes_ok=True
hindsight_lcm_aliases_ok=True
delegation_batches_ok=True
isolated_delegation_sessions_ok=True
process_isolated_delegation_ok=True
delegation_detail_session_bound_ok=True
delegation_storage_redaction_ok=True
auth_status_redacted_ok=True
safety_preflight_ok=True
media_artifacts_ok=True
media_detail_session_bound_ok=True
local_ref_resolver_ok=True
audit_detail_session_bound_redacted_ok=True
evidence_timeline_ok=True
evidence_manifest_ok=True
evidence_manifest_verify_ok=True
evidence_manifest_verify_flags_ok=True
evidence_secret_scan_ok=True
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
bridge_attachment_size_guard_ok=True
gateway_ok=True
gateway_full_api_ok=True
gateway_invalid_query_handling_ok=True
gateway_invalid_post_handling_ok=True
gateway_body_size_limit_ok=True
gateway_audit_detail_route_ok=True
granular_guardrail_ui_ok=True
deploy_kit_ok=True
remote_vps_ui_auth_ok=True
pack_exported_and_redacted=True
no_legacy_public_terms_ok=True
db_exists=True
artifact_count=769
pack=/root/Documents/Tools/phobos-agent/demo-phobos-parity/evidence/phobos-agent-parity-smoke/agent/exports/closeout-pack.zip
```

`native_tool_call_milestone_contract_ok=True` is an aggregate gate over every native tool-call safety/translation smoke above, including direct Gemini GenerateContent candidate `functionCall` plans, direct Anthropic Messages `tool_use` plans, single/top-level content-block calls, flat/choice-delta/choice-delta-fragment/choice-delta-functionCall-fragment/choice-delta-toolUse-fragment/nested/message-level/message-content/parts Responses output calls, captured Responses streaming function-call events and raw SSE frames with argument-delta assembly, typed and typeless nested `output[].message` wrappers, Responses typed or typeless direct or nested `output[].message` `tool_calls`/`toolCalls`/`tool_call`/`toolCall` aliases, root-level `message` wrapper alias matrix, root/message-level `toolUse`/`toolUses` aliases, root/message `functionCall` / `functionCalls` / `function_calls` aliases, provider tool-name alias normalization, bounded/redacted provider call-ID provenance with duplicate-ID rejection before dispatch, per-step model tool-call budget enforcement, result-echo suppression including role=`tool`/`function` result messages, provider-hosted/freeform tool-call rejection (including Responses file-search, image-generation, local-shell, and MCP hosted calls), runtime policy, ROE preview, approval stops, and ledger claim semantics. The smoke gate also compares the aggregate list against every `native_*` smoke boolean so new native coverage cannot be left out silently.



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
approval-detail.txt
approvals.txt
auth-status.json
auto-apply.txt
auto-loop.txt
auto-loop-recall.txt
auto-plan.txt
auto-recall.txt
auto-secret-scan.txt
auto-scope.txt
bridge-approval-block.json
bridge-attachment-size-guard.json
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
secret-scan-cli.command.txt
secret-scan-cli.stderr.txt
secret-scan-cli.stdout.txt
delegation.json
delegation-process.json
delegation-storage.json
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
gateway-invalid-query.json
gateway-invalid-post.json
gateway-body-limit.json
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
lcm-session-scope.json
legacy-term-grep.txt
media-import.json
media-list.json
evidence-manifest.json
evidence-secret-scan.json
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
finding-bundle.json
finding-tool-run-storage-redaction.json
artifact-output-escape.json
artifact-output-scoped.json
operator-briefing.json
pack-export.json
plugin-echo.txt
schema-scope-check.txt
scope-allowed.txt
scope-blocked.txt
scope-ipv6-allowed.txt
scope-ipv6-port-allowed.txt
scope-summary.txt
scope-url-port-allowed.txt
scope-url-port-blocked.txt
scope-wildcard-port-allowed.txt
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
storage-redaction-boundary.json
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
- `/auto` has a verified local native model/tool-calling loop with deterministic fake-adapter smoke coverage, bounded redacted runtime context, wrapped/fenced JSON plan extraction, pre-dispatch name/schema validation, runtime-policy confirm/block annotations, read-only guardrail preview metadata for target-affecting calls, explicit allowed-execution ledger proof, natural-message auto-execute provenance when that opt-in mode is enabled, direct operator approval replay proof for confirm-gated native plans, redacted one-shot planner/provider traces, redacted rejected-call transcript entries, provider `tool_result`/`toolResult`/`functionResponse`/`functionCallOutput` result-echo ignore handling, provider candidate list-or-single `parts` `functionCall`, flat/nested Responses output calls, root `functionCall`/`functionCalls` translation, provider-hosted/custom/freeform native-call rejection without input echo that is part of the aggregate milestone smoke gate, redacted plan-preview and applied-plan transcripts under `agent/auto-plans`, redacted execution ledgers, a `/status` milestone contract matrix, and a bounded cumulative result-feedback `/auto-loop` that redacts follow-up copies of the original prompt plus tool-result feedback and writes redacted transcript artifacts that respect terminal no-tool model responses after feedback, stops with explicit `model_error` state on post-feedback provider failure, and stops rather than continuing past queued approvals or blocked results, but it is still scoped to Phobos' local registry/guardrail runtime rather than Hermes' full general-purpose autonomy;
- local `/delegate` now supports process-isolated deterministic worker tasks with per-task child sessions/workspaces/artifacts, but it is still not Hermes' true distributed subagent sandbox with independent terminal/tool backends or separate model credentials;
- sealed snapshots and `seal-db`/`unseal-db` provide authenticated passphrase-env protected exports/backups; this is not transparent live SQLite page encryption unless the operator also uses filesystem encryption, SQLCipher, or another deployment control;
- Phobos now has explicit LCM-style context nodes and Hindsight-style aliases over local memory/context, but it does not implement Hermes' live long-context compression DAG or full Hindsight/Obsidian memory system;

The important pieces for a standalone pentest agent are working: sessions, memory, Hindsight aliases, task board, local skills, context snapshots/compaction, LCM-style context nodes, tool schemas, structured scanner wrapper evidence, finding lifecycle records, plugin loading, runtime policy, approvals, foreground/background process handling, jobs, model fallback, subagent role reviews, durable local delegation batches with child sessions, media/artifact import, bridge media metadata/import, auth/profile status, operator briefings, handoff export/import, sealed portable snapshots, sealed DB backup/restore, authenticated local/VPS gateway/dashboard and remote browser client, Discord/Slack/Telegram bridge dispatch, ROE-gated non-destructive execution, evidence logging, local evidence secret hygiene scans, and the pentest-specific tools.
