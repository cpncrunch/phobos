# Phobos Agent Harness

A local, Hermes-inspired agent harness for **authorized offensive security testing**. It is built for professional pentest workflow support: ROE intake, action gating, low-risk impact validation, evidence capture, offline AD/BloodHound review, CVE triage, model-assisted drafting, and report-ready finding exports.

This is **not** a malware, evasion, persistence, DoS, or mass-exploitation framework. The harness is authorization-aware and dry-run-first: it helps prove realistic impact safely and document it defensibly.

## Implemented modules

- **ROE + guardrails** — explicit in-scope targets, prohibited techniques, stop conditions, secret redaction, `allow` / `confirm` / `block` decisions, and granular local/VPS UI editing for safety mode, scope, stop conditions, and per-tool confirm/block policy.
- **Burp MCP adapter** — probes a JSON-RPC/MCP endpoint, creates Repeater tabs from saved raw HTTP requests, and writes raw/redacted request artifacts. Dry-run by default.
- **BloodHound / ADCS importer** — parses BloodHound-style JSON directories/files/ZIPs offline, inventories high-value relationships, identifies ADCS-related edges, and classifies principal-to-privileged graph paths without touching AD.
- **CVE advisor** — matches a local CVE catalog and optionally queries NVD, then recommends non-invasive validation and flags DoS/destructive PoC risk.
- **Model adapter layer** — supports a deterministic offline heuristic adapter plus OpenAI-compatible/local/Hermes-CLI adapters for role-specific drafting.
- **Finding Markdown exporter + QA/closeout review** — renders confirmed finding JSON into report-ready Markdown and reviews stored finding records plus engagement closeout state for blocking/advisory evidence gaps before operator/client delivery.
- **Standalone Phobos Agent runtime** — SQLite sessions/memory/tasks with FTS recall, Hindsight/LCM-style local recall aliases, schema-versioned local state, structured nmap/httpx/nuclei/ffuf wrapper evidence, finding lifecycle records, tool schemas, local skills, guarded natural-language `/auto` planning, plugins, background processes, jobs, authenticated local/VPS web gateway plus validated deploy-kit templates and remote browser client, Discord/Slack/Telegram bridges with safe media/voice attachment handling, redacted evidence timelines/manifests/closeout reviews, operator briefings, portable session handoffs, sealed DB backup/restore, runtime tool policy, and redacted engagement-pack export.

## Quick start

```bash
cd /root/Documents/Tools/phobos-agent
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

# Create an engagement profile.
phobos-harness init \
  --name "Demo Assessment" \
  --scope app.example.test,10.10.0.0/24,corp.local \
  --allowed web,api,service-enumeration,offline-analysis \
  --prohibited dos,destructive,persistence,evasion,malware \
  --evidence-dir evidence \
  --out engagement.json
```

## Safety decisions

```bash
phobos-harness assess \
  --engagement engagement.json \
  --target app.example.test \
  --type web \
  --purpose "Capture response headers" \
  --command "curl -I https://app.example.test" \
  --dry-run
```

Decision statuses:

- `allow` — in-scope and low-risk. Execution still requires `--execute`.
- `confirm` — potentially noisy/state-changing/credential-sensitive; the MVP logs and refuses execution until a human reviews ROE/safety.
- `block` — out-of-scope or matches destructive/DoS/persistence/evasion/malware-like guardrails.

## Burp MCP workflow

Create a raw HTTP request file:

```http
GET /api/invoices/123 HTTP/1.1
Host: app.example.test
Authorization: Bearer REDACT-ME

```

Dry-run and save artifacts without contacting Burp:

```bash
phobos-harness burp-tab \
  --engagement engagement.json \
  --mcp-url http://127.0.0.1:9876/mcp \
  --target app.example.test \
  --tab-name "IDOR positive proof" \
  --request-file request.http
```

Actually create the Repeater tab when Burp MCP is reachable:

```bash
phobos-harness burp-probe --mcp-url http://127.0.0.1:9876/mcp --host-header localhost:9876

phobos-harness burp-tab \
  --engagement engagement.json \
  --mcp-url http://127.0.0.1:9876/mcp \
  --host-header localhost:9876 \
  --target app.example.test \
  --tab-name "IDOR positive proof" \
  --request-file request.http \
  --create
```

Artifacts are written under:

```text
evidence/<engagement>/burp/*.http
evidence/<engagement>/burp/*.redacted.http
evidence/<engagement>/burp/*.json
```

## BloodHound / ADCS offline analysis

```bash
phobos-harness bloodhound-import \
  --engagement engagement.json \
  --input bloodhound-export.zip \
  --principal 'USER@CORP.LOCAL'
```

The importer produces:

```text
evidence/<engagement>/ad/bloodhound-analysis.md
```

It inventories high-value relationships such as `GenericAll`, `WriteDacl`, `Owns`, `AddMember`, `AdminTo`, `HasSession`, and ADCS markers such as `ADCSESC*`, `Enroll`, `ManageCA`, and certificate-template/CA edges. It does **offline graph review only** and does not modify AD or validate exploitation on live systems.

## CVE advisor

Local catalog example:

```json
{
  "cves": [
    {
      "cve_id": "CVE-2099-0001",
      "component_patterns": ["ExampleServer"],
      "affected_versions": ["<=1.2.3"],
      "title": "ExampleServer crafted request denial of service",
      "summary": "A crafted request can cause a denial of service crash.",
      "severity": "High"
    }
  ]
}
```

Run offline/local-catalog review:

```bash
phobos-harness cve-advice \
  --engagement engagement.json \
  --component ExampleServer \
  --version 1.2.0 \
  --evidence "service banner" \
  --catalog cve-catalog.json
```

Optionally add NVD keyword search:

```bash
phobos-harness cve-advice \
  --engagement engagement.json \
  --component "Apache httpd" \
  --version 2.4.49 \
  --online
```

The output is a Markdown coverage note under `evidence/<engagement>/cve/`. Version-only matches are treated as internal notes until application-specific impact is safely confirmed.

## Model adapters

Offline deterministic drafting:

```bash
phobos-harness model-draft \
  --provider heuristic \
  --role safety \
  --prompt "Review whether this planned validation is safe under no-DoS ROE."
```

OpenAI-compatible/local endpoint:

```bash
export OPENAI_API_KEY='...'
phobos-harness model-draft \
  --provider openai-compatible \
  --model gpt-4o-mini \
  --base-url https://api.openai.com/v1 \
  --role report \
  --prompt "Draft report-safe finding language from the supplied evidence."
```

Local/Ollama-style OpenAI-compatible endpoint:

```bash
phobos-harness model-draft \
  --provider local \
  --base-url http://127.0.0.1:11434/v1 \
  --model llama3.1 \
  --role impact \
  --prompt "Plan the minimum safe impact validation step."
```

Hermes CLI adapter is explicit so the operator controls the exact Hermes invocation:

```bash
phobos-harness model-draft \
  --provider hermes-cli \
  --command-template 'hermes --no-tools --prompt-file {prompt_file}' \
  --role evidence \
  --prompt "Extract what this artifact proves."
```

## Finding Markdown export

Finding JSON example:

```json
{
  "title": "Improper Authorization Allows Access to Controlled Invoice",
  "severity": "High",
  "component": "API",
  "industry_reference": "OWASP A01: Broken Access Control",
  "impact": "Unauthorized Access",
  "root_cause": "Improper Authorization",
  "description": "During testing, a standard user was able to access a second controlled test user's invoice by modifying the invoice_id parameter.",
  "evidence": [
    "burp/idor-positive.http",
    "burp/idor-negative-control.http"
  ],
  "affected_assets": [
    "GET /api/invoices/{id}"
  ],
  "recommendation": "Enforce server-side object authorization for every invoice request.",
  "confirmed": true
}
```

Export:

```bash
phobos-harness export-finding \
  --engagement engagement.json \
  --finding-file finding.json
```

Output:

```text
evidence/<engagement>/reports/<finding-title>.md
```

If `confirmed` is `false`, the exporter labels the item as an internal candidate note and explicitly states it is not client-reportable yet.

## Artifact layout

Each engagement writes artifacts under `evidence/<safe-engagement-name>/` by default:

```text
decisions.jsonl                      # guardrail decisions
command-log.md                       # report-friendly command/action log
evidence-matrix.md                   # artifact/evidence tracker
plans/safe-impact-validation.md      # safe next-step plans
burp/*.http                          # raw Burp requests
burp/*.redacted.http                 # redacted Burp requests
ad/bloodhound-analysis.md            # offline AD path review
cve/*.md                             # CVE coverage notes
reports/*.md                         # report-ready finding drafts
agent/findings/*review*.md           # deterministic finding QA/readiness reviews
agent/processes/*.log                # background process stdout/stderr artifacts
agent/context-summary-*.md           # compacted session summaries
agent/context-nodes/*.md             # LCM-style expandable context node summaries
agent/delegations/delegation-*/       # durable local pseudo-subagent task artifacts
agent/preflight/*                     # read-only ROE/runtime readiness reports
agent/manifests/*                     # read-only SHA-256 artifact inventories
agent/closeout/*                      # read-only closeout readiness reviews
agent/media/*                         # copied local media/artifact evidence with hashes
agent/briefings/operator-briefing-*.md # redacted operator briefings
agent/session-exports/*.json         # portable redacted session handoffs
agent/sealed/*.sealed.json           # passphrase-env sealed portable snapshots
agent/exports/*.zip                  # redacted engagement packs
```

## Development verification

Run:

```bash
cd /root/Documents/Tools/phobos-agent
. .venv/bin/activate
python -m compileall -q src tests examples/plugins scripts
python -m unittest discover -s tests -v
python scripts/smoke_hermes_parity.py
```

The unit suite and smoke include deterministic finding QA review, read-only safety preflight, evidence manifest/verification, and closeout review coverage: `/finding-review` writes a redacted Markdown readiness review for findings, `/preflight` checks ROE/runtime readiness, `/manifest` inventories artifact metadata/hashes without file contents, `/manifest-verify` re-hashes a prior manifest to flag changed/missing/unsafe/new local artifacts, and `/closeout` composes local approvals/tasks/findings/processes/tool-runs/artifacts into a redacted closeout readiness report with bounded local drill-down references. These review tools perform no target activity.

Current verification: 45 tests pass, covering guardrails, CLI/profile/auth-status/preflight/closeout, DB seal/unseal backup round-trips, Burp MCP client/artifacts, BloodHound path/ADCS import, CVE advisor, model adapter, finding exporter, deterministic finding QA review, safety preflight readiness reports, artifact output containment, lifecycle records, structured nmap/httpx/nuclei/ffuf wrappers, tool-run/finding storage redaction, SQLite FTS recall, guarded auto-planning and bounded auto-loop, Hindsight aliases, session-scoped LCM-style context node describe/expand, isolated local delegation child sessions, local/remote-metadata bridge media handling, media artifacts, redacted audit storage/display, redacted evidence timelines, read-only evidence manifests, closeout readiness reviews with local drill-down links, sealed portable snapshots, local skills, task boards, tool policy, operator briefings, handoff export/import, Discord/Slack/Telegram bridge dispatch, pack export, expanded gateway routes/tool calls, authenticated VPS remote UI, and the standalone Hermes-like agent runtime.

## Standalone Phobos Agent runtime

The project now includes a separate local runtime command:

```bash
phobos-agent
```

This turns the harness into a standalone agent-style application with:

- SQLite-backed sessions and task boards;
- local persistent memory and FTS-backed current/cross-session search;
- schema-versioned SQLite state with `/status` health output; current runtime schema is v5;
- context snapshots, explicit `/compact` summaries, LCM-style `/lcm-compact`/`/lcm-describe`/`/lcm-expand`/`/lcm-query` context nodes, and Hindsight-style `/hindsight-retain`/`/hindsight-recall`/`/hindsight-reflect` aliases over local memory/context; node describe/expand operations are scoped to the active session;
- tool registry, JSON-style schemas, plugin loading, local skill loading, redacted audit log with common Authorization/Cookie/quoted-secret scrubbing, redacted evidence timeline, SHA-256 manifest, and closeout readiness review;
- ROE-gated structured wrappers for `nmap`, `httpx`, `nuclei`, and `ffuf` that can either execute with explicit `execute=true` or parse captured output into durable, session-bound evidence artifacts; structured tool-run targets, commands, decisions, parsed data, and metadata are redacted before SQLite storage; `nuclei_scan` requires an explicit operator-selected template path when executing so it never runs the broad default template set accidentally;
- finding lifecycle records (`draft`, `needs-evidence`, `confirmed`, `resolved`, `accepted-risk`, `false-positive`) with session-bound evidence/tool-run links, deterministic QA/readiness reviews, Markdown export, and field/evidence redaction before SQLite storage;
- guarded deterministic `/auto` planning plus optional model-assisted JSON planning and bounded `/auto-loop`;
- a configurable Phobos assistant persona (`operator_name`, `assistant_style`) so natural-language replies sound like a concise pentest copilot instead of a raw harness log;
- non-destructive-by-default command execution;
- foreground and background process management, including `/wait`;
- approval queue for confirm-level actions, with current-session lookup and replay enforced in both runtime and store helpers; approval args/results are redacted before SQLite storage, and approvals whose arguments were redacted are review-only until the operator re-submits fresh execution input;
- runtime policy that can block or approval-gate arbitrary tools;
- durable scheduled jobs runnable with `phobos-agent run-due`, plus session-bound redacted `/job-detail`, `/job-update`, `/job-enable`, and `/job-disable` controls so automation can be paused without losing audit history;
- role-based subagent reviews and durable local delegation batches with session-bound detail/completion paths for per-task child sessions/artifacts, with delegation prompts/tasks/results redacted before SQLite storage;
- model adapter fallback chains;
- engagement workspace file tools that resolve candidate paths before reading/searching so symlink escapes stay blocked;
- profile-aware local config/DB roots under `~/.phobos/profiles/<name>`;
- auth/token environment status checks that never reveal secret values, plus `/preflight` readiness checks before opening operator sessions, enabling bridges, exposing a gateway, or handing off to another tester;
- local media/artifact import, listing, and session-bound metadata drill-down with SHA-256 hashes and no file-content reads;
- redacted evidence timeline, read-only evidence manifests with SHA-256 artifact inventories plus manifest verification reports, closeout readiness reviews with local drill-down refs for pending approvals/tasks/processes/findings/artifacts, redacted task/process detail views, operator briefing, portable session handoff export/import, passphrase-env sealed snapshot export/import, and CLI `seal-db`/`unseal-db` sealed SQLite backup/restore;
- local HTTP gateway with JSON endpoints, route discovery, local dashboard, granular guardrail editor, session-bound finding/tool-run/delegation/media/job/task/process detail, timeline/manifest/preflight/closeout views, and routes for status/tools/schemas/sessions/context/preflight/timeline/manifest/manifest-verify/closeout/LCM/tasks/task-detail/findings/finding-detail/tool-runs/tool-run-detail/jobs/job-detail/processes/process-detail/approvals/redacted approval detail/delegations/delegation-detail/media/media-detail/auth/bridges/guardrails/audit;
- VPS-capable remote browser client (`phobos-agent ui-client` or `/ui-client`) plus bearer-token/CORS gateway mode; non-local binds refuse to start without `--token-env` unless explicitly forced with `--unsafe-no-auth`;
- Discord, Slack, and Telegram bridges with channel/user allowlists, env-var tokens, mass-ping neutralization, concise chat-polished responses, size-checked local attachment import, remote metadata-only recording, and disabled-by-default remote approval actions;
- redacted engagement-pack ZIP export that skips symlinked evidence paths resolving outside the evidence root and constrains user-supplied artifact `out=` paths to their `agent/` artifact directories;
- interactive chat and single-message modes.

The new public commands are `phobos-agent` and `phobos-harness`. The old
prototype aliases, `offsec-agent` and `offsec-harness`, are still installed for
backwards compatibility.

Initialize and use it:

```bash
cd /root/Documents/Tools/phobos-agent
. .venv/bin/activate

phobos-agent --db data/phobos-agent.db init --engagement engagement.json

phobos-agent config-init --out agent.config.json

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/tools'

phobos-agent --db data/phobos-agent.db chat --engagement engagement.json
```

Examples:

```bash
# Store local agent memory.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/remember key=client value="ACME internal assessment" tags=engagement'

# ROE-gated command execution.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/run target=app.example.test type=host purpose="safe local smoke" command="printf ok" execute=true'

# Routine active testing is allowed by the default non_destructive safety mode
# when the target is in scope and the command is not destructive/disruptive.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/assess target=10.10.0.5 type=service-enumeration purpose="version scan" command="nmap -sV 10.10.0.5"'

# Structured wrapper evidence can parse captured output without requiring the
# scanner binary during tests/demos, or execute only with explicit execute=true.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/nmap target=10.10.0.5 ports=80,443 stdout="80/tcp open http nginx"'

# Live wrapper execution requires scanner binaries. On Ubuntu/Kali:
#   apt-get install -y nmap ffuf golang-go
#   GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#   GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# If Python's HTTPX CLI shadows ProjectDiscovery httpx, set PHOBOS_HTTPX_BIN=/path/to/httpx
# (Phobos also prefers $HOME/go/bin/httpx when present). Nuclei execution requires
# an explicit safe template file/directory.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/nuclei url=https://app.example.test templates=./safe-templates/ execute=true rate_limit=1'

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/finding-create title="Exposed administrative interface" severity=Medium status=needs-evidence tool_run_ids=1'

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/finding-review id=1'

phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/finding-export id=1'

# State-changing or lockout-sensitive actions are queued, not blindly run.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/run target=app.example.test type=web purpose="controlled test update" command="curl -X POST https://app.example.test/profile" execute=true'

# Review approvals.
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approvals'
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approval id=1'

# Workspace files, background processes, plugins, context compaction, and local gateway.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/write path=notes/scope.md content="Scope app.example.test authz notes"'

# Workspace read/search/patch resolves symlinks and refuses paths whose real
# target leaves the engagement workspace.

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/auto apply=true prompt="remember client: ACME internal assessment"'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/start target=app.example.test type=host purpose="background smoke" command="printf bg-agent-ok" execute=true'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/compact limit=60'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/task-add content="Review closeout evidence" status=pending'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/timeline limit=50 include_audit=false'

phobos-agent --db data/phobos-agent.db --config agent.config.json evidence-manifest \
  --engagement engagement.json \
  --out closeout-manifest.json

phobos-agent --db data/phobos-agent.db --config agent.config.json manifest-verify \
  --engagement engagement.json \
  --path closeout-manifest.json \
  --out closeout-manifest-verify.json

phobos-agent --db data/phobos-agent.db --config agent.config.json closeout \
  --engagement engagement.json \
  --out closeout-review.md
# Closeout reviews are read-only and report ready/review/blocked based only on
# local ROE, approvals, tasks, findings, process state, and evidence metadata;
# fail/warn rows include redacted local drill-down refs instead of raw commands.

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/briefing query=client'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/handoff out=session-handoff.json'

phobos-agent --db data/phobos-agent.db --config agent.config.json status \
  --engagement engagement.json

phobos-agent --db data/phobos-agent.db --config agent.config.json export-pack \
  --engagement engagement.json \
  --out closeout-pack.zip
# Export packs redact text artifacts and skip symlinked evidence paths whose
# resolved target leaves the evidence root.

phobos-agent --db data/phobos-agent.db --config agent.config.json serve \
  --engagement engagement.json \
  --host 127.0.0.1 \
  --port 8765

# Generate a standalone browser UI that can connect to a VPS-hosted agent.
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

# VPS mode: bind publicly only with a bearer token env var and CORS policy.
export PHOBOS_GATEWAY_TOKEN='use-a-long-random-secret-from-your-password-manager'
phobos-agent --db data/phobos-agent.db --config agent.config.json serve \
  --engagement engagement.json \
  --host 0.0.0.0 \
  --port 8765 \
  --token-env PHOBOS_GATEWAY_TOKEN \
  --allow-origin https://your-ui-origin.example

# Offline-test Discord bridge filtering without network credentials.
phobos-agent --db data/phobos-agent.db --config agent.config.json bridge-test \
  --engagement engagement.json \
  --platform discord \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos' \
  --channel-id <channel-or-thread-id> \
  --user-id <operator-user-id> \
  --message '!phobos /status'

# Offline-test a local voice/media bridge attachment. Local files are checked
# against the bridge size limit before dispatch; blocked/imported attachment
# metadata is redacted, and Phobos does not blindly download remote URLs.
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

# Seal a closed local SQLite DB into an authenticated encrypted backup. This is
# backup/restore protection, not transparent live page encryption.
export PHOBOS_DB_SEAL='...'
phobos-agent --db data/phobos-agent.db seal-db \
  --out data/phobos-agent.db.sealed \
  --passphrase-env PHOBOS_DB_SEAL \
  --remove-plaintext
phobos-agent --db data/phobos-agent.db unseal-db \
  --in data/phobos-agent.db.sealed \
  --passphrase-env PHOBOS_DB_SEAL \
  --overwrite

# Check bridge token/API readiness without sending chat messages.
phobos-agent bridge-doctor --platform discord --platform slack --platform telegram

# Run a live Discord bridge. Tokens stay in environment variables, not config/Git.
# --discord-thread-mode per-message makes top-level requests behave like Hermes:
# Phobos creates a new Discord thread for each top-level request and continues
# replies there. The bot also needs Discord's Create Public Threads permission.
# Bridge responses are chat-polished by default; add --no-response-polish if you
# need raw runtime JSON/diagnostics in chat for debugging.
export PHOBOS_DISCORD_TOKEN='...'
phobos-agent --db data/phobos-agent.db --config agent.config.json discord \
  --engagement engagement.json \
  --allow-channel <channel-or-thread-id> \
  --allow-user <operator-user-id> \
  --prefix '!phobos' \
  --discord-thread-mode per-message

# Optional live-but-safe local integration smoke. It scans only a local test HTTP
# server, uses a generated one-request Nuclei template, and never sends bridge
# messages. Add --require-bridge-tokens only after setting real token env vars.
python scripts/smoke_live_integrations.py --require-scanners
```

See `docs/full-agent-runtime.md` for the full command list, scheduler pattern, approval flow, and current limitations.

### Current full-runtime verification

```text
python -m compileall -q src tests examples/plugins scripts
python -m unittest discover -s tests -v

Ran 46 tests
OK
```

Polished parity smoke verification is committed as `scripts/smoke_hermes_parity.py` and produced:

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
session_bound_approval_store_ok=True
approval_storage_redaction_ok=True
audit_redaction_ok=True
auth_header_cookie_redaction_ok=True
structured_tool_wrappers_ok=True
finding_lifecycle_ok=True
finding_review_ok=True
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
delegation_detail_session_bound_ok=True
delegation_storage_redaction_ok=True
auth_status_redacted_ok=True
safety_preflight_ok=True
media_artifacts_ok=True
media_detail_session_bound_ok=True
evidence_timeline_ok=True
evidence_manifest_ok=True
evidence_manifest_verify_ok=True
evidence_manifest_verify_flags_ok=True
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
granular_guardrail_ui_ok=True
deploy_kit_ok=True
remote_vps_ui_auth_ok=True
pack_exported_and_redacted=True
no_legacy_public_terms_ok=True
db_exists=True
artifact_count=241
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

