# Phobos Agent Harness

A local, Hermes-inspired agent harness for **authorized offensive security testing**. It is built for professional pentest workflow support: ROE intake, action gating, low-risk impact validation, evidence capture, offline AD/BloodHound review, CVE triage, model-assisted drafting, and report-ready finding exports.

This is **not** a malware, evasion, persistence, DoS, or mass-exploitation framework. The harness is authorization-aware and dry-run-first: it helps prove realistic impact safely and document it defensibly.

## Implemented modules

- **ROE + guardrails** — explicit in-scope targets, prohibited techniques, stop conditions, secret redaction, and `allow` / `confirm` / `block` decisions.
- **Burp MCP adapter** — probes a JSON-RPC/MCP endpoint, creates Repeater tabs from saved raw HTTP requests, and writes raw/redacted request artifacts. Dry-run by default.
- **BloodHound / ADCS importer** — parses BloodHound-style JSON directories/files/ZIPs offline, inventories high-value relationships, identifies ADCS-related edges, and classifies principal-to-privileged graph paths without touching AD.
- **CVE advisor** — matches a local CVE catalog and optionally queries NVD, then recommends non-invasive validation and flags DoS/destructive PoC risk.
- **Model adapter layer** — supports a deterministic offline heuristic adapter plus OpenAI-compatible/local/Hermes-CLI adapters for role-specific drafting.
- **Finding Markdown exporter** — renders confirmed finding JSON into report-ready Markdown with risk metadata, evidence, affected assets, recommendations, evidence health, and candidate/non-reportable handling.
- **Standalone Phobos Agent runtime** — SQLite sessions/memory/tasks with FTS recall, schema-versioned local state, tool schemas, local skills, guarded natural-language `/auto` planning, plugins, background processes, jobs, localhost web/gateway, operator briefings, portable session handoffs, runtime tool policy, and redacted engagement-pack export.

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
agent/processes/*.log                # background process stdout/stderr artifacts
agent/context-summary-*.md           # compacted session summaries
agent/operator-briefing-*.md         # redacted operator briefings
agent/session-exports/*.json         # portable redacted session handoffs
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

Current verification: 27 tests pass, covering guardrails, CLI, Burp MCP client/artifacts, BloodHound path/ADCS import, CVE advisor, model adapter, finding exporter, SQLite FTS recall, guarded auto-planning, local skills, task boards, tool policy, operator briefings, handoff export/import, pack export, gateway tool calls, and the standalone Hermes-like agent runtime.

## Standalone Phobos Agent runtime

The project now includes a separate local runtime command:

```bash
phobos-agent
```

This turns the harness into a standalone agent-style application with:

- SQLite-backed sessions and task boards;
- local persistent memory and FTS-backed session/memory search;
- schema-versioned SQLite state with `/status` health output; current runtime schema is v3;
- context snapshots and explicit `/compact` summaries;
- tool registry, JSON-style schemas, plugin loading, local skill loading, and audit log;
- guarded deterministic `/auto` planning for common natural-language operator intents;
- non-destructive-by-default command execution;
- foreground and background process management;
- approval queue for confirm-level actions;
- runtime policy that can block or approval-gate arbitrary tools;
- durable scheduled jobs runnable with `phobos-agent run-due`;
- role-based subagent reviews;
- model adapter fallback chains;
- engagement workspace file tools;
- operator briefing and portable session handoff export/import;
- local HTTP gateway with JSON endpoints and a simple web dashboard;
- redacted engagement-pack ZIP export;
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

# State-changing or lockout-sensitive actions are queued, not blindly run.
phobos-agent --db data/phobos-agent.db once \
  --engagement engagement.json \
  --message '/run target=app.example.test type=web purpose="controlled test update" command="curl -X POST https://app.example.test/profile" execute=true'

# Review approvals.
phobos-agent --db data/phobos-agent.db once --engagement engagement.json --message '/approvals'

# Workspace files, background processes, plugins, context compaction, and local gateway.
phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/write path=notes/scope.md content="Scope app.example.test authz notes"'

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
  --message '/briefing query=client'

phobos-agent --db data/phobos-agent.db --config agent.config.json once \
  --engagement engagement.json \
  --message '/handoff out=session-handoff.json'

phobos-agent --db data/phobos-agent.db --config agent.config.json status \
  --engagement engagement.json

phobos-agent --db data/phobos-agent.db --config agent.config.json export-pack \
  --engagement engagement.json \
  --out closeout-pack.zip

phobos-agent --db data/phobos-agent.db --config agent.config.json serve \
  --engagement engagement.json \
  --host 127.0.0.1 \
  --port 8765
```

See `docs/full-agent-runtime.md` for the full command list, scheduler pattern, approval flow, and current limitations.

### Current full-runtime verification

```text
python -m compileall -q src tests examples/plugins scripts
python -m unittest discover -s tests -v

Ran 27 tests in 3.545s
OK
```

Polished parity smoke verification is committed as `scripts/smoke_hermes_parity.py` and produced:

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
gateway_ok=True
pack_exported_and_redacted=True
db_exists=True
artifact_count=76
pack=/root/Documents/Tools/phobos-agent/demo-phobos-parity/evidence/phobos-agent-parity-smoke/agent/exports/closeout-pack.zip
```

