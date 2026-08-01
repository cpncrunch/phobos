from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bloodhound import analyze_bloodhound
from .burp_mcp import BurpMCPClient, HTTPRequestArtifact, write_burp_artifacts
from .cve_advisor import CveAdvisor
from .harness import OffSecHarness
from .model_adapters import build_adapter
from .models import ActionRequest, EngagementROE
from .reporting import FindingInput, FindingMarkdownExporter, safe_report_filename


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _print(data: dict) -> None:
    print(json.dumps(data, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phobos Agent authorized offensive security harness")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    init = sub.add_parser("init", help="Create an engagement ROE JSON file")
    init.add_argument("--name", required=True)
    init.add_argument("--scope", required=True, help="Comma-separated host/IP/CIDR/wildcard scope rules")
    init.add_argument("--allowed", default="web,api,service-enumeration")
    init.add_argument("--prohibited", default="dos,destructive,persistence,evasion,malware")
    init.add_argument(
        "--safety-mode",
        default="non_destructive",
        choices=["non_destructive", "standard"],
        help="non_destructive allows normal active testing unless it is destructive/disruptive; standard confirmation-gates active/noisy actions",
    )
    init.add_argument("--testing-window", default="not specified")
    init.add_argument("--evidence-dir", default="evidence")
    init.add_argument("--out", default="engagement.json")

    assess = sub.add_parser("assess", help="Evaluate a proposed command/action")
    assess.add_argument("--engagement", required=True)
    assess.add_argument("--target", required=True)
    assess.add_argument("--type", required=True, dest="action_type")
    assess.add_argument("--purpose", required=True)
    assess.add_argument("--command", default=None)
    mode = assess.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True, help="Default: decide and log without execution")
    mode.add_argument("--execute", action="store_true", help="Execute only if guardrails return allow")
    assess.add_argument("--timeout", type=int, default=30)

    plan = sub.add_parser("plan", help="Generate a safe impact validation plan from an observed finding")
    plan.add_argument("--engagement", required=True)
    plan.add_argument("--finding", required=True)

    burp_probe = sub.add_parser("burp-probe", help="Probe a Burp MCP JSON-RPC endpoint")
    burp_probe.add_argument("--mcp-url", required=True)
    burp_probe.add_argument("--host-header")
    burp_probe.add_argument("--timeout", type=float, default=10.0)

    burp_tab = sub.add_parser("burp-tab", help="Create a Burp Repeater tab from a raw HTTP request and save artifacts")
    burp_tab.add_argument("--engagement", required=True)
    burp_tab.add_argument("--mcp-url", required=True)
    burp_tab.add_argument("--target", required=True)
    burp_tab.add_argument("--tab-name", required=True)
    burp_tab.add_argument("--request-file", required=True)
    burp_tab.add_argument("--host-header")
    burp_tab.add_argument("--timeout", type=float, default=10.0)
    burp_tab.add_argument("--create", action="store_true", help="Actually ask Burp MCP to create the tab; default only logs/saves artifacts")

    bh = sub.add_parser("bloodhound-import", help="Offline BloodHound/ADCS graph path classification")
    bh.add_argument("--engagement", required=True)
    bh.add_argument("--input", required=True, help="BloodHound JSON file, directory, or ZIP")
    bh.add_argument("--principal", help="Optional starting user/group/computer principal")
    bh.add_argument("--out", help="Markdown output path; default: engagement evidence/ad/bloodhound-analysis.md")

    cve = sub.add_parser("cve-advice", help="Generate safe CVE validation advice for an observed component/version")
    cve.add_argument("--engagement", required=True)
    cve.add_argument("--component", required=True)
    cve.add_argument("--version", default="")
    cve.add_argument("--evidence", default="")
    cve.add_argument("--catalog", help="Optional local JSON CVE catalog")
    cve.add_argument("--online", action="store_true", help="Also query NVD keywordSearch; network/API failures become notes")
    cve.add_argument("--out", help="Markdown output path; default: engagement evidence/cve/<component>.md")

    model = sub.add_parser("model-draft", help="Use a heuristic/OpenAI-compatible/Responses/Gemini/local/Hermes adapter for role-specific drafting")
    model.add_argument("--provider", default="heuristic", choices=["heuristic", "openai", "openai-compatible", "openai-responses", "responses", "gemini", "google", "google-gemini", "local", "ollama", "hermes", "hermes-cli"])
    model.add_argument("--role", default="impact", choices=["scope", "safety", "evidence", "impact", "cve", "report"])
    model.add_argument("--prompt", required=True)
    model.add_argument("--context-file")
    model.add_argument("--model", default="gpt-4o-mini")
    model.add_argument("--base-url")
    model.add_argument("--key-env", default="OPENAI_API_KEY")
    model.add_argument("--command-template", help="For hermes-cli provider, shell template containing {prompt_file}")
    model.add_argument("--out")

    export = sub.add_parser("export-finding", help="Render a report-ready finding draft from JSON")
    export.add_argument("--engagement", required=True)
    export.add_argument("--finding-file", required=True)
    export.add_argument("--out", help="Markdown output path; default: engagement evidence/reports/<title>.md")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.subcommand == "init":
        roe = EngagementROE(
            name=args.name,
            authorized=True,
            in_scope_targets=_csv(args.scope),
            allowed_techniques=_csv(args.allowed),
            prohibited_techniques=_csv(args.prohibited),
            testing_window=args.testing_window,
            evidence_dir=args.evidence_dir,
            safety_mode=args.safety_mode,
        )
        roe.save(args.out)
        _print({"created": args.out, "roe": roe.to_dict()})
        return 0

    if args.subcommand == "burp-probe":
        client = BurpMCPClient(args.mcp_url, host_header=args.host_header, timeout=args.timeout)
        _print(client.probe())
        return 0

    if args.subcommand == "model-draft":
        context = Path(args.context_file).read_text(encoding="utf-8") if args.context_file else ""
        adapter = build_adapter(args.provider, model=args.model, base_url=args.base_url, key_env=args.key_env, command_template=args.command_template)
        response = adapter.generate(args.role, args.prompt, context=context)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(response.content, encoding="utf-8")
        _print(response.to_dict() | ({"out": args.out} if args.out else {}))
        return 0

    roe = EngagementROE.load(args.engagement)
    harness = OffSecHarness(roe)

    if args.subcommand == "assess":
        request = ActionRequest(
            target=args.target,
            action_type=args.action_type,
            purpose=args.purpose,
            command=args.command,
        )
        result = harness.assess(request, execute=bool(args.execute), timeout=args.timeout)
        _print(result.to_dict())
        return 0 if result.decision.status.value != "block" else 2

    if args.subcommand == "plan":
        path = harness.plan(args.finding)
        _print({"plan_path": str(path)})
        return 0

    if args.subcommand == "burp-tab":
        http_request = HTTPRequestArtifact.load(args.request_file)
        guard_request = ActionRequest(
            target=args.target,
            action_type="web",
            purpose=f"Create Burp Repeater tab {args.tab_name!r} for {http_request.method} {http_request.path}; no target request is sent by the harness",
            command=f"burp-mcp create_repeater_tab {args.tab_name}",
        )
        decision_result = harness.assess(guard_request, execute=False)
        if decision_result.decision.status.value == "block":
            artifacts = write_burp_artifacts(harness.store.root, args.tab_name, http_request, result={"skipped": "blocked by guardrails"})
            _print({"decision": decision_result.decision.to_dict(), "artifacts": artifacts})
            return 2
        mcp_result = {"skipped": "dry-run; pass --create to contact Burp MCP"}
        if args.create:
            client = BurpMCPClient(args.mcp_url, host_header=args.host_header, timeout=args.timeout)
            mcp_result = client.create_repeater_tab(args.tab_name, http_request)
        artifacts = write_burp_artifacts(harness.store.root, args.tab_name, http_request, result=mcp_result)
        _print({"decision": decision_result.decision.to_dict(), "mcp_result": mcp_result, "artifacts": artifacts})
        return 0

    if args.subcommand == "bloodhound-import":
        analysis = analyze_bloodhound(args.input, principal=args.principal)
        out = Path(args.out) if args.out else harness.store.root / "ad" / "bloodhound-analysis.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(analysis.to_markdown(), encoding="utf-8")
        _print({"analysis": analysis.to_dict(), "markdown_path": str(out)})
        return 0

    if args.subcommand == "cve-advice":
        advice = CveAdvisor.from_catalog_file(args.catalog).advise(args.component, version=args.version, evidence=args.evidence, online=args.online)
        safe_component = safe_report_filename(args.component)
        out = Path(args.out) if args.out else harness.store.root / "cve" / f"{safe_component}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(advice.to_markdown(), encoding="utf-8")
        _print({"advice": advice.to_dict(), "markdown_path": str(out)})
        return 0

    if args.subcommand == "export-finding":
        finding = FindingInput.load(args.finding_file)
        out = Path(args.out) if args.out else harness.store.root / "reports" / f"{safe_report_filename(finding.title)}.md"
        path = FindingMarkdownExporter().write_finding(finding, out)
        _print({"finding": finding.to_dict(), "markdown_path": str(path)})
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
