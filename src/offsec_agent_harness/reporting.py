from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json
import re


@dataclass(slots=True)
class FindingInput:
    title: str
    severity: str = "Medium"
    component: str = "Application Penetration Testing"
    industry_reference: str = "Not specified"
    impact: str = "Not specified"
    root_cause: str = "Not specified"
    description: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    recommendation: str = ""
    confirmed: bool = True
    cvss: str = ""
    cwe: str = ""
    limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FindingInput":
        aliases = dict(data)
        if "evidence" in aliases and "supporting_evidence" not in aliases:
            aliases["supporting_evidence"] = aliases.pop("evidence")
        if isinstance(aliases.get("supporting_evidence"), str):
            aliases["supporting_evidence"] = [aliases["supporting_evidence"]]
        if isinstance(aliases.get("affected_assets"), str):
            aliases["affected_assets"] = [aliases["affected_assets"]]
        allowed = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in aliases.items() if key in allowed})

    @classmethod
    def load(cls, path: str | Path) -> "FindingInput":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingMarkdownExporter:
    def render_finding(self, finding: FindingInput) -> str:
        title = finding.title.strip() or "Untitled Finding"
        if not finding.confirmed:
            heading = f"# Internal Candidate Note — {title}"
            reportability = "This item is not client-reportable yet because it is not marked confirmed. Keep it as an internal coverage note until concrete, application-specific evidence is collected."
        else:
            heading = f"# {title}"
            reportability = "This draft is suitable for report review if the supporting evidence paths/artifacts are present and accurate."
        metadata = [
            ("INDUSTRY REFERENCE", finding.industry_reference),
            ("IMPACT", finding.impact),
            ("ROOT CAUSE", finding.root_cause),
            ("RISK LEVEL", finding.severity),
        ]
        if finding.cvss:
            metadata.append(("CVSS", finding.cvss))
        if finding.cwe:
            metadata.append(("CWE", finding.cwe))
        lines = [heading, "", "## Risk Metadata", "", "| Field | Value |", "|---|---|"]
        lines += [f"| {key} | {_escape(value)} |" for key, value in metadata]
        lines += ["", "## Reportability", "", reportability, "", "## Technical Description", ""]
        lines.append(finding.description.strip() or _default_description(finding))
        lines += ["", "## Supporting Evidence", ""]
        if finding.supporting_evidence:
            lines += [f"- {item}" for item in finding.supporting_evidence]
        else:
            lines.append("- Evidence not supplied. Add request/response pairs, command output, screenshots, decoded claims, or other artifacts before final reporting.")
        lines += ["", "## Affected Assets", ""]
        if finding.affected_assets:
            lines += [f"- `{asset}`" for asset in finding.affected_assets]
        else:
            lines.append("- Affected assets not supplied.")
        lines += ["", "## Recommendation", ""]
        lines.append(finding.recommendation.strip() or _default_recommendation(finding))
        lines += ["", "## Evidence Health Check", ""]
        lines.append(f"- Confirmed finding: {'yes' if finding.confirmed else 'no'}")
        lines.append(f"- Evidence items supplied: {len(finding.supporting_evidence)}")
        lines.append(f"- Affected assets supplied: {len(finding.affected_assets)}")
        if finding.limitations:
            lines += ["", "## Limitations / Non-Claims", ""] + [f"- {item}" for item in finding.limitations]
        elif not finding.confirmed:
            lines += ["", "## Limitations / Non-Claims", "", "- Exploitability and impact have not been safely confirmed under the current evidence set."]
        return "\n".join(lines) + "\n"

    def write_finding(self, finding: FindingInput, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render_finding(finding), encoding="utf-8")
        return out


def safe_report_filename(title: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", title.strip()).strip("-").lower() or "finding"


def _escape(value: str) -> str:
    return str(value).replace("|", "\\|")


def _default_description(finding: FindingInput) -> str:
    return (
        f"During testing, {finding.title} was identified in the {finding.component} component. "
        "The observed behaviour could affect the security properties described in the risk metadata above. "
        "The final report should tie this statement to concrete supporting evidence and avoid claims beyond the supplied artifacts."
    )


def _default_recommendation(finding: FindingInput) -> str:
    return (
        "Review the affected functionality and implement server-side controls that address the identified root cause. "
        "Where possible, add regression tests and monitoring to detect recurrence. If immediate remediation is not feasible, apply compensating controls until the underlying issue can be corrected."
    )
