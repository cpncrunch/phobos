from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json
import re
import urllib.parse
import urllib.request


DOS_WORDS = re.compile(r"(?i)denial of service|\bDoS\b|crash|resource exhaustion|infinite loop|panic|segmentation fault")
DESTRUCTIVE_WORDS = re.compile(r"(?i)data corruption|delete|overwrite|destructive|ransom|wipe")


@dataclass(slots=True)
class CVECandidate:
    cve_id: str
    title: str
    summary: str
    severity: str = "Unknown"
    affected_versions: list[str] = field(default_factory=list)
    source: str = "catalog"
    safe_validation: list[str] = field(default_factory=list)
    destructive_risk: str = "unknown"
    reportability: str = "internal-note-until-confirmed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CVEAdvice:
    component: str
    version: str
    evidence: str = ""
    candidates: list[CVECandidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [
            "# CVE Advisory Review", "",
            f"- Component: `{self.component}`",
            f"- Observed version/build: `{self.version or 'not specified'}`",
            f"- Evidence source: {self.evidence or 'not specified'}", "",
            "## Safety Position", "",
            "Prefer non-invasive validation: version/build confirmation, configuration review, vendor advisory mapping, scanner evidence, authenticated read-only checks, or lab reproduction. Do not run PoCs that may crash services, exhaust resources, corrupt data, or cause denial of service unless the ROE explicitly permits that specific test.", "",
        ]
        if not self.candidates:
            lines += ["## Candidate CVEs", "", "No matching CVEs were identified by the configured catalog/query. Keep this as a coverage note rather than a finding.", ""]
        else:
            lines += ["## Candidate CVEs", ""]
            for cand in self.candidates:
                lines += [
                    f"### {cand.cve_id} — {cand.title}", "",
                    f"- Severity: {cand.severity}",
                    f"- Source: {cand.source}",
                    f"- Destructive/DoS validation risk: {cand.destructive_risk}",
                    f"- Reportability: {cand.reportability}",
                    f"- Affected-version hints: {', '.join(cand.affected_versions) or 'not specified'}", "",
                    cand.summary.strip(), "", "Safe validation options:",
                ]
                lines += [f"- {item}" for item in cand.safe_validation] + [""]
        if self.notes:
            lines += ["## Notes", ""] + [f"- {note}" for note in self.notes] + [""]
        return "\n".join(lines)


class CveAdvisor:
    def __init__(self, catalog: list[dict[str, Any]] | None = None):
        self.catalog = catalog or []

    @classmethod
    def from_catalog_file(cls, path: str | Path | None) -> "CveAdvisor":
        if not path:
            return cls([])
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = data.get("cves") or data.get("items") or [] if isinstance(data, dict) else data
        return cls(list(entries))

    def advise(self, component: str, version: str = "", evidence: str = "", online: bool = False, limit: int = 10) -> CVEAdvice:
        notes: list[str] = []
        candidates = self._catalog_matches(component, version)[:limit]
        if online:
            try:
                candidates.extend(query_nvd(component, version, limit=max(1, limit - len(candidates))))
            except Exception as exc:
                notes.append(f"Online NVD query failed: {exc}")
        seen: set[str] = set()
        unique: list[CVECandidate] = []
        for cand in candidates:
            if cand.cve_id not in seen:
                unique.append(cand)
                seen.add(cand.cve_id)
        if not unique:
            notes.append("No CVE candidates matched. Verify product identity/version and consider a targeted vendor advisory review.")
        return CVEAdvice(component=component, version=version, evidence=evidence, candidates=unique[:limit], notes=notes)

    def _catalog_matches(self, component: str, version: str) -> list[CVECandidate]:
        out: list[CVECandidate] = []
        component_l = component.lower()
        for entry in self.catalog:
            patterns = entry.get("component_patterns") or entry.get("components") or [entry.get("component", "")]
            if isinstance(patterns, str):
                patterns = [patterns]
            if not any(pattern and pattern.lower() in component_l for pattern in patterns):
                continue
            specs = entry.get("affected_versions") or entry.get("versions") or ["*"]
            if isinstance(specs, str):
                specs = [specs]
            if version and not any(_version_matches(version, spec) for spec in specs):
                continue
            out.append(_candidate_from_entry(entry, specs))
        return out


def _candidate_from_entry(entry: dict[str, Any], specs: list[str]) -> CVECandidate:
    summary = entry.get("summary") or entry.get("description") or "No summary supplied."
    safe_validation, risk, reportability = _validation_guidance(summary, entry.get("safe_validation"))
    return CVECandidate(
        cve_id=entry.get("cve_id") or entry.get("id") or "CVE-UNKNOWN",
        title=entry.get("title") or entry.get("name") or entry.get("cve_id") or "CVE candidate",
        summary=summary,
        severity=entry.get("severity", "Unknown"),
        affected_versions=[str(item) for item in specs],
        source=entry.get("source", "catalog"),
        safe_validation=safe_validation,
        destructive_risk=risk,
        reportability=entry.get("reportability", reportability),
    )


def query_nvd(component: str, version: str = "", limit: int = 5) -> list[CVECandidate]:
    query = f"{component} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": str(limit)})
    req = urllib.request.Request(url, headers={"User-Agent": "phobos-agent/0.1"})
    with urllib.request.urlopen(req, timeout=15) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
    candidates: list[CVECandidate] = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "CVE-UNKNOWN")
        descriptions = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severity = "Unknown"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                severity = metrics[key][0].get("cvssData", {}).get("baseSeverity") or metrics[key][0].get("baseSeverity", "Unknown")
                break
        safe_validation, risk, reportability = _validation_guidance(summary, None)
        candidates.append(CVECandidate(cve_id, cve_id, summary or "No NVD English description returned.", severity, [version] if version else [], "NVD keywordSearch", safe_validation, risk, reportability))
    return candidates


def _validation_guidance(summary: str, supplied: Any) -> tuple[list[str], str, str]:
    if supplied:
        safe = supplied if isinstance(supplied, list) else [str(supplied)]
    else:
        safe = [
            "Confirm the exact product, edition, version, build, plugin, and configuration from a trusted source.",
            "Map the observed version/configuration to the vendor advisory and NVD record.",
            "Prefer a scanner-safe or authenticated read-only check where available.",
            "If exploit behaviour is needed, reproduce in a controlled lab instead of production.",
        ]
    if DOS_WORDS.search(summary) or DESTRUCTIVE_WORDS.search(summary):
        return safe + ["Avoid production PoC execution because available validation may be disruptive."], "high", "internal-note-unless-non-destructively-confirmed"
    return safe, "low-to-medium", "internal-note-until-application-specific-impact-is-confirmed"


def _version_matches(version: str, spec: str) -> bool:
    version = version.strip()
    spec = str(spec).strip()
    if not spec or spec in {"*", "any"}:
        return True
    if spec.endswith(".*"):
        return version.startswith(spec[:-1])
    for op in ("<=", ">=", "==", "<", ">"):
        if spec.startswith(op):
            cmp = _compare_versions(version, spec[len(op):].strip())
            return {"<=": cmp <= 0, ">=": cmp >= 0, "==": cmp == 0, "<": cmp < 0, ">": cmp > 0}[op]
    return spec == version or spec in version


def _compare_versions(left: str, right: str) -> int:
    def parts(value: str) -> list[int]:
        return [int(p) for p in re.findall(r"\d+", value)] or [0]
    l_parts, r_parts = parts(left), parts(right)
    width = max(len(l_parts), len(r_parts))
    l_parts += [0] * (width - len(l_parts))
    r_parts += [0] * (width - len(r_parts))
    return (l_parts > r_parts) - (l_parts < r_parts)
