from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
import json
import zipfile


PRIVILEGED_NAME_MARKERS = ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "DOMAIN CONTROLLERS", "ADMINISTRATORS@")
HIGH_VALUE_RELATIONSHIPS = {
    "AdminTo", "GenericAll", "GenericWrite", "Owns", "WriteDacl", "WriteOwner", "AddMember",
    "ForceChangePassword", "AllowedToDelegate", "AddAllowedToAct", "CanRDP", "ExecuteDCOM",
    "HasSession", "MemberOf",
}
ADCS_RELATIONSHIP_MARKERS = ("ADCSESC", "Enroll", "ManageCA", "ManageCertificates", "NTAuthStoreFor", "PublishedTo", "GoldenCert")


@dataclass(slots=True)
class ADNode:
    id: str
    name: str
    labels: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ADEdge:
    source: str
    target: str
    relationship: str
    source_name: str = ""
    target_name: str = ""


@dataclass(slots=True)
class ADPath:
    nodes: list[str]
    relationships: list[str]
    confidence: str
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BloodHoundAnalysis:
    node_count: int
    edge_count: int
    privileged_targets: list[str]
    paths: list[ADPath]
    risky_edges: list[ADEdge]
    adcs_edges: list[ADEdge]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [
            "# BloodHound / ADCS Offline Path Analysis",
            "",
            "## Summary",
            "",
            f"- Nodes parsed: {self.node_count}",
            f"- Edges parsed: {self.edge_count}",
            f"- Privileged targets identified: {len(self.privileged_targets)}",
            f"- Principal-to-privileged paths found: {len(self.paths)}",
            f"- High-value edges identified: {len(self.risky_edges)}",
            f"- ADCS-related edges identified: {len(self.adcs_edges)}",
            "",
            "## Safety Note",
            "",
            "This analysis is offline graph review only. It does not modify AD, authenticate to targets, dump credentials, or validate exploitation paths on live systems.",
            "",
        ]
        if self.privileged_targets:
            lines += ["## Privileged Targets", ""] + [f"- {item}" for item in self.privileged_targets] + [""]
        if self.paths:
            lines += ["## Candidate Paths", ""]
            for i, path in enumerate(self.paths, 1):
                lines += [f"### Path {i} ({path.confidence})", "", f"- Chain: `{' -> '.join(path.nodes)}`", f"- Relationships: {', '.join(path.relationships)}"]
                lines += [f"- Note: {note}" for note in path.notes] + [""]
        if self.risky_edges:
            lines += ["## High-Value Relationship Inventory", "", "| Source | Relationship | Target |", "|---|---|---|"]
            for edge in self.risky_edges[:100]:
                lines.append(f"| {edge.source_name or edge.source} | {edge.relationship} | {edge.target_name or edge.target} |")
            if len(self.risky_edges) > 100:
                lines.append(f"| ... | truncated | {len(self.risky_edges) - 100} additional edges |")
            lines.append("")
        if self.adcs_edges:
            lines += ["## ADCS-Related Relationship Inventory", "", "| Source | Relationship | Target |", "|---|---|---|"]
            for edge in self.adcs_edges[:100]:
                lines.append(f"| {edge.source_name or edge.source} | {edge.relationship} | {edge.target_name or edge.target} |")
            if len(self.adcs_edges) > 100:
                lines.append(f"| ... | truncated | {len(self.adcs_edges) - 100} additional edges |")
            lines.append("")
        if self.warnings:
            lines += ["## Warnings / Parser Notes", ""] + [f"- {w}" for w in self.warnings] + [""]
        lines += [
            "## Recommended Safe Next Steps", "",
            "1. Validate key graph relationships with read-only commands or existing BloodHound evidence where ROE permits.",
            "2. Classify each path as confirmed, likely, theoretical, or blocked due to safety/ROE constraints.",
            "3. Stop before domain modifications, Tier 0 object changes, broad credential dumping, or actions likely to trigger lockouts/EDR disruption unless explicitly approved.",
            "4. Capture screenshots/exports of the graph path and command output proving each relationship safely validated.",
        ]
        return "\n".join(lines) + "\n"


def analyze_bloodhound(path: str | Path, principal: str | None = None, max_paths: int = 10) -> BloodHoundAnalysis:
    warnings: list[str] = []
    nodes, edges = load_bloodhound(path, warnings=warnings)
    id_to_name = {node.id: node.name for node in nodes.values()}
    for edge in edges:
        edge.source_name = edge.source_name or id_to_name.get(edge.source, "")
        edge.target_name = edge.target_name or id_to_name.get(edge.target, "")
    privileged_ids = [node_id for node_id, node in nodes.items() if _is_privileged_name(node.name)]
    risky_edges = [edge for edge in edges if edge.relationship in HIGH_VALUE_RELATIONSHIPS or _is_risky_relationship(edge.relationship)]
    adcs_edges = [edge for edge in edges if _is_adcs_relationship(edge.relationship) or _is_adcs_name(edge.source_name) or _is_adcs_name(edge.target_name)]
    paths: list[ADPath] = []
    if principal:
        starts = _find_principal_ids(principal, nodes)
        if not starts:
            warnings.append(f"Principal {principal!r} was not found in parsed BloodHound nodes.")
        for start in starts:
            paths.extend(_bfs_paths(start, set(privileged_ids), edges, id_to_name, limit=max_paths - len(paths)))
            if len(paths) >= max_paths:
                break
    else:
        warnings.append("No principal supplied; generated relationship inventory but did not compute principal-to-privileged paths.")
    return BloodHoundAnalysis(
        node_count=len(nodes), edge_count=len(edges), privileged_targets=[nodes[i].name for i in privileged_ids],
        paths=paths[:max_paths], risky_edges=risky_edges, adcs_edges=adcs_edges, warnings=warnings,
    )


def load_bloodhound(path: str | Path, warnings: list[str] | None = None) -> tuple[dict[str, ADNode], list[ADEdge]]:
    warnings = warnings if warnings is not None else []
    nodes: dict[str, ADNode] = {}
    edges: list[ADEdge] = []
    for obj in _iter_json_objects(Path(path), warnings):
        _extract_graph(obj, nodes, edges)
    for edge in edges:
        if edge.source and edge.source not in nodes:
            nodes[edge.source] = ADNode(edge.source, edge.source_name or edge.source, [])
        if edge.target and edge.target not in nodes:
            nodes[edge.target] = ADNode(edge.target, edge.target_name or edge.target, [])
    return nodes, edges


def _iter_json_objects(path: Path, warnings: list[str]) -> Iterable[Any]:
    if path.is_dir():
        for child in sorted(path.rglob("*.json")):
            yield from _iter_json_objects(child, warnings)
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in sorted(zf.namelist()):
                if name.lower().endswith(".json"):
                    try:
                        yield json.loads(zf.read(name).decode("utf-8", errors="replace"))
                    except Exception as exc:
                        warnings.append(f"Could not parse {name} in {path}: {exc}")
    else:
        yield json.loads(path.read_text(encoding="utf-8-sig"))


def _extract_graph(obj: Any, nodes: dict[str, ADNode], edges: list[ADEdge]) -> None:
    if isinstance(obj, list):
        for item in obj:
            _extract_graph(item, nodes, edges)
        return
    if not isinstance(obj, dict):
        return
    for key in ("nodes", "Nodes"):
        if key in obj:
            values = obj[key].values() if isinstance(obj[key], dict) else obj[key]
            if isinstance(values, Iterable):
                for item in values:
                    node = _parse_node(item)
                    if node:
                        nodes[node.id] = node
    for key in ("edges", "Edges", "relationships", "Relationships"):
        if key in obj:
            values = obj[key].values() if isinstance(obj[key], dict) else obj[key]
            if isinstance(values, Iterable):
                for item in values:
                    edge = _parse_edge(item)
                    if edge:
                        edges.append(edge)
    edge = _parse_edge(obj)
    if edge:
        edges.append(edge)
    else:
        node = _parse_node(obj)
        if node:
            nodes[node.id] = node
    for key in ("data", "Data", "results", "graph", "Graph"):
        if key in obj:
            _extract_graph(obj[key], nodes, edges)


def _parse_node(obj: Any) -> ADNode | None:
    if not isinstance(obj, dict):
        return None
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    node_id = _first(obj, props, keys=("id", "objectid", "objectId", "ObjectIdentifier", "sid", "name"))
    name = _first(obj, props, keys=("name", "label", "displayName", "samaccountname")) or node_id
    if not node_id or not name:
        return None
    labels = obj.get("labels") or obj.get("kinds") or []
    if isinstance(labels, str):
        labels = [labels]
    node_type = _first(obj, props, keys=("type", "kind", "objectType", "category"))
    if node_type:
        labels = list(labels) + [node_type]
    return ADNode(str(node_id), str(name), [str(label) for label in labels])


def _parse_edge(obj: Any) -> ADEdge | None:
    if not isinstance(obj, dict):
        return None
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    source_obj = obj.get("source") or obj.get("start") or obj.get("from") or obj.get("sourceid") or obj.get("sourceId") or props.get("source") or props.get("sourceid")
    target_obj = obj.get("target") or obj.get("end") or obj.get("to") or obj.get("targetid") or obj.get("targetId") or props.get("target") or props.get("targetid")
    source, target = _endpoint(source_obj), _endpoint(target_obj)
    if not source or not target:
        return None
    rel = _first(obj, props, keys=("relationship", "kind", "label", "type", "edgeType", "rel")) or "RELATED_TO"
    return ADEdge(str(source), str(target), str(rel), _endpoint_name(source_obj), _endpoint_name(target_obj))


def _first(*dicts: dict[str, Any], keys: tuple[str, ...]) -> str:
    for d in dicts:
        if isinstance(d, dict):
            for key in keys:
                if key in d and d[key] not in (None, ""):
                    return str(d[key])
    return ""


def _endpoint(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        props = value.get("properties") if isinstance(value.get("properties"), dict) else {}
        return _first(value, props, keys=("id", "objectid", "objectId", "ObjectIdentifier", "sid", "name"))
    return str(value)


def _endpoint_name(value: Any) -> str:
    if isinstance(value, dict):
        props = value.get("properties") if isinstance(value.get("properties"), dict) else {}
        return _first(value, props, keys=("name", "label", "displayName"))
    return ""


def _is_privileged_name(name: str) -> bool:
    return any(marker in name.upper() for marker in PRIVILEGED_NAME_MARKERS)


def _is_risky_relationship(rel: str) -> bool:
    return rel in HIGH_VALUE_RELATIONSHIPS or rel.startswith("Can") or rel.startswith("Add") or rel.startswith("Write")


def _is_adcs_relationship(rel: str) -> bool:
    return any(marker.upper() in rel.upper() for marker in ADCS_RELATIONSHIP_MARKERS)


def _is_adcs_name(name: str) -> bool:
    upper = name.upper()
    return "CERTIFICATE" in upper or " ADCS" in upper or "CA@" in upper or "PKI" in upper


def _find_principal_ids(principal: str, nodes: dict[str, ADNode]) -> list[str]:
    needle = principal.lower()
    exact = [node_id for node_id, node in nodes.items() if node.name.lower() == needle or node_id.lower() == needle]
    return exact or [node_id for node_id, node in nodes.items() if needle in node.name.lower() or needle in node_id.lower()]


def _bfs_paths(start: str, targets: set[str], edges: list[ADEdge], id_to_name: dict[str, str], limit: int = 10) -> list[ADPath]:
    adjacency: dict[str, list[ADEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source, []).append(edge)
    results: list[ADPath] = []
    queue = deque([(start, [start], [])])
    while queue and len(results) < limit:
        current, node_path, rel_path = queue.popleft()
        if current in targets and current != start:
            results.append(ADPath(
                nodes=[id_to_name.get(node, node) for node in node_path], relationships=rel_path,
                confidence="likely graph path", notes=["Validate each relationship safely before reporting as confirmed."],
            ))
            continue
        if len(node_path) > 12:
            continue
        for edge in adjacency.get(current, []):
            if edge.target in node_path:
                continue
            queue.append((edge.target, node_path + [edge.target], rel_path + [edge.relationship]))
    return results
