from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import re


@dataclass(slots=True)
class LocalSkill:
    name: str
    path: str
    description: str = ""
    triggers: list[str] | None = None
    metadata: dict[str, Any] | None = None
    content: str = ""

    def to_dict(self, *, include_content: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_content:
            data.pop("content", None)
        return data


def discover_skills(skill_dirs: tuple[str, ...] | list[str]) -> dict[str, LocalSkill]:
    """Discover local SKILL.md files without loading their full bodies.

    This mirrors Hermes-style progressive disclosure: listing skills is cheap and
    only reads frontmatter/heading-level metadata until the operator explicitly
    loads a skill.
    """

    skills: dict[str, LocalSkill] = {}
    for root in _skill_roots(skill_dirs):
        for path in sorted(root.rglob("SKILL.md")):
            if not _is_relative_to(path.resolve(), root):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            metadata, body = _parse_frontmatter(text)
            name = _normalize_name(str(metadata.get("name") or path.parent.name))
            if not name:
                continue
            description = str(metadata.get("description") or _first_heading_or_sentence(body))
            triggers = metadata.get("triggers") if isinstance(metadata.get("triggers"), list) else []
            skills[name] = LocalSkill(
                name=name,
                path=str(path),
                description=description,
                triggers=[str(item) for item in triggers],
                metadata=metadata,
            )
    return skills


def load_skill(name: str, skill_dirs: tuple[str, ...] | list[str]) -> LocalSkill:
    normalized = _normalize_name(name)
    if not normalized or normalized != name.strip().lower():
        raise ValueError("skill name must be a simple local name, not a path")
    skills = discover_skills(skill_dirs)
    if normalized not in skills:
        raise KeyError(f"Skill not found: {normalized}")
    skill = skills[normalized]
    content = Path(skill.path).read_text(encoding="utf-8", errors="replace")
    metadata, body = _parse_frontmatter(content)
    return LocalSkill(
        name=skill.name,
        path=skill.path,
        description=skill.description,
        triggers=skill.triggers or [],
        metadata=metadata,
        content=body.strip() or content.strip(),
    )


def render_loaded_skills(skills: dict[str, LocalSkill], *, max_chars: int = 8000) -> str:
    if not skills:
        return ""
    parts = []
    remaining = max_chars
    for name in sorted(skills):
        skill = skills[name]
        chunk = f"## Loaded skill: {skill.name}\nDescription: {skill.description}\nSource: {skill.path}\n\n{skill.content.strip()}\n"
        if len(chunk) > remaining:
            chunk = chunk[: max(0, remaining)] + "\n...[skill truncated]"
        parts.append(chunk)
        remaining -= len(chunk)
        if remaining <= 0:
            break
    return "\n\n".join(parts)


def _skill_roots(skill_dirs: tuple[str, ...] | list[str]) -> list[Path]:
    roots: list[Path] = []
    for item in skill_dirs:
        if not str(item).strip():
            continue
        root = Path(item).expanduser().resolve()
        if root.exists() and root.is_dir():
            roots.append(root)
    return roots


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    raw = text[4:end]
    body = text[text.find("\n", end + 4) + 1 :]
    return _parse_simple_yaml(raw), body


def _parse_simple_yaml(raw: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_key: str | None = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        if line.startswith("  - ") and current_key:
            data.setdefault(current_key, []).append(line[4:].strip().strip('"\''))
            continue
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            current_key = key
            if value == "":
                data[key] = []
            elif value.startswith("[") and value.endswith("]"):
                data[key] = [item.strip().strip('"\'') for item in value[1:-1].split(",") if item.strip()]
            else:
                data[key] = value.strip('"\'')
    return data


def _first_heading_or_sentence(body: str) -> str:
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
        if stripped:
            return stripped[:160]
    return ""


def _normalize_name(value: str) -> str:
    value = value.strip().lower()
    if "/" in value or "\\" in value or ".." in value:
        return ""
    return re.sub(r"[^a-z0-9_-]+", "-", value).strip("-")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
