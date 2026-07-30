from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import re
import shlex


@dataclass(slots=True)
class PlannedToolCall:
    tool: str
    args: dict[str, Any]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AgentPlan:
    prompt: str
    summary: str
    tool_calls: list[PlannedToolCall] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "summary": self.summary,
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "warnings": self.warnings,
        }


COMMANDISH_PREFIXES = ("assess", "evaluate", "check", "run", "execute", "start", "background")


def plan_agent_actions(prompt: str, *, allow_command_execution: bool = False) -> AgentPlan:
    """Build a conservative deterministic tool plan from natural language.

    This is intentionally not a jailbreakable LLM planner. It recognizes common
    operator intents and returns explicit registry tool calls. Target-affecting
    calls still pass through the normal ROE guardrails; command execution is not
    enabled unless the operator explicitly passes allow_command_execution=True.
    """

    text = prompt.strip()
    lower = text.lower()
    calls: list[PlannedToolCall] = []
    warnings: list[str] = []

    if not text:
        return AgentPlan(prompt=prompt, summary="No prompt supplied.", warnings=["Provide an operator prompt to plan from."])

    command_args = _extract_command_args(text)
    if command_args:
        wants_start = lower.startswith("start") or "background" in lower
        wants_run = lower.startswith(("run", "execute")) or " execute=true" in lower or " execute it" in lower
        if wants_start:
            command_args["execute"] = bool(allow_command_execution)
            calls.append(PlannedToolCall("start_process", command_args, "Operator requested a guarded background process."))
        elif wants_run:
            command_args["execute"] = bool(allow_command_execution)
            calls.append(PlannedToolCall("run_command", command_args, "Operator requested guarded command execution."))
        else:
            calls.append(PlannedToolCall("assess_action", command_args, "Operator supplied target/command details; assess before execution."))
        if not allow_command_execution and (wants_run or wants_start):
            warnings.append("Command execution was requested, but this plan leaves execute=false unless /auto execute=true is supplied.")

    remember = _extract_memory(text)
    if remember:
        calls.append(PlannedToolCall("remember", remember, "Operator asked to store local agent memory."))

    recall_query = _extract_recall_query(text)
    if recall_query:
        calls.append(PlannedToolCall("recall", {"query": recall_query, "limit": 10}, "Operator asked to recall local memory."))

    forget_key = _extract_forget_memory(text)
    if forget_key:
        calls.append(PlannedToolCall("forget_memory", {"key": forget_key}, "Operator asked to delete a local memory entry."))

    local_ref = _extract_local_ref(text)
    if local_ref:
        calls.append(PlannedToolCall("resolve_local_ref", {"ref": local_ref}, "Operator asked to inspect a local drill-down ref."))

    session_query = _extract_session_query(text)
    if session_query:
        calls.append(PlannedToolCall("search_session", {"query": session_query, "limit": 10}, "Operator asked to search session history."))

    workspace_read = _extract_read_path(text)
    if workspace_read:
        calls.append(PlannedToolCall("workspace_read", {"path": workspace_read}, "Operator asked to read a workspace file."))

    workspace_search = _extract_workspace_search(text)
    if workspace_search:
        calls.append(PlannedToolCall("workspace_search", workspace_search, "Operator asked to search workspace files."))

    task = _extract_task(text)
    if task:
        calls.append(PlannedToolCall("add_task", task, "Operator asked to add a task-board item."))

    if "briefing" in lower or "operator brief" in lower or "status briefing" in lower:
        calls.append(PlannedToolCall("operator_briefing", {}, "Operator asked for a Hermes-like session briefing."))

    if "handoff" in lower or "export session" in lower or "session export" in lower:
        calls.append(PlannedToolCall("export_session", {}, "Operator asked to export a portable session handoff."))

    if "list tools" in lower or lower in {"tools", "what tools are available", "show tools"}:
        calls.append(PlannedToolCall("tool_schemas", {}, "Operator asked for available tool schemas."))

    if not calls:
        warnings.append("No direct tool intent was recognized; use /tools or /schemas to inspect available commands.")
        return AgentPlan(prompt=prompt, summary="No executable tool plan recognized.", warnings=warnings)

    return AgentPlan(prompt=prompt, summary=f"Planned {len(calls)} tool call(s).", tool_calls=calls, warnings=warnings)


def _extract_command_args(text: str) -> dict[str, Any] | None:
    if "target=" not in text or "command=" not in text:
        return None
    # Drop a leading English verb so shlex sees a plain key=value stream.
    body = text.strip()
    first = body.split(maxsplit=1)[0].lower() if body.split() else ""
    if first in COMMANDISH_PREFIXES and len(body.split(maxsplit=1)) > 1:
        body = body.split(maxsplit=1)[1]
    args = _parse_key_values(body)
    if "target" not in args or "command" not in args:
        return None
    args.setdefault("type", args.get("action_type", "host"))
    args.setdefault("purpose", "auto-planned operator request")
    return args


def _extract_memory(text: str) -> dict[str, str] | None:
    match = re.search(r"(?is)\bremember\s+(.+)$", text.strip())
    if not match:
        return None
    body = match.group(1).strip()
    if not body:
        return None
    if ":" in body:
        key, value = body.split(":", 1)
    else:
        split = re.split(r"\s+is\s+|\s+as\s+", body, maxsplit=1, flags=re.IGNORECASE)
        if len(split) == 2:
            key, value = split
        else:
            pieces = body.split(maxsplit=1)
            if len(pieces) < 2:
                return None
            key, value = pieces
    key = _slug_key(key)
    value = value.strip().strip('"\'')
    if not key or not value:
        return None
    return {"key": key, "value": value, "tags": "auto"}


def _extract_recall_query(text: str) -> str | None:
    match = re.search(r"(?is)\b(?:recall|search memory for|remembered about)\s+(.+)$", text.strip())
    if match:
        return match.group(1).strip().strip('"\'')
    return None


def _extract_forget_memory(text: str) -> str | None:
    match = re.search(r"(?is)\b(?:forget|delete memory|remove memory|purge memory)\s+(?:memory\s+)?(.+)$", text.strip())
    if not match:
        return None
    key = match.group(1).strip().strip('"\'')
    if not key:
        return None
    return _slug_key(key)


def _extract_local_ref(text: str) -> str | None:
    match = re.search(
        r"(?is)\b(?:show|inspect|resolve|open|get|detail|details?|drill\s*down)\s+(?:ref\s+|reference\s+)?(?P<ref>[a-z][a-z0-9_-]{1,32}:[^\s]+)\s*$",
        text.strip(),
    )
    if match:
        return match.group("ref").strip().strip('"\'')
    if re.fullmatch(r"(?is)[a-z][a-z0-9_-]{1,32}:[^\s]+", text.strip()):
        return text.strip()
    return None


def _extract_session_query(text: str) -> str | None:
    match = re.search(r"(?is)\b(?:search session for|find in session)\s+(.+)$", text.strip())
    if match:
        return match.group(1).strip().strip('"\'')
    return None


def _extract_read_path(text: str) -> str | None:
    match = re.search(r"(?is)^\s*(?:read|open|show)\s+(?:workspace\s+file\s+)?(?P<path>[A-Za-z0-9_./-]+)\s*$", text)
    return match.group("path") if match else None


def _extract_workspace_search(text: str) -> dict[str, Any] | None:
    match = re.search(r"(?is)\bsearch\s+workspace\s+(?:for\s+)?(?P<query>.+)$", text.strip())
    if not match:
        return None
    return {"query": match.group("query").strip().strip('"\''), "glob": "**/*", "limit": 20}


def _extract_task(text: str) -> dict[str, str] | None:
    match = re.search(r"(?is)\b(?:add task|task|todo)\s*:?\s+(.+)$", text.strip())
    if not match:
        return None
    content = match.group(1).strip().strip('"\'')
    if not content:
        return None
    return {"content": content, "status": "pending"}


def _parse_key_values(body: str) -> dict[str, Any]:
    args: dict[str, Any] = {}
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        args[key.replace("-", "_")] = _coerce(value)
    return args


def _coerce(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"true", "yes", "1"}:
        return True
    if lowered in {"false", "no", "0"}:
        return False
    if lowered.isdigit():
        return int(lowered)
    return value


def _slug_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value.strip().lower()).strip("-")
