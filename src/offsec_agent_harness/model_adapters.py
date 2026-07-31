from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import os
import re
import shlex
import subprocess
import tempfile
import urllib.error
import urllib.request

from .models import redact_secrets


ROLE_SYSTEM_PROMPTS = {
    "assistant": "You are Phobos, a professional penetration-test assistant for authorized engagements. Speak naturally and directly. Help the operator turn vague findings into safe, evidence-backed next steps. Be concise by default, practical, and candid about uncertainty. Preserve ROE: never imply permission to exceed scope, never claim a tool ran unless the runtime/tool path actually ran it, and keep destructive, DoS, persistence, evasion, malware-like, or lockout-prone work blocked or approval-gated. Avoid boilerplate such as 'Phobos Agent response'.",
    "scope": "You are a scope and rules-of-engagement reviewer for authorized security testing. Identify scope ambiguity, prohibited actions, and stop conditions.",
    "safety": "You are a disruption-safety reviewer. Prefer non-destructive validation, no DoS, no persistence, no evasion, no avoidable lockouts, and evidence-first alternatives.",
    "evidence": "You are an evidence analyst. Extract what the artifact proves, confidence, missing evidence, and negative controls needed.",
    "impact": "You are an impact-chain analyst for authorized pentests. Push for maximum realistic impact that can be proven safely within ROE, while separating proven facts from plausible theory.",
    "cve": "You are a CVE analyst. Prefer non-invasive validation and clearly flag PoCs that may cause denial of service or destructive side effects.",
    "report": "You draft confirmed-finding report language: neutral tone, evidence-backed claims, affected assets, and actionable remediation without overclaiming.",
}


@dataclass(slots=True)
class ModelResponse:
    provider: str
    role: str
    content: str
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"provider": self.provider, "role": self.role, "content": self.content, "raw": self.raw or {}}


class BaseModelAdapter:
    provider = "base"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        raise NotImplementedError

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        """Ask the adapter for structured Phobos tool calls.

        Adapters that do not support a provider-native tool-calling API inherit
        the existing JSON-content planner contract. Native adapters may override
        this method, but they must still return a JSON object in ``content`` with
        ``summary``, ``tool_calls`` and ``warnings`` so the runtime can validate
        names/schemas/ROE before any dispatch or approval queueing.
        """

        return self.generate(
            "impact",
            _tool_plan_prompt(prompt, tool_specs, allow_command_execution=allow_command_execution),
            context=context,
        )


class HeuristicAdapter(BaseModelAdapter):
    provider = "heuristic"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        sections = {
            "assistant": ["I’d handle it like a pentest assistant:", "- Confirm the exact in-scope asset, objective, and evidence you already have.", "- Use the least-invasive check that proves impact.", "- Capture clean evidence and stop before destructive, DoS, persistence, evasion, or lockout-prone actions.", "- If you want Phobos to act, use an explicit slash command so ROE and approvals can evaluate it."],
            "scope": ["Scope / ROE Review", "- Confirm the target appears in the engagement scope before action.", "- Identify prohibited techniques and testing-window constraints.", "- Define stop conditions before state-changing or noisy validation."],
            "safety": ["Safety / Disruption Review", "- Prefer read-only or single-request validation.", "- Avoid destructive changes, denial-of-service conditions, persistence, evasion, and avoidable account lockouts.", "- Use controlled test objects and document cleanup."],
            "evidence": ["Evidence Review", "- Record exact asset, role/access level, timestamp, request/command, and observed result.", "- Add a negative control where feasible.", "- Mark unproven claims as missing evidence, not report findings."],
            "impact": ["Safe Impact Plan", "- Define the currently proven weakness.", "- Choose the minimum safe next action that proves realistic business impact.", "- Stop before bulk access, destructive activity, DoS, persistence, or evasion."],
            "cve": ["CVE Review", "- Confirm product/version/configuration against vendor advisories.", "- Prefer non-invasive checks and lab reproduction.", "- Do not run PoCs with crash/resource-exhaustion risk in production without explicit ROE approval."],
            "report": ["Report Drafting Notes", "- Use confirmed evidence only.", "- Describe what was observed, affected assets, impact, and remediation.", "- Avoid overclaiming beyond the evidence supplied."],
        }
        body = "\n".join(sections[role])
        if context:
            body += "\n\nContext considered:\n" + _truncate(context, 1500)
        body += "\n\nOperator prompt:\n" + _truncate(prompt, 1500)
        return ModelResponse(provider=self.provider, role=role, content=body)


class OpenAICompatibleAdapter(BaseModelAdapter):
    provider = "openai-compatible"

    def __init__(self, model: str, base_url: str = "https://api.openai.com/v1", key_env: str = "OPENAI_API_KEY", timeout: int = 60):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.key_env = key_env
        self.timeout = timeout

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        messages = [
            {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
            {"role": "user", "content": (context + "\n\n" if context else "") + prompt},
        ]
        payload = {"model": self.model, "messages": messages, "temperature": 0.2}
        raw = self._chat_completion(payload)
        message = _first_choice_message(raw)
        content = _message_content_text(message.get("content", ""))
        return ModelResponse(provider=self.provider, role=role, content=content, raw={"model": self.model, "base_url": self.base_url})

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        """Use OpenAI-compatible native tool calls when the endpoint supports them.

        The runtime still performs the authoritative validation and execution
        gating. This method only translates provider-native ``tool_calls`` into
        the same JSON plan shape used by deterministic/fake planners, and it
        avoids returning raw provider payloads or secrets in ``raw``.
        """

        tools = [_openai_tool_from_spec(spec) for spec in tool_specs[:80]]
        tools = [tool for tool in tools if tool is not None]
        messages = [
            {"role": "system", "content": ROLE_SYSTEM_PROMPTS["impact"]},
            {
                "role": "user",
                "content": (context + "\n\n" if context else "")
                + (
                    "Plan Phobos Agent tool calls for the authorized operator request. "
                    "Use provider-native tool calls when a tool is needed. Do not claim a tool ran. "
                    "If no tool is needed, respond with a concise summary and no tool calls. "
                    "Target-affecting tools still go through ROE guardrails after planning. "
                    "If command execution is not explicitly allowed, request execute=false.\n\n"
                    f"Command execution allowed: {allow_command_execution}\n"
                    f"Operator request: {prompt}"
                ),
            },
        ]
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": 0.2}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        else:
            payload["messages"][1]["content"] += "\n\n" + _tool_plan_prompt(prompt, tool_specs, allow_command_execution=allow_command_execution)
        raw = self._chat_completion(payload)
        message = _first_choice_message(raw)
        plan_content, meta = _native_tool_calls_to_plan_content(message)
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=plan_content,
            raw={
                "model": self.model,
                "base_url": self.base_url,
                "native_tool_calls": meta["native_tool_calls"],
                "native_tool_call_count": meta["native_tool_call_count"],
                "rejected_native_tool_call_count": meta["rejected_native_tool_call_count"],
            },
        )

    def _chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self.key_env, "")
        if not api_key and not _is_local_base_url(self.base_url):
            raise RuntimeError(f"Missing API key environment variable {self.key_env}")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(self.base_url + "/chat/completions", data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Model endpoint HTTP {exc.code}: {body[:500]}") from exc


class HermesCLIAdapter(BaseModelAdapter):
    provider = "hermes-cli"

    def __init__(self, command_template: str, timeout: int = 120):
        self.command_template = command_template
        self.timeout = timeout

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        full_prompt = ROLE_SYSTEM_PROMPTS[role] + "\n\n" + (context + "\n\n" if context else "") + prompt
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".prompt.txt") as handle:
            handle.write(full_prompt)
            prompt_file = handle.name
        try:
            command = self.command_template.format(prompt_file=shlex.quote(prompt_file), role=shlex.quote(role))
            completed = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=self.timeout, check=False)
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr[-1000:] or f"Hermes CLI command exited {completed.returncode}")
            return ModelResponse(provider=self.provider, role=role, content=completed.stdout)
        finally:
            Path(prompt_file).unlink(missing_ok=True)


class FallbackModelAdapter(BaseModelAdapter):
    """Try model adapters in order, mirroring Hermes-style provider fallback."""

    provider = "fallback"

    def __init__(self, adapters: list[BaseModelAdapter]):
        if not adapters:
            raise ValueError("FallbackModelAdapter requires at least one adapter")
        self.adapters = adapters

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        attempts: list[dict[str, str]] = []
        for adapter in self.adapters:
            try:
                response = adapter.generate(role, prompt, context=context)
                raw = dict(response.raw or {})
                raw["fallback_attempts"] = attempts
                raw["selected_provider"] = response.provider
                return ModelResponse(
                    provider=response.provider if len(self.adapters) == 1 else f"fallback:{response.provider}",
                    role=response.role,
                    content=response.content,
                    raw=raw,
                )
            except Exception as exc:  # pragma: no cover - provider failures depend on operator config
                attempts.append({"provider": getattr(adapter, "provider", adapter.__class__.__name__), "error": _safe_error(exc)})
        raise RuntimeError("All model providers failed: " + json.dumps(attempts))

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        """Try provider-native/JSON tool planning through each configured provider.

        Tool planning must preserve the same fallback behavior as normal chat
        generation.  Calling ``generate(...)`` here would bypass adapters that
        implement provider-native tool calls, so each provider gets the full
        ``generate_tool_plan(...)`` contract and the runtime still validates the
        returned tool names, schemas, runtime policy, and ROE before dispatch.
        """

        attempts: list[dict[str, str]] = []
        for adapter in self.adapters:
            try:
                response = adapter.generate_tool_plan(
                    prompt,
                    tool_specs,
                    allow_command_execution=allow_command_execution,
                    context=context,
                )
                raw = dict(response.raw or {})
                raw["fallback_attempts"] = attempts
                raw["selected_provider"] = response.provider
                raw["tool_plan_fallback"] = True
                return ModelResponse(
                    provider=response.provider if len(self.adapters) == 1 else f"fallback:{response.provider}",
                    role=response.role,
                    content=response.content,
                    raw=raw,
                )
            except Exception as exc:  # pragma: no cover - provider failures depend on operator config
                attempts.append({"provider": getattr(adapter, "provider", adapter.__class__.__name__), "error": _safe_error(exc)})
        raise RuntimeError("All model tool planners failed: " + json.dumps(attempts))


def build_fallback_adapter(provider_configs: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> BaseModelAdapter:
    adapters = [
        build_adapter(
            str(config.get("provider", "heuristic")),
            model=str(config.get("model", "gpt-4o-mini")),
            base_url=config.get("base_url"),
            key_env=str(config.get("key_env", "OPENAI_API_KEY")),
            command_template=config.get("command_template"),
        )
        for config in provider_configs
        if config
    ]
    if not adapters:
        return HeuristicAdapter()
    if len(adapters) == 1:
        return adapters[0]
    return FallbackModelAdapter(adapters)


def build_adapter(provider: str, model: str = "gpt-4o-mini", base_url: str | None = None, key_env: str = "OPENAI_API_KEY", command_template: str | None = None) -> BaseModelAdapter:
    provider = provider.lower()
    if provider == "heuristic":
        return HeuristicAdapter()
    if provider in {"openai", "openai-compatible"}:
        return OpenAICompatibleAdapter(model=model, base_url=base_url or "https://api.openai.com/v1", key_env=key_env)
    if provider in {"local", "ollama"}:
        return OpenAICompatibleAdapter(model=model, base_url=base_url or "http://127.0.0.1:11434/v1", key_env=key_env)
    if provider in {"hermes", "hermes-cli"}:
        if not command_template:
            raise RuntimeError("hermes-cli provider requires --command-template with {prompt_file}")
        return HermesCLIAdapter(command_template=command_template)
    raise ValueError(f"Unsupported model provider: {provider}")


def _is_local_base_url(base_url: str) -> bool:
    return "127.0.0.1" in base_url or "localhost" in base_url


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "\n...[truncated]"


def _safe_error(exc: Exception) -> str:
    return (redact_secrets(str(exc)) or exc.__class__.__name__)[:500]


def _tool_plan_prompt(prompt: str, tool_specs: list[dict[str, Any]], *, allow_command_execution: bool) -> str:
    return (
        "You are planning Phobos Agent tool calls. Return ONLY JSON with keys summary, tool_calls, warnings. "
        "tool_calls must be a list of {tool, args, reason}. Use only registered tools. Do not invent tools. "
        "Target-affecting tools still go through ROE guardrails. If command execution is not explicitly allowed, set execute=false.\n\n"
        f"Command execution allowed: {allow_command_execution}\n"
        f"Operator request: {prompt}\n\n"
        f"Registered tools: {json.dumps(tool_specs[:80], indent=2)[:30000]}"
    )


def _first_choice_message(raw: dict[str, Any]) -> dict[str, Any]:
    choices = raw.get("choices") if isinstance(raw, dict) else []
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict) and isinstance(first.get("message"), dict):
            return first["message"]
    return {}


def _message_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return "" if content is None else str(content)


def _native_tool_calls_to_plan_content(message: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    content_value = message.get("content", "")
    content_text = _message_content_text(content_value).strip()
    calls: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_calls = message.get("tool_calls")
    if isinstance(raw_calls, list):
        for index, item in enumerate(raw_calls, start=1):
            parsed, rejected_item, warning = _parse_native_tool_call(item, index=index)
            if warning:
                warnings.append(warning)
            if parsed:
                calls.append(parsed)
            if rejected_item:
                rejected.append(rejected_item)
    content_calls, content_rejected, content_warnings = _parse_native_content_tool_blocks(
        content_value,
        start_index=len(calls) + len(rejected) + 1,
    )
    calls.extend(content_calls)
    rejected.extend(content_rejected)
    warnings.extend(content_warnings)
    legacy_function = message.get("function_call")
    if isinstance(legacy_function, dict):
        parsed, rejected_item, warning = _parse_native_function_call(legacy_function, index=len(calls) + len(rejected) + 1, legacy=True)
        if warning:
            warnings.append(warning)
        if parsed:
            calls.append(parsed)
        if rejected_item:
            rejected.append(rejected_item)
    if calls or rejected or warnings:
        payload = {
            "summary": content_text or f"Provider returned {len(calls)} native tool call(s).",
            "tool_calls": calls,
            "warnings": warnings,
        }
        if rejected:
            payload["rejected_tool_calls"] = rejected
        return json.dumps(payload), {
            "native_tool_calls": bool(calls),
            "native_tool_call_count": len(calls),
            "rejected_native_tool_call_count": len(rejected),
        }
    if content_text.startswith("{") and content_text.endswith("}"):
        return content_text, {"native_tool_calls": False, "native_tool_call_count": 0, "rejected_native_tool_call_count": 0}
    return json.dumps({"summary": content_text or "Provider returned no tool calls.", "tool_calls": [], "warnings": []}), {
        "native_tool_calls": False,
        "native_tool_call_count": 0,
        "rejected_native_tool_call_count": 0,
    }


def _parse_native_content_tool_blocks(
    content: Any,
    *,
    start_index: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Translate content-block tool-call variants into the common plan shape.

    Some OpenAI-compatible shims and provider bridges surface native tool calls
    inside ``message.content`` blocks rather than the top-level ``tool_calls``
    array.  Treat these as planner proposals only: the runtime still performs
    schema validation, runtime policy, ROE preview, and guarded dispatch later.
    """

    if not isinstance(content, list):
        return [], [], []
    calls: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    warnings: list[str] = []
    index = max(1, start_index)
    for item in content:
        if not isinstance(item, dict):
            continue
        block_type = str(item.get("type") or "").strip()
        if block_type not in {"tool_use", "tool_call", "function_call"}:
            continue
        parsed, rejected_item, warning = _parse_native_content_tool_block(item, index=index, block_type=block_type)
        if warning:
            warnings.append(warning)
        if parsed:
            calls.append(parsed)
        if rejected_item:
            rejected.append(rejected_item)
        index += 1
    return calls, rejected, warnings


def _parse_native_content_tool_block(
    item: dict[str, Any],
    *,
    index: int,
    block_type: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    function = item.get("function")
    call_id = str(item.get("id") or "")
    if isinstance(function, dict):
        return _parse_native_function_call(
            function,
            index=index,
            legacy=False,
            call_id=call_id,
            label=f"native content-block {block_type}",
        )
    arguments = item.get("input", item.get("arguments", {}))
    return _parse_native_function_call(
        {"name": item.get("name"), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=call_id,
        label=f"native content-block {block_type}",
    )


def _parse_native_tool_call(item: Any, *, index: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    if not isinstance(item, dict):
        return None, {"tool": None, "reason": "Native tool call must be an object.", "args": {"value_type": type(item).__name__}}, "Native tool call was not an object; skipped."
    native_type = item.get("type")
    if native_type not in {None, "function", "tool_call", "tool_use"}:
        return None, {"tool": None, "reason": "Only function tool calls are supported.", "args": {"native_type": str(native_type)}}, "Native non-function tool call skipped."
    function = item.get("function")
    if isinstance(function, dict):
        return _parse_native_function_call(function, index=index, legacy=False, call_id=str(item.get("id") or ""))
    # Several OpenAI-compatible shims flatten top-level tool calls instead of
    # nesting them under {"function": {"name", "arguments"}}.  Treat these as
    # planner proposals only; runtime schema/ROE validation remains authoritative.
    name = item.get("name") or item.get("tool")
    if isinstance(function, str) and not name:
        name = function
    if name:
        arguments = item.get("arguments", item.get("args", item.get("input", {})))
        return _parse_native_function_call(
            {"name": name, "arguments": arguments},
            index=index,
            legacy=False,
            call_id=str(item.get("id") or item.get("call_id") or ""),
            label="native provider flat tool_call",
        )
    return None, {"tool": None, "reason": "Native tool call missing function payload.", "args": {}}, "Native tool call missing function payload; skipped."


def _parse_native_function_call(
    function: dict[str, Any],
    *,
    index: int,
    legacy: bool,
    call_id: str = "",
    label: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    name = str(function.get("name") or "").strip()
    if not name:
        return None, {"tool": None, "reason": "Native function call missing tool name.", "args": {}}, "Native function call missing a name; skipped."
    args, error = _parse_native_arguments(function.get("arguments"))
    if error:
        return None, {"tool": name, "reason": error, "args": {}}, f"Native arguments for {name} were invalid; skipped."
    label = label or ("legacy native function_call" if legacy else "native provider tool_call")
    suffix = f" ({call_id})" if call_id else f" #{index}"
    return {"tool": name, "args": args, "reason": f"Model requested {label}{suffix}."}, None, None


def _parse_native_arguments(value: Any) -> tuple[dict[str, Any], str | None]:
    if value in (None, ""):
        return {}, None
    if isinstance(value, dict):
        return dict(value), None
    if not isinstance(value, str):
        return {}, "Native tool arguments must be a JSON object."
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}, "Native tool arguments were not valid JSON."
    if not isinstance(parsed, dict):
        return {}, "Native tool arguments must decode to a JSON object."
    return parsed, None


_OPENAI_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_OPENAI_SCHEMA_KEYS = {
    "type",
    "description",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "items",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
}


def _openai_tool_from_spec(spec: dict[str, Any]) -> dict[str, Any] | None:
    name = str(spec.get("name") or "").strip()
    if not _OPENAI_TOOL_NAME_RE.fullmatch(name):
        return None
    description = str(spec.get("description") or name)
    parameters = _sanitize_tool_schema(spec.get("schema") if isinstance(spec.get("schema"), dict) else {"type": "object", "properties": {}})
    if not isinstance(parameters, dict) or parameters.get("type") != "object":
        parameters = {"type": "object", "properties": {}}
    parameters.setdefault("properties", {})
    parameters.setdefault("required", [])
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": _truncate(description, 1024),
            "parameters": parameters,
        },
    }


def _sanitize_tool_schema(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key not in _OPENAI_SCHEMA_KEYS:
                continue
            if key == "properties" and isinstance(item, dict):
                out[key] = {str(prop): _sanitize_tool_schema(prop_schema) for prop, prop_schema in item.items() if isinstance(prop_schema, dict)}
            elif key == "items":
                out[key] = _sanitize_tool_schema(item)
            elif key == "required" and isinstance(item, list):
                out[key] = [str(entry) for entry in item if isinstance(entry, str)]
            elif key == "enum" and isinstance(item, list):
                out[key] = [entry for entry in item if isinstance(entry, str | int | float | bool) or entry is None]
            elif isinstance(item, dict | list):
                out[key] = _sanitize_tool_schema(item)
            else:
                out[key] = item
        if "properties" in out and "type" not in out:
            out["type"] = "object"
        return out
    if isinstance(value, list):
        return [_sanitize_tool_schema(item) for item in value]
    return value
