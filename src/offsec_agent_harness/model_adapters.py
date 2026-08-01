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
    candidate_message = _candidate_content_to_message(raw)
    if candidate_message:
        return candidate_message
    responses_message = _responses_output_to_message(raw)
    if responses_message:
        return responses_message
    top_level_message = _top_level_content_message(raw)
    if top_level_message:
        return top_level_message
    return {}


def _message_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        content_parts = _native_content_parts(content)
        if content_parts is not None:
            return _message_content_text(content_parts)
        return _message_content_text([content])
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                block_type = str(item.get("type") or "").strip()
                if block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES | _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES | _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
                    # Provider-side tool-call/result blocks are planner state,
                    # not assistant summary text.  In particular, ``tool_result``
                    # content may contain raw tool output from an upstream model
                    # loop and must never be copied into Phobos plan summaries.
                    continue
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return "" if content is None else str(content)


def _native_argument_keys(preferred: tuple[str, ...]) -> list[str]:
    """Return provider argument keys plus common JSON alias variants.

    Most providers use ``arguments``, ``args`` or ``input``.  A few
    OpenAI-compatible and bridge shims expose the same payload under aliases
    such as ``arguments_json`` or camelCase ``inputJson``.  Normalize those at
    the adapter boundary so schema/ROE/runtime-policy validation still happens
    in the Phobos runtime rather than requiring provider-specific planner code.
    """

    keys: list[str] = []
    for raw_key in preferred:
        key = str(raw_key or "").strip()
        if not key:
            continue
        for candidate in (key, f"{key}_json", f"{key}Json"):
            if candidate not in keys:
                keys.append(candidate)
    return keys


def _native_argument_value(
    mapping: dict[str, Any],
    *,
    preferred: tuple[str, ...] = ("arguments", "args", "input", "parameters", "params"),
) -> Any:
    if not isinstance(mapping, dict):
        return {}
    first_present: Any = None
    has_present = False
    for key in _native_argument_keys(preferred):
        if key not in mapping:
            continue
        value = mapping.get(key)
        if not has_present:
            first_present = value
            has_present = True
        if value not in (None, ""):
            return value
    return first_present if has_present else {}


def _native_content_parts(content: Any) -> list[Any] | None:
    """Return Gemini-style content parts from a message/content object.

    A few OpenAI-compatible shims wrap Gemini-style ``parts`` under
    ``choices[].message.content`` or a top-level ``content`` object instead of
    returning a top-level ``candidates`` array.  Normalize those parts at the
    adapter boundary so functionCall proposals still enter Phobos' normal
    schema/runtime-policy/ROE validation path and provider result echoes remain
    ignored planner state.
    """

    if not isinstance(content, dict) or "parts" not in content:
        return None
    parts = content.get("parts")
    if isinstance(parts, dict):
        return [parts]
    if isinstance(parts, list):
        return parts
    return None


def _candidate_content_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize candidate/part native function calls into the common shape.

    Some OpenAI-compatible gateways front providers that expose Gemini-style
    ``candidates[].content.parts[]`` payloads with camelCase ``functionCall``
    entries and ``args``/``parameters`` objects instead of Chat Completions
    ``tool_calls``.  Treat them exactly like other planner proposals: translate
    only the requested registered-call shape and leave all ROE/schema/runtime
    enforcement to the Phobos runtime.  Provider-side ``functionResponse``
    echoes are preserved only as ignored result blocks so their content never
    becomes summary text or dispatch input.
    """

    if not isinstance(raw, dict):
        return {}
    candidates = raw.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return {}
    first = candidates[0]
    if not isinstance(first, dict):
        return {}
    content = first.get("content") if isinstance(first.get("content"), dict) else {}
    parts = content.get("parts") if isinstance(content, dict) else None
    if isinstance(parts, dict):
        # Some Gemini/OpenAI-compatible shims collapse a one-part candidate
        # response into a single object instead of candidates[].content.parts[].
        # Normalize at the adapter boundary so the runtime can still enforce the
        # exact same schema, runtime-policy, ROE, and transcript provenance rules
        # before anything can dispatch.
        parts = [parts]
    elif not isinstance(parts, list):
        return {}
    content_blocks: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str):
            content_blocks.append({"type": "text", "text": text})
        function_call = part.get("functionCall") or part.get("function_call")
        if isinstance(function_call, dict):
            call_id = _native_call_id(function_call)
            tool_calls.append({
                "type": "tool_call",
                "name": function_call.get("name") or function_call.get("tool"),
                "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                "call_id": str(call_id),
                "_provider_shape": "gemini.candidate",
            })
        function_response = part.get("functionResponse") or part.get("function_response")
        if isinstance(function_response, dict):
            content_blocks.append({"type": "tool_result", "content": function_response.get("response") or function_response.get("content") or ""})
    if not content_blocks and not tool_calls:
        return {}
    return {"content": content_blocks, "tool_calls": tool_calls}


def _responses_output_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Responses-style output blocks into a chat message shape.

    OpenAI-compatible shims usually return Chat Completions ``choices``. Some
    newer provider bridges expose a Responses-style top-level ``output`` array
    with flat ``function_call`` items, OpenAI-style nested ``function`` items,
    or Gemini-style nested ``functionCall`` items instead.  Treat those as
    and convert them into the existing message/tool-call boundary so Phobos still
    performs schema validation, runtime policy, ROE preview, and guarded apply.
    Provider-side result echoes remain content blocks that are ignored later.
    """

    if not isinstance(raw, dict):
        return {}
    output = raw.get("output")
    if isinstance(output, dict):
        # Some OpenAI-compatible Responses shims collapse a one-item output
        # array into a single object.  Normalize it here so provider-native
        # function-call proposals still enter the normal schema/runtime-policy/
        # ROE validation boundary instead of becoming a no-tool terminal plan.
        output = [dict(output, _provider_shape="single_responses.output")]
    if not isinstance(output, list):
        return {}
    content_blocks: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        block_type = str(item.get("type") or "").strip()
        if block_type == "message":
            _extend_responses_content_blocks(content_blocks, item.get("content"), provider_shape="responses.message.content")
            _extend_responses_message_tool_calls(tool_calls, item)
            nested_message = item.get("message")
            if isinstance(nested_message, dict):
                # A few Responses-compatible shims wrap the assistant message
                # under output[].message rather than putting content/tool-call
                # aliases directly on the output[] item. Keep this in the same
                # native planning boundary with distinct provenance labels so
                # transcripts show exactly which provider shape was accepted.
                _extend_responses_content_blocks(
                    content_blocks,
                    nested_message.get("content"),
                    provider_shape="responses.output.message.content",
                )
                _extend_responses_message_tool_calls(
                    tool_calls,
                    nested_message,
                    provider_shape_prefix="responses.output.message",
                )
            continue
        if block_type in {"output_text", "text"}:
            text = item.get("text") or item.get("content")
            if isinstance(text, str):
                content_blocks.append({"type": "text", "text": text})
            continue
        provider_shape = str(item.get("_provider_shape") or "responses.output")
        if block_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
            call_id = _native_call_id(item)
            tool_calls.append({
                "type": block_type,
                "name": item.get("name") or item.get("tool"),
                "call_id": str(call_id),
                "_provider_shape": provider_shape,
            })
            continue
        if block_type in {"function_call", "tool_call", "tool_use"}:
            function = item.get("function")
            if isinstance(function, dict):
                # Some Responses-compatible shims keep the OpenAI Chat
                # Completions nesting even inside output[] items. Preserve it as
                # a provider-native proposal only; runtime schema, ROE,
                # runtime-policy, approval, and execution boundaries still own
                # the decision before any tool dispatch can occur.
                tool_calls.append({
                    "type": "tool_call",
                    "function": function,
                    "call_id": str(_native_call_id(item, function)),
                    "_provider_shape": f"{provider_shape}.function",
                })
                continue
            function_call = item.get("functionCall") or item.get("function_call")
            if isinstance(function_call, dict):
                # Gemini-style wrappers may put functionCall under a Responses
                # output item. Normalize the name/args shape but do not copy any
                # provider result/input blobs outside the validated plan path.
                tool_calls.append({
                    "type": "tool_call",
                    "name": function_call.get("name") or function_call.get("tool"),
                    "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                    "call_id": str(_native_call_id(item, function_call)),
                    "_provider_shape": f"{provider_shape}.functionCall",
                })
                continue
            name = item.get("name") or item.get("tool")
            arguments = _native_argument_value(item, preferred=("arguments", "input", "args", "parameters", "params"))
            call_id = _native_call_id(item)
            tool_calls.append({
                "type": "tool_call",
                "name": name,
                "arguments": arguments,
                "call_id": str(call_id),
                "_provider_shape": provider_shape,
            })
            continue
        if block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES:
            content_blocks.append({"type": "tool_result", "content": item.get("output") or item.get("content") or item.get("response") or ""})
            continue
    output_text = raw.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        has_text = any(
            isinstance(block, dict)
            and str(block.get("type") or "") not in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES
            and str(block.get("text") or block.get("content") or "").strip()
            for block in content_blocks
        )
        if not has_text:
            content_blocks.insert(0, {"type": "text", "text": output_text})
    content_value: Any = content_blocks if content_blocks else (output_text if isinstance(output_text, str) else "")
    if not tool_calls and not content_value:
        return {}
    return {"content": content_value, "tool_calls": tool_calls}


def _extend_responses_content_blocks(blocks: list[dict[str, Any]], content: Any, *, provider_shape: str = "") -> None:
    if isinstance(content, str):
        blocks.append({"type": "text", "text": content})
        return
    if isinstance(content, dict):
        content_parts = _native_content_parts(content)
        if content_parts is not None:
            # Some Responses-compatible shims nest Gemini-style content parts
            # inside output[].message.content instead of returning a top-level
            # candidates[] object. Flatten those parts but preserve provider
            # provenance so transcripts/ledgers still show the native boundary
            # while runtime schema/ROE/policy validation remains authoritative.
            part_shape = f"{provider_shape}.parts" if provider_shape else "content.parts"
            _extend_responses_content_blocks(blocks, content_parts, provider_shape=part_shape)
            return
        blocks.append(_responses_content_block(content, provider_shape=provider_shape))
        return
    if not isinstance(content, list):
        return
    for block in content:
        if isinstance(block, dict):
            content_parts = _native_content_parts(block)
            if content_parts is not None:
                part_shape = f"{provider_shape}.parts" if provider_shape else "content.parts"
                _extend_responses_content_blocks(blocks, content_parts, provider_shape=part_shape)
            else:
                blocks.append(_responses_content_block(block, provider_shape=provider_shape))
        elif isinstance(block, str):
            blocks.append({"type": "text", "text": block})


def _responses_content_block(block: dict[str, Any], *, provider_shape: str) -> dict[str, Any]:
    out = dict(block)
    block_type = str(out.get("type") or "").strip()
    has_native_call_alias = isinstance(out.get("functionCall") or out.get("function_call"), dict)
    has_native_result_alias = isinstance(out.get("functionResponse") or out.get("function_response"), dict)
    if provider_shape and "_provider_shape" not in out and (
        block_type in (
            _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES
            | _NATIVE_PROVIDER_RESULT_BLOCK_TYPES
            | _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES
        )
        or has_native_call_alias
        or has_native_result_alias
    ):
        # Responses API output[].type=message commonly nests function/tool-call
        # content blocks.  Preserve this provider provenance through the normal
        # content-block parser so transcripts and ledgers distinguish these
        # calls from top-level Anthropic-style content blocks without weakening
        # schema/ROE/runtime-policy validation.  Gemini-style parts may omit a
        # type and carry functionCall/functionResponse aliases directly.
        out["_provider_shape"] = provider_shape
    return out


def _extend_responses_message_tool_calls(tool_calls: list[dict[str, Any]], item: dict[str, Any], *, provider_shape_prefix: str = "responses.message") -> None:
    """Normalize tool calls carried on a Responses ``output[].message`` item.

    Some OpenAI-compatible shims preserve Chat-Completions-style ``tool_calls``
    or JS/Gemini camelCase aliases directly on a Responses message object rather
    than inside ``message.content``.  Keep these as provider-native proposals
    only; the runtime still owns schema validation, runtime policy, ROE preview,
    approval replay, execution gating, and transcript redaction.
    """

    def append_raw(raw: Any, *, provider_shape: str) -> None:
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    shape = str(entry.get("_provider_shape") or provider_shape)
                    tool_calls.append(dict(entry, _provider_shape=shape))
                else:
                    tool_calls.append(entry)
        elif isinstance(raw, dict):
            shape = str(raw.get("_provider_shape") or provider_shape)
            tool_calls.append(dict(raw, _provider_shape=shape))

    append_raw(item.get("tool_calls"), provider_shape=f"{provider_shape_prefix}.tool_calls")
    append_raw(item.get("toolCalls"), provider_shape=f"{provider_shape_prefix}.toolCalls")
    append_raw(item.get("tool_call"), provider_shape=f"{provider_shape_prefix}.tool_call")
    append_raw(item.get("toolCall"), provider_shape=f"{provider_shape_prefix}.toolCall")

    function_call = item.get("functionCall")
    if isinstance(function_call, dict):
        tool_calls.append({
            "type": "tool_call",
            "name": function_call.get("name") or function_call.get("tool"),
            "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
            "call_id": str(_native_call_id(item, function_call)),
            "_provider_shape": f"{provider_shape_prefix}.functionCall",
        })
    legacy_function_call = item.get("function_call")
    if isinstance(legacy_function_call, dict):
        tool_calls.append({
            "type": "tool_call",
            "function": legacy_function_call,
            "call_id": str(_native_call_id(item, legacy_function_call)),
            "_provider_shape": f"{provider_shape_prefix}.function_call",
        })
    if isinstance(item.get("functionCalls"), (list, dict)):
        tool_calls.extend(_native_function_call_batch_items(f"{provider_shape_prefix}.functionCalls", item.get("functionCalls")))
    if isinstance(item.get("function_calls"), (list, dict)):
        tool_calls.extend(_native_function_call_batch_items(f"{provider_shape_prefix}.function_calls", item.get("function_calls")))


def _top_level_content_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize top-level content/tool-call payloads into chat message shape.

    Some local shims expose Anthropic-style Messages responses directly instead
    of wrapping them in Chat Completions ``choices`` or Responses ``output``.
    Those payloads commonly put ``content`` blocks (including ``tool_use``) at
    the response root.  Treat them as planner proposals only: this adapter-level
    conversion does not dispatch handlers or queue approvals, and the runtime's
    normal schema, runtime-policy, ROE, and transcript boundaries remain
    authoritative.  Gemini/OpenAI-compatible bridges may also collapse a single
    function proposal into a root ``functionCall`` object, and a few wrappers
    expose a root ``functionCalls``/``function_calls`` array.  Normalize those
    into the same provider-native call boundary rather than letting them become
    terminal no-tool responses.
    """

    if not isinstance(raw, dict):
        return {}
    message: dict[str, Any] = {}
    if "content" in raw:
        content = raw.get("content")
        if isinstance(content, (str, list, dict)) or content is None:
            message["content"] = content
    if "tool_calls" in raw:
        message["tool_calls"] = raw.get("tool_calls")
    if "toolCalls" in raw and "tool_calls" not in message:
        # Some JS/Gemini/OpenAI-compatible shims camel-case provider-native
        # tool-call arrays. Normalize the alias here so the runtime still owns
        # schema validation, runtime policy, ROE preview, and guarded dispatch.
        message["toolCalls"] = raw.get("toolCalls")
    if "tool_call" in raw:
        # Some OpenAI-compatible shims collapse a one-call response into a
        # singular ``tool_call`` field rather than the standard ``tool_calls``
        # array.  Preserve that as planner input only; the runtime still handles
        # schema, runtime-policy, ROE, and approval gating before dispatch.
        message["tool_call"] = raw.get("tool_call")
    if "toolCall" in raw and "tool_call" not in message:
        # Camel-case singular alias seen in a few lightweight provider bridges.
        message["toolCall"] = raw.get("toolCall")
    root_function_call = raw.get("functionCall") or raw.get("function_call_root")
    if isinstance(root_function_call, dict):
        _append_message_tool_call(
            message,
            {
                "type": "tool_call",
                "name": root_function_call.get("name") or root_function_call.get("tool"),
                "arguments": _native_argument_value(root_function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                "call_id": str(_native_call_id(root_function_call)),
                "_provider_shape": "root.functionCall",
            },
        )
    root_function_call_batches: list[tuple[str, Any]] = []
    if isinstance(raw.get("functionCalls"), (list, dict)):
        root_function_call_batches.append(("root.functionCalls", raw.get("functionCalls")))
    if isinstance(raw.get("function_calls"), (list, dict)):
        root_function_call_batches.append(("root.function_calls", raw.get("function_calls")))
    for provider_shape, root_function_calls in root_function_call_batches:
        for call in _native_function_call_batch_items(provider_shape, root_function_calls):
            _append_message_tool_call(message, call)
    root_function_response = raw.get("functionResponse") or raw.get("function_response")
    if isinstance(root_function_response, dict):
        _append_message_content_block(
            message,
            {"type": "tool_result", "content": root_function_response.get("response") or root_function_response.get("content") or ""},
        )
    if isinstance(raw.get("function_call"), dict):
        message["function_call"] = raw.get("function_call")
    return message if message else {}


def _append_message_tool_call(message: dict[str, Any], call: dict[str, Any]) -> None:
    existing = message.get("tool_calls")
    if existing is None:
        message["tool_calls"] = [call]
    elif isinstance(existing, list):
        message["tool_calls"] = list(existing) + [call]
    elif isinstance(existing, dict):
        existing_item = existing
        if "_provider_shape" not in existing_item:
            existing_item = dict(existing_item, _provider_shape="single_top_level.tool_calls")
        message["tool_calls"] = [existing_item, call]
    else:
        message["tool_calls"] = [call]


def _append_message_content_block(message: dict[str, Any], block: dict[str, Any]) -> None:
    existing = message.get("content")
    if existing is None:
        message["content"] = [block]
    elif isinstance(existing, list):
        message["content"] = list(existing) + [block]
    elif isinstance(existing, dict):
        message["content"] = [existing, block]
    elif isinstance(existing, str):
        message["content"] = [{"type": "text", "text": existing}, block]
    else:
        message["content"] = [block]


def _native_function_call_batch_items(provider_shape: str, raw_function_calls: Any) -> list[dict[str, Any]]:
    """Return tool-call objects for provider ``functionCalls`` aliases.

    Gemini/OpenAI-compatible shims can surface plural function calls either at
    the raw response root or inside ``choices[].message``.  Normalize both
    placements into the same provider-native tool-call boundary; the runtime
    still performs schema validation, runtime policy, ROE preview, approval
    checks, and execution gating before anything can dispatch.
    """

    if isinstance(raw_function_calls, dict):
        items: list[Any] = [raw_function_calls]
    elif isinstance(raw_function_calls, list):
        items = raw_function_calls
    else:
        return []
    calls: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        function = item.get("function")
        if isinstance(function, dict):
            calls.append({
                "type": "tool_call",
                "function": function,
                "call_id": str(_native_call_id(item, function)),
                "_provider_shape": provider_shape,
            })
            continue
        function_call = item.get("functionCall") or item.get("function_call")
        if isinstance(function_call, dict):
            calls.append({
                "type": "tool_call",
                "name": function_call.get("name") or function_call.get("tool"),
                "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                "call_id": str(_native_call_id(item, function_call)),
                "_provider_shape": provider_shape,
            })
            continue
        calls.append({
            "type": "tool_call",
            "name": item.get("name") or item.get("tool"),
            "arguments": _native_argument_value(item, preferred=("args", "arguments", "parameters", "input", "params")),
            "call_id": str(_native_call_id(item)),
            "_provider_shape": provider_shape,
        })
    return calls


def _native_tool_calls_to_plan_content(message: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    content_value = message.get("content", "")
    content_text = _message_content_text(content_value).strip()
    calls: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    warnings: list[str] = []
    raw_calls = message.get("tool_calls")
    raw_calls_shape = ""
    if raw_calls is None and "toolCalls" in message:
        raw_calls = message.get("toolCalls")
        raw_calls_shape = "camelCase.toolCalls"
    if raw_calls is None and "tool_call" in message:
        raw_calls = message.get("tool_call")
        if isinstance(raw_calls, dict):
            raw_calls = dict(raw_calls, _provider_shape="singular.tool_call")
    if raw_calls is None and "toolCall" in message:
        raw_calls = message.get("toolCall")
        if isinstance(raw_calls, dict):
            raw_calls = dict(raw_calls, _provider_shape="singular.toolCall")
    raw_call_items: list[Any] = []
    if isinstance(raw_calls, list):
        raw_call_items = [
            dict(item, _provider_shape=raw_calls_shape) if raw_calls_shape and isinstance(item, dict) and "_provider_shape" not in item else item
            for item in raw_calls
        ]
    elif isinstance(raw_calls, dict):
        # A few OpenAI-compatible shims collapse a one-call top-level
        # ``tool_calls`` array into a single object.  Normalize it at the
        # adapter boundary so the runtime can still apply the exact same
        # schema/ROE/runtime-policy validation before any dispatch.
        provider_shape = str(raw_calls.get("_provider_shape") or raw_calls_shape or "single_top_level.tool_calls")
        raw_call_items = [dict(raw_calls, _provider_shape=provider_shape)]
    message_function_call = message.get("functionCall")
    if isinstance(message_function_call, dict):
        raw_call_items.append({
            "type": "tool_call",
            "name": message_function_call.get("name") or message_function_call.get("tool"),
            "arguments": _native_argument_value(message_function_call, preferred=("args", "arguments", "parameters", "input", "params")),
            "call_id": str(_native_call_id(message_function_call)),
            "_provider_shape": "message.functionCall",
        })
    if isinstance(message.get("functionCalls"), (list, dict)):
        raw_call_items.extend(_native_function_call_batch_items("message.functionCalls", message.get("functionCalls")))
    if isinstance(message.get("function_calls"), (list, dict)):
        raw_call_items.extend(_native_function_call_batch_items("message.function_calls", message.get("function_calls")))
    for index, item in enumerate(raw_call_items, start=1):
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

    if isinstance(content, dict):
        content_parts = _native_content_parts(content)
        if content_parts is not None:
            content_items = [
                dict(item, _provider_shape=str(item.get("_provider_shape") or "content.parts"))
                if isinstance(item, dict)
                else item
                for item in content_parts
            ]
        else:
            content_items = [content]
    elif isinstance(content, list):
        content_items = content
    else:
        return [], [], []
    calls: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    warnings: list[str] = []
    index = max(1, start_index)
    for item in content_items:
        if not isinstance(item, dict):
            continue
        block_type = str(item.get("type") or "").strip()
        function_response = item.get("functionResponse") or item.get("function_response")
        if isinstance(function_response, dict) and (not block_type or block_type in {"functionResponse", "function_response"}):
            warnings.append("Native provider functionResponse content ignored; Phobos only accepts model-requested tool calls at this boundary.")
            continue
        function_call = item.get("functionCall") or item.get("function_call")
        if isinstance(function_call, dict) and (not block_type or block_type in {"functionCall", "function_call"}):
            parsed, rejected_item, warning = _parse_native_content_function_call_block(item, function_call, index=index)
            if warning:
                warnings.append(warning)
            if parsed:
                calls.append(parsed)
            if rejected_item:
                rejected.append(rejected_item)
            index += 1
            continue
        if block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES:
            warnings.append("Native provider tool_result content ignored; Phobos only accepts model-requested tool calls at this boundary.")
            continue
        if block_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
            parsed, rejected_item, warning = _reject_unsupported_native_tool_call(item, index=index, native_type=block_type)
            if warning:
                warnings.append(warning)
            if parsed:
                calls.append(parsed)
            if rejected_item:
                rejected.append(rejected_item)
            index += 1
            continue
        if block_type not in _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES:
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
    call_id = _native_call_id(item, function if isinstance(function, dict) else None)
    provider_shape = str(item.get("_provider_shape") or "")
    if provider_shape == "responses.message.content":
        label = f"native provider responses message content {block_type}"
    elif provider_shape == "responses.message.content.parts":
        label = f"native provider responses message content parts {block_type}"
    elif provider_shape == "responses.output.message.content":
        label = f"native provider responses output message content {block_type}"
    elif provider_shape == "responses.output.message.content.parts":
        label = f"native provider responses output message content parts {block_type}"
    elif provider_shape == "content.parts":
        label = f"native provider content parts {block_type}"
    else:
        label = f"native content-block {block_type}"
    if isinstance(function, dict):
        return _parse_native_function_call(
            function,
            index=index,
            legacy=False,
            call_id=call_id,
            label=label,
        )
    arguments = _native_argument_value(item, preferred=("input", "arguments", "args", "parameters", "params"))
    return _parse_native_function_call(
        {"name": item.get("name"), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=call_id,
        label=label,
    )


def _parse_native_content_function_call_block(
    item: dict[str, Any],
    function_call: dict[str, Any],
    *,
    index: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Translate Gemini-style content-block functionCall aliases.

    Some OpenAI-compatible and Gemini bridge shims place camelCase
    ``functionCall`` objects directly inside ``message.content`` parts rather
    than top-level ``tool_calls`` or ``candidates[].content.parts[]``. Keep them
    in the native planning boundary only: schema validation, runtime policy,
    ROE preview, approval, and execution gates still happen in the runtime.
    """

    provider_shape = str(item.get("_provider_shape") or "")
    if provider_shape == "responses.message.content":
        label = "native provider responses message content functionCall"
    elif provider_shape == "responses.message.content.parts":
        label = "native provider responses message content parts functionCall"
    elif provider_shape == "responses.output.message.content":
        label = "native provider responses output message content functionCall"
    elif provider_shape == "responses.output.message.content.parts":
        label = "native provider responses output message content parts functionCall"
    elif provider_shape == "content.parts":
        label = "native provider content parts functionCall"
    else:
        label = "native content-block functionCall"
    arguments = _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params"))
    return _parse_native_function_call(
        {"name": function_call.get("name") or function_call.get("tool"), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=_native_call_id(item, function_call),
        label=label,
    )


def _parse_native_tool_call(item: Any, *, index: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    if not isinstance(item, dict):
        return None, {"tool": None, "reason": "Native tool call must be an object.", "args": {"value_type": type(item).__name__}}, "Native tool call was not an object; skipped."
    native_type = item.get("type")
    if native_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES:
        return None, None, "Native provider tool_result entry ignored; Phobos only accepts model-requested tool calls at this boundary."
    if native_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
        return _reject_unsupported_native_tool_call(item, index=index, native_type=str(native_type))
    if native_type not in {None, "function", "tool_call", "tool_use"}:
        return None, {"tool": None, "reason": "Only function tool calls are supported.", "args": {"native_type": str(native_type)}}, "Native non-function tool call skipped."
    provider_shape = str(item.get("_provider_shape") or "")
    function = item.get("function")
    if isinstance(function, dict):
        if provider_shape == "single_top_level.tool_calls":
            label = "native provider single top-level tool_call"
        elif provider_shape == "singular.tool_call":
            label = "native provider singular tool_call"
        elif provider_shape in {"camelCase.toolCalls", "singular.toolCall"}:
            label = "native provider camelCase toolCall"
        elif provider_shape == "responses.output.function":
            label = "native provider responses output nested function"
        elif provider_shape == "single_responses.output.function":
            label = "native provider single responses output nested function"
        elif provider_shape == "responses.message.tool_calls":
            label = "native provider responses message tool_calls"
        elif provider_shape == "responses.message.tool_call":
            label = "native provider responses message tool_call"
        elif provider_shape == "responses.message.toolCalls":
            label = "native provider responses message toolCalls"
        elif provider_shape == "responses.message.toolCall":
            label = "native provider responses message toolCall"
        elif provider_shape == "responses.message.function_call":
            label = "native provider responses message function_call"
        elif provider_shape == "responses.message.functionCall":
            label = "native provider responses message functionCall"
        elif provider_shape == "responses.message.functionCalls":
            label = "native provider responses message functionCalls"
        elif provider_shape == "responses.message.function_calls":
            label = "native provider responses message function_calls"
        elif provider_shape == "responses.output.message.tool_calls":
            label = "native provider responses output message tool_calls"
        elif provider_shape == "responses.output.message.tool_call":
            label = "native provider responses output message tool_call"
        elif provider_shape == "responses.output.message.toolCalls":
            label = "native provider responses output message toolCalls"
        elif provider_shape == "responses.output.message.toolCall":
            label = "native provider responses output message toolCall"
        elif provider_shape == "responses.output.message.function_call":
            label = "native provider responses output message function_call"
        elif provider_shape == "responses.output.message.functionCall":
            label = "native provider responses output message functionCall"
        elif provider_shape == "responses.output.message.functionCalls":
            label = "native provider responses output message functionCalls"
        elif provider_shape == "responses.output.message.function_calls":
            label = "native provider responses output message function_calls"
        elif provider_shape == "root.functionCalls":
            label = "native provider root functionCalls"
        elif provider_shape == "root.function_calls":
            label = "native provider root function_calls"
        elif provider_shape == "message.functionCalls":
            label = "native provider message functionCalls"
        elif provider_shape == "message.functionCall":
            label = "native provider message functionCall"
        elif provider_shape == "message.function_calls":
            label = "native provider message function_calls"
        else:
            label = None
        return _parse_native_function_call(
            function,
            index=index,
            legacy=False,
            call_id=_native_call_id(item, function),
            label=label,
        )
    # Several OpenAI-compatible shims flatten top-level tool calls instead of
    # nesting them under {"function": {"name", "arguments"}}.  Treat these as
    # planner proposals only; runtime schema/ROE validation remains authoritative.
    name = item.get("name") or item.get("tool")
    if isinstance(function, str) and not name:
        name = function
    if name:
        arguments = _native_argument_value(item, preferred=("arguments", "args", "input", "parameters", "params"))
        if item.get("_provider_shape") == "responses.output":
            label = "native provider responses output function_call"
        elif item.get("_provider_shape") == "single_responses.output":
            label = "native provider single responses output function_call"
        elif item.get("_provider_shape") == "responses.output.functionCall":
            label = "native provider responses output nested functionCall"
        elif item.get("_provider_shape") == "single_responses.output.functionCall":
            label = "native provider single responses output nested functionCall"
        elif item.get("_provider_shape") == "gemini.candidate":
            label = "native provider candidate functionCall"
        elif item.get("_provider_shape") == "root.functionCall":
            label = "native provider root functionCall"
        elif item.get("_provider_shape") == "responses.message.tool_calls":
            label = "native provider responses message tool_calls"
        elif item.get("_provider_shape") == "responses.message.tool_call":
            label = "native provider responses message tool_call"
        elif item.get("_provider_shape") == "responses.message.toolCalls":
            label = "native provider responses message toolCalls"
        elif item.get("_provider_shape") == "responses.message.toolCall":
            label = "native provider responses message toolCall"
        elif item.get("_provider_shape") == "responses.message.function_call":
            label = "native provider responses message function_call"
        elif item.get("_provider_shape") == "responses.message.functionCall":
            label = "native provider responses message functionCall"
        elif item.get("_provider_shape") == "responses.message.functionCalls":
            label = "native provider responses message functionCalls"
        elif item.get("_provider_shape") == "responses.message.function_calls":
            label = "native provider responses message function_calls"
        elif item.get("_provider_shape") == "responses.output.message.tool_calls":
            label = "native provider responses output message tool_calls"
        elif item.get("_provider_shape") == "responses.output.message.tool_call":
            label = "native provider responses output message tool_call"
        elif item.get("_provider_shape") == "responses.output.message.toolCalls":
            label = "native provider responses output message toolCalls"
        elif item.get("_provider_shape") == "responses.output.message.toolCall":
            label = "native provider responses output message toolCall"
        elif item.get("_provider_shape") == "responses.output.message.function_call":
            label = "native provider responses output message function_call"
        elif item.get("_provider_shape") == "responses.output.message.functionCall":
            label = "native provider responses output message functionCall"
        elif item.get("_provider_shape") == "responses.output.message.functionCalls":
            label = "native provider responses output message functionCalls"
        elif item.get("_provider_shape") == "responses.output.message.function_calls":
            label = "native provider responses output message function_calls"
        elif item.get("_provider_shape") == "root.functionCalls":
            label = "native provider root functionCalls"
        elif item.get("_provider_shape") == "root.function_calls":
            label = "native provider root function_calls"
        elif item.get("_provider_shape") == "message.functionCalls":
            label = "native provider message functionCalls"
        elif item.get("_provider_shape") == "message.functionCall":
            label = "native provider message functionCall"
        elif item.get("_provider_shape") == "message.function_calls":
            label = "native provider message function_calls"
        elif provider_shape == "single_top_level.tool_calls":
            label = "native provider single top-level tool_call"
        elif provider_shape == "singular.tool_call":
            label = "native provider singular tool_call"
        elif provider_shape in {"camelCase.toolCalls", "singular.toolCall"}:
            label = "native provider camelCase toolCall"
        else:
            label = "native provider flat tool_call"
        return _parse_native_function_call(
            {"name": name, "arguments": arguments},
            index=index,
            legacy=False,
            call_id=_native_call_id(item),
            label=label,
        )
    return None, {"tool": None, "reason": "Native tool call missing function payload.", "args": {}}, "Native tool call missing function payload; skipped."


def _native_call_id(*items: Any) -> str:
    """Return a provider call identifier from common native-tool-call aliases.

    Provider bridges disagree on where they place the opaque correlation id:
    OpenAI-style content blocks usually use ``id``, Responses-style blocks often
    use ``call_id``, some shims use ``tool_call_id``, and Anthropic-compatible
    bridges may use ``tool_use_id``.  Preserve the bounded id as provenance only;
    runtime schema/ROE checks still decide whether any call can be applied.
    """

    for item in items:
        if not isinstance(item, dict):
            continue
        for key in ("id", "call_id", "tool_call_id", "tool_use_id", "callId", "toolCallId", "toolUseId"):
            value = item.get(key)
            if value not in (None, ""):
                return str(value)
    return ""


_NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES = {"tool_use", "tool_call", "function_call", "functionCall"}
_NATIVE_PROVIDER_RESULT_BLOCK_TYPES = {
    "tool_result",
    "function_result",
    "function_call_output",
    "functionResponse",
    "function_response",
}
_NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES = {"custom_tool_call"}


def _reject_unsupported_native_tool_call(
    item: dict[str, Any],
    *,
    index: int,
    native_type: str,
) -> tuple[None, dict[str, Any], str]:
    """Reject provider-native freeform/custom tool calls without surfacing input.

    Phobos only accepts registered JSON-schema function/tool calls at this
    boundary.  Provider custom/freeform calls can carry arbitrary text in fields
    such as ``input`` or ``content``; keep those bytes out of transcripts and ask
    the model/provider to use a registered function call instead.
    """

    raw_tool_name = str(item.get("name") or item.get("tool") or "").strip()
    tool_name = redact_secrets(raw_tool_name[:200]) or None
    call_id = _native_call_id(item).strip()
    args: dict[str, Any] = {"native_type": str(native_type or "custom_tool_call"), "native_tool_call_index": index}
    if call_id:
        args["provider_tool_call_id"] = redact_secrets(call_id[:200]) or ""
    reason = "Custom/freeform native tool calls are not supported; use registered JSON-schema function calls."
    warning = "Native custom/freeform tool call skipped; Phobos only accepts registered JSON-schema function calls."
    return None, {"tool": tool_name, "reason": reason, "args": args}, warning


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
    args, error = _parse_native_arguments(_native_argument_value(function))
    if error:
        return None, {"tool": name, "reason": error, "args": {}}, f"Native arguments for {name} were invalid; skipped."
    label = label or ("legacy native function_call" if legacy else "native provider tool_call")
    suffix = f" ({call_id})" if call_id else f" #{index}"
    metadata: dict[str, Any] = {
        "native_tool_call_source": label,
        "native_tool_call_index": index,
    }
    if call_id:
        metadata["provider_tool_call_id"] = call_id
    return {"tool": name, "args": args, "reason": f"Model requested {label}{suffix}.", "metadata": metadata}, None, None


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
