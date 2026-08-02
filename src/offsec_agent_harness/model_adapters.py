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
import urllib.parse
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
                body = response.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body)
                except json.JSONDecodeError as exc:
                    events = _parse_responses_sse_events(body)
                    if events:
                        return {"events": events, "_response_format": "chat_completions_sse"}
                    raise RuntimeError("OpenAI-compatible endpoint returned neither JSON nor parseable SSE event data") from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Model endpoint HTTP {exc.code}: {body[:500]}") from exc


class OpenAIResponsesAdapter(OpenAICompatibleAdapter):
    """OpenAI Responses API adapter for direct native tool-call planning.

    ``OpenAICompatibleAdapter`` targets Chat Completions compatible shims.  Some
    operators point Phobos at a real Responses endpoint instead, where function
    specs are flattened and tool proposals return under ``output[]``.  Keep this
    as an adapter-level translation boundary only: the runtime still validates
    names/schemas, runtime policy, ROE previews, approvals, and explicit execute
    intent before any registry handler can run.
    """

    provider = "openai-responses"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
                {"role": "user", "content": (context + "\n\n" if context else "") + prompt},
            ],
            "temperature": 0.2,
        }
        raw = self._responses_completion(payload)
        message = _first_choice_message(raw)
        if not message and isinstance(raw.get("output_text"), str):
            message = {"content": raw.get("output_text")}
        content = _message_content_text(message.get("content", "")).strip()
        if not content and isinstance(raw.get("output_text"), str):
            content = raw.get("output_text", "")
        return ModelResponse(provider=self.provider, role=role, content=content, raw={"model": self.model, "base_url": self.base_url, "api": "responses"})

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        tools = [_responses_tool_from_spec(spec) for spec in tool_specs[:80]]
        tools = [tool for tool in tools if tool is not None]
        user_content = (
            (context + "\n\n" if context else "")
            + "Plan Phobos Agent tool calls for the authorized operator request. "
            "Use Responses API function calls when a tool is needed. Do not claim a tool ran. "
            "If no tool is needed, respond with a concise summary and no tool calls. "
            "Target-affecting tools still go through ROE guardrails after planning. "
            "If command execution is not explicitly allowed, request execute=false.\n\n"
            f"Command execution allowed: {allow_command_execution}\n"
            f"Operator request: {prompt}"
        )
        if not tools:
            user_content += "\n\n" + _tool_plan_prompt(prompt, tool_specs, allow_command_execution=allow_command_execution)
        payload: dict[str, Any] = {
            "model": self.model,
            "input": [
                {"role": "system", "content": ROLE_SYSTEM_PROMPTS["impact"]},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.2,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        raw = self._responses_completion(payload)
        message = _first_choice_message(raw)
        if not message and isinstance(raw.get("output_text"), str):
            message = {"content": raw.get("output_text")}
        plan_content, meta = _native_tool_calls_to_plan_content(message)
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=plan_content,
            raw={
                "model": self.model,
                "base_url": self.base_url,
                "api": "responses",
                "native_tool_calls": meta["native_tool_calls"],
                "native_tool_call_count": meta["native_tool_call_count"],
                "rejected_native_tool_call_count": meta["rejected_native_tool_call_count"],
            },
        )

    def _responses_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self.key_env, "")
        if not api_key and not _is_local_base_url(self.base_url):
            raise RuntimeError(f"Missing API key environment variable {self.key_env}")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(self.base_url + "/responses", data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body)
                except json.JSONDecodeError as exc:
                    events = _parse_responses_sse_events(body)
                    if events:
                        return {"events": events, "_response_format": "sse"}
                    raise RuntimeError("Responses endpoint returned neither JSON nor parseable SSE event data") from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Responses endpoint HTTP {exc.code}: {body[:500]}") from exc


class GeminiAdapter(BaseModelAdapter):
    """Google Gemini GenerateContent adapter for native Phobos tool planning.

    Gemini returns function proposals as ``candidates[].content.parts[].functionCall``.
    This adapter only translates those provider-native calls into the common
    Phobos JSON plan boundary; schema validation, runtime policy, ROE preview,
    approvals, explicit execute intent, and transcript redaction still happen in
    the runtime before any tool can dispatch.
    """

    provider = "gemini"

    def __init__(self, model: str, base_url: str = "https://generativelanguage.googleapis.com/v1beta", key_env: str = "GEMINI_API_KEY", timeout: int = 60):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.key_env = key_env
        self.timeout = timeout

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        payload = {
            "systemInstruction": {"parts": [{"text": ROLE_SYSTEM_PROMPTS[role]}]},
            "contents": [{"role": "user", "parts": [{"text": (context + "\n\n" if context else "") + prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }
        raw = self._gemini_completion(payload)
        message = _first_choice_message(raw)
        content = _message_content_text(message.get("content", "")).strip()
        return ModelResponse(provider=self.provider, role=role, content=content, raw={"model": self.model, "base_url": self.base_url, "api": "generateContent"})

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        declarations = [_gemini_function_declaration_from_spec(spec) for spec in tool_specs[:80]]
        declarations = [declaration for declaration in declarations if declaration is not None]
        user_content = (
            (context + "\n\n" if context else "")
            + "Plan Phobos Agent tool calls for the authorized operator request. "
            "Use Gemini function calls when a tool is needed. Do not claim a tool ran. "
            "If no tool is needed, respond with a concise summary and no tool calls. "
            "Target-affecting tools still go through ROE guardrails after planning. "
            "If command execution is not explicitly allowed, request execute=false.\n\n"
            f"Command execution allowed: {allow_command_execution}\n"
            f"Operator request: {prompt}"
        )
        if not declarations:
            user_content += "\n\n" + _tool_plan_prompt(prompt, tool_specs, allow_command_execution=allow_command_execution)
        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": ROLE_SYSTEM_PROMPTS["impact"]}]},
            "contents": [{"role": "user", "parts": [{"text": user_content}]}],
            "generationConfig": {"temperature": 0.2},
        }
        if declarations:
            payload["tools"] = [{"functionDeclarations": declarations}]
            payload["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
        raw = self._gemini_completion(payload)
        message = _first_choice_message(raw)
        plan_content, meta = _native_tool_calls_to_plan_content(message)
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=plan_content,
            raw={
                "model": self.model,
                "base_url": self.base_url,
                "api": "generateContent",
                "native_tool_calls": meta["native_tool_calls"],
                "native_tool_call_count": meta["native_tool_call_count"],
                "rejected_native_tool_call_count": meta["rejected_native_tool_call_count"],
            },
        )

    def _gemini_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self.key_env, "")
        if not api_key and not _is_local_base_url(self.base_url):
            raise RuntimeError(f"Missing API key environment variable {self.key_env}")
        model_id = self.model[7:] if self.model.startswith("models/") else self.model
        url = f"{self.base_url}/models/{urllib.parse.quote(model_id, safe='')}:generateContent"
        if api_key:
            url += "?" + urllib.parse.urlencode({"key": api_key})
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body)
                except json.JSONDecodeError as exc:
                    events = _parse_responses_sse_events(body)
                    if events:
                        return {"events": events, "_response_format": "gemini_sse"}
                    raise RuntimeError("Gemini endpoint returned neither JSON nor parseable SSE event data") from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gemini endpoint HTTP {exc.code}: {body[:500]}") from exc


class AnthropicMessagesAdapter(BaseModelAdapter):
    """Anthropic Messages API adapter for native Phobos tool planning.

    Anthropic returns native tool proposals as ``content`` blocks with
    ``type=tool_use`` and ``input`` JSON.  This adapter only translates those
    blocks into Phobos' common JSON plan contract; the runtime remains the
    authoritative boundary for schema validation, runtime policy, ROE preview,
    approvals, explicit execute intent, transcripts, and dispatch.
    """

    provider = "anthropic"

    def __init__(self, model: str, base_url: str = "https://api.anthropic.com/v1", key_env: str = "ANTHROPIC_API_KEY", timeout: int = 60):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.key_env = key_env
        self.timeout = timeout

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        role = role if role in ROLE_SYSTEM_PROMPTS else "impact"
        payload = {
            "model": self.model,
            "system": ROLE_SYSTEM_PROMPTS[role],
            "messages": [{"role": "user", "content": (context + "\n\n" if context else "") + prompt}],
            "temperature": 0.2,
            "max_tokens": 1024,
        }
        raw = self._messages_completion(payload)
        message = _anthropic_message_with_provider_shape(_first_choice_message(raw))
        content = _message_content_text(message.get("content", "")).strip()
        return ModelResponse(provider=self.provider, role=role, content=content, raw={"model": self.model, "base_url": self.base_url, "api": "messages"})

    def generate_tool_plan(
        self,
        prompt: str,
        tool_specs: list[dict[str, Any]],
        *,
        allow_command_execution: bool = False,
        context: str = "",
    ) -> ModelResponse:
        tools = [_anthropic_tool_from_spec(spec) for spec in tool_specs[:80]]
        tools = [tool for tool in tools if tool is not None]
        user_content = (
            (context + "\n\n" if context else "")
            + "Plan Phobos Agent tool calls for the authorized operator request. "
            "Use Anthropic Messages tool_use blocks when a tool is needed. Do not claim a tool ran. "
            "If no tool is needed, respond with a concise summary and no tool calls. "
            "Target-affecting tools still go through ROE guardrails after planning. "
            "If command execution is not explicitly allowed, request execute=false.\n\n"
            f"Command execution allowed: {allow_command_execution}\n"
            f"Operator request: {prompt}"
        )
        if not tools:
            user_content += "\n\n" + _tool_plan_prompt(prompt, tool_specs, allow_command_execution=allow_command_execution)
        payload: dict[str, Any] = {
            "model": self.model,
            "system": ROLE_SYSTEM_PROMPTS["impact"],
            "messages": [{"role": "user", "content": user_content}],
            "temperature": 0.2,
            "max_tokens": 2048,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = {"type": "auto"}
        raw = self._messages_completion(payload)
        message = _anthropic_message_with_provider_shape(_first_choice_message(raw))
        plan_content, meta = _native_tool_calls_to_plan_content(message)
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=plan_content,
            raw={
                "model": self.model,
                "base_url": self.base_url,
                "api": "messages",
                "native_tool_calls": meta["native_tool_calls"],
                "native_tool_call_count": meta["native_tool_call_count"],
                "rejected_native_tool_call_count": meta["rejected_native_tool_call_count"],
            },
        )

    def _messages_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.environ.get(self.key_env, "")
        if not api_key and not _is_local_base_url(self.base_url):
            raise RuntimeError(f"Missing API key environment variable {self.key_env}")
        headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
        if api_key:
            headers["x-api-key"] = api_key
        req = urllib.request.Request(self.base_url + "/messages", data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body)
                except json.JSONDecodeError as exc:
                    events = _parse_responses_sse_events(body)
                    if events:
                        return {"events": events, "_response_format": "anthropic_sse"}
                    raise RuntimeError("Anthropic Messages endpoint returned neither JSON nor parseable SSE event data") from exc
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Anthropic Messages endpoint HTTP {exc.code}: {body[:500]}") from exc


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
    if provider in {"openai-responses", "responses"}:
        return OpenAIResponsesAdapter(model=model, base_url=base_url or "https://api.openai.com/v1", key_env=key_env)
    if provider in {"gemini", "google", "google-gemini"}:
        gemini_key_env = key_env if key_env != "OPENAI_API_KEY" else "GEMINI_API_KEY"
        return GeminiAdapter(model=model, base_url=base_url or "https://generativelanguage.googleapis.com/v1beta", key_env=gemini_key_env)
    if provider in {"anthropic", "claude"}:
        anthropic_key_env = key_env if key_env != "OPENAI_API_KEY" else "ANTHROPIC_API_KEY"
        return AnthropicMessagesAdapter(model=model, base_url=base_url or "https://api.anthropic.com/v1", key_env=anthropic_key_env)
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


def _choice_items(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Chat-Completions choice objects from plural or collapsed wrappers.

    OpenAI-compatible routers normally return ``choices: [...]``. Some local or
    AI-gateway shims collapse a one-choice response into ``choices: {...}`` or a
    singular ``choice`` object. Normalize those shapes at the adapter boundary so
    provider-native tool-call proposals still enter the usual inert Phobos plan
    path before schema, runtime-policy, ROE, approval, and execute gates run.
    """

    if not isinstance(raw, dict):
        return []
    choices = raw.get("choices")
    if isinstance(choices, dict):
        return [choices]
    if isinstance(choices, list):
        return [choice for choice in choices if isinstance(choice, dict)]
    choice = raw.get("choice")
    if isinstance(choice, dict):
        return [choice]
    return []


def _first_choice_message(raw: dict[str, Any], *, _wrapper_depth: int = 0) -> dict[str, Any]:
    chat_stream_message = _chat_completion_stream_events_to_message(raw)
    if chat_stream_message:
        return chat_stream_message
    responses_stream_message = _responses_stream_events_to_message(raw)
    if responses_stream_message:
        return responses_stream_message
    bedrock_converse_stream_message = _bedrock_converse_stream_events_to_message(raw)
    if bedrock_converse_stream_message:
        return bedrock_converse_stream_message
    anthropic_stream_message = _anthropic_stream_events_to_message(raw)
    if anthropic_stream_message:
        return anthropic_stream_message
    gemini_stream_message = _gemini_stream_events_to_message(raw)
    if gemini_stream_message:
        return gemini_stream_message
    bedrock_converse_message = _bedrock_converse_output_to_message(raw)
    if bedrock_converse_message:
        return bedrock_converse_message
    choices = _choice_items(raw) if isinstance(raw, dict) else []
    if choices:
        first = choices[0]
        if isinstance(first, dict):
            if isinstance(first.get("message"), dict):
                result_echo = _native_provider_result_role_message(first["message"], provider_shape="choice.message")
                if result_echo:
                    return result_echo
                return first["message"]
            choice_delta_message = _choice_delta_sequence_to_message(choices)
            if choice_delta_message:
                return choice_delta_message
            choice_message = _choice_wrapper_to_message(first)
            if choice_message:
                return choice_message
    root_message = _root_message_to_message(raw)
    if root_message:
        return root_message
    root_messages = _root_messages_to_message(raw)
    if root_messages:
        return root_messages
    root_contents = _root_contents_to_message(raw)
    if root_contents:
        return root_contents
    root_predictions = _root_predictions_to_message(raw, depth=_wrapper_depth)
    if root_predictions:
        return root_predictions
    root_outputs = _root_outputs_to_message(raw, depth=_wrapper_depth)
    if root_outputs:
        return root_outputs
    candidate_message = _candidate_content_to_message(raw)
    if candidate_message:
        return candidate_message
    responses_message = _responses_output_to_message(raw)
    if responses_message:
        return responses_message
    top_level_message = _top_level_content_message(raw)
    if top_level_message:
        return top_level_message
    envelope_message = _provider_response_envelope_to_message(raw, depth=_wrapper_depth)
    if envelope_message:
        return envelope_message
    return {}


def _provider_response_envelope_to_message(raw: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Unwrap provider ``response``/``result``/``data`` envelopes before native-call parsing.

    A few local/OpenAI-compatible gateways return the actual model payload under
    a root ``response`` object, for example ``{"response": {"message": ...}}``
    or ``{"response": {"choices": [...]}}``.  Some lightweight gateways use a
    ``result`` object for the same final provider payload, while generic API
    facades commonly use a root ``data`` object or list.  Plural ``responses``
    and ``results`` lists show up in router batch/transcript captures too; treat
    them as the same newest-first, result-echo-skipping translation boundary.
    Recurse into the nested provider payload, then let the existing Phobos
    runtime boundary validate schemas, runtime policy, ROE, approvals, execution
    intent, and transcript redaction before any tool can run.  Limit recursion so
    malformed nested envelopes fail closed as no-tool responses instead of
    causing unbounded parsing.
    """

    if depth >= 3 or not isinstance(raw, dict):
        return {}
    for envelope_key in ("response", "result", "data", "responses", "results"):
        wrapped = raw.get(envelope_key)
        if isinstance(wrapped, dict):
            message = _first_choice_message(wrapped, _wrapper_depth=depth + 1)
            if message and not _native_message_is_result_echo_only(message):
                return message
            continue
        if isinstance(wrapped, list):
            message = _provider_envelope_list_to_message(wrapped, envelope_key=envelope_key, depth=depth)
            if message:
                return message
    return {}


def _provider_envelope_list_to_message(items: list[Any], *, envelope_key: str, depth: int) -> dict[str, Any]:
    """Return the latest fresh assistant/model message from a list-valued envelope.

    Some gateway facades wrap the provider response as ``{"data": [...]}`` (or
    ``response``/``result`` lists) instead of a single object.  Walk newest-first,
    skip provider result echoes, and only return a recognizable native-planning
    message.  This keeps list envelopes translation-only: no schema validation,
    approval queueing, evidence writes, or target activity happens here.
    """

    if depth >= 3:
        return {}
    for item in reversed(items):
        if not isinstance(item, dict):
            continue
        if _native_provider_result_role_message(item, provider_shape=f"{envelope_key}.list"):
            continue
        message = _first_choice_message(item, _wrapper_depth=depth + 1)
        if not message or _native_message_is_result_echo_only(message):
            continue
        return message
    return {}


def _native_message_is_result_echo_only(message: dict[str, Any]) -> bool:
    """Return True when a normalized message contains only provider tool results.

    Result echoes can appear as the newest item in list-valued provider envelopes;
    they must not hide an earlier assistant/model tool-call proposal, and they
    must not become prompt summaries or dispatch input.  Keep the check narrow:
    any recognized fresh tool-call field or non-result text makes the message a
    normal planner candidate for later runtime validation.
    """

    if not isinstance(message, dict):
        return False
    fresh_keys = (
        "tool_calls",
        "toolCalls",
        "tool_call",
        "toolCall",
        "functionCall",
        "functionCalls",
        "function_calls",
        "function_call",
        "tool",
        *_NATIVE_TOOL_USE_ALIAS_KEYS,
    )
    if any(key in message for key in fresh_keys):
        return False
    content = message.get("content")
    if isinstance(content, dict):
        blocks: list[Any] = [content]
    elif isinstance(content, list):
        blocks = list(content)
    else:
        return False
    if not blocks:
        return False
    saw_result = False
    for block in blocks:
        if isinstance(block, str):
            if block.strip():
                return False
            continue
        if not isinstance(block, dict):
            return False
        block_type = str(block.get("type") or "").strip()
        if block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES or _native_provider_result_alias_value(block) is not None:
            saw_result = True
            continue
        return False
    return saw_result


def _choice_wrapper_to_message(choice: dict[str, Any]) -> dict[str, Any]:
    """Normalize choice-level/delta native tool-call wrappers into message shape.

    Some OpenAI-compatible endpoints expose a final streaming-style snapshot as
    ``choices[0].delta`` instead of ``choices[0].message``; a few lightweight
    shims put ``tool_calls``/``toolCalls`` directly on the choice object.  Treat
    those as provider-native planning proposals only.  Phobos still validates
    tool names, JSON schemas, runtime policy, ROE previews, approvals, execution
    intent, and transcript redaction before anything can dispatch.
    """

    if not isinstance(choice, dict):
        return {}
    delta = choice.get("delta")
    if isinstance(delta, dict):
        message = _provider_message_wrapper_to_message(delta, provider_shape_prefix="choice.delta")
        if message:
            return message
    if _responses_output_item_looks_like_message(choice):
        return _provider_message_wrapper_to_message(choice, provider_shape_prefix="choice")
    return {}


def _choice_delta_sequence_to_message(choices: list[Any], *, provider_shape_prefix: str = "choice.delta") -> dict[str, Any]:
    """Assemble streaming-style ``choices[].delta`` tool-call fragments.

    Some OpenAI-compatible shims return a captured stream as multiple choice
    delta chunks instead of a single final ``message``.  Tool-call arguments may
    be split across those chunks, so validate only after assembling same-index or
    same-id fragments into one provider-native proposal.  If a stream contains
    multiple provider alternatives (``choice.index`` 0, 1, ...), assemble only the
    first observed choice index and ignore the others; combining alternatives can
    corrupt inert proposals before the runtime's schema/ROE boundary.  This
    remains a planner translation boundary: no handler dispatch, approval
    queueing, evidence write, or target activity happens here.
    """

    content_blocks: list[dict[str, Any]] = []
    tool_call_chunks: list[Any] = []
    saw_delta = False
    selected_choice_key: str | None = None
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        choice_key = _choice_stream_choice_key(choice)
        if choice_key is not None:
            if selected_choice_key is None:
                selected_choice_key = choice_key
            elif choice_key != selected_choice_key:
                continue
        elif selected_choice_key is not None:
            continue
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        saw_delta = True
        chunk_message = _provider_message_wrapper_to_message(delta, provider_shape_prefix=provider_shape_prefix)
        content = chunk_message.get("content")
        if isinstance(content, list):
            content_blocks.extend([item for item in content if isinstance(item, dict)])
        elif isinstance(content, dict):
            content_blocks.append(content)
        elif isinstance(content, str) and content:
            content_blocks.append({"type": "text", "text": content})
        raw_calls = chunk_message.get("tool_calls")
        if isinstance(raw_calls, list):
            tool_call_chunks.extend(raw_calls)
        elif isinstance(raw_calls, dict):
            tool_call_chunks.append(raw_calls)
    if not saw_delta:
        return {}
    message: dict[str, Any] = {}
    if content_blocks:
        message["content"] = content_blocks
    merged_tool_calls = _merge_choice_delta_tool_call_chunks(tool_call_chunks)
    if merged_tool_calls:
        message["tool_calls"] = merged_tool_calls
    return message


def _choice_stream_choice_key(choice: dict[str, Any]) -> str | None:
    for key in ("index", "choice_index", "choiceIndex"):
        value = choice.get(key)
        if isinstance(value, bool) or value in (None, ""):
            continue
        return f"index:{value}"
    return None


def _chat_completion_stream_events_to_message(raw: Any) -> dict[str, Any]:
    """Normalize OpenAI Chat Completions SSE chunks into a final message shape.

    OpenAI-compatible gateways may return captured ``chat.completion.chunk`` SSE
    frames instead of a final JSON response. Assemble only provider-native
    ``choices[].delta.tool_calls`` and content fragments into an inert proposal;
    schema validation, runtime policy, ROE previews, approvals, explicit execute
    intent, and transcript redaction remain Phobos runtime boundaries.
    """

    events = _responses_stream_event_items(raw)
    if not events:
        return {}
    choices: list[Any] = []
    saw_chat_stream = False
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = str(_responses_stream_event_value(event, "type", "event") or "").strip()
        if event_type.startswith("response."):
            continue
        raw_choices = _responses_stream_event_value(event, "choices")
        if not isinstance(raw_choices, list):
            continue
        if event_type and not event_type.startswith("chat.completion"):
            continue
        saw_chat_stream = True
        choices.extend([choice for choice in raw_choices if isinstance(choice, dict)])
    if not saw_chat_stream or not choices:
        return {}
    return _choice_delta_sequence_to_message(choices, provider_shape_prefix="chat.completions.sse.delta")


def _gemini_stream_events_to_message(raw: Any) -> dict[str, Any]:
    """Normalize Gemini GenerateContent SSE chunks into a message shape.

    Some Gemini-compatible endpoints and proxies return captured
    ``streamGenerateContent``/SSE frames as ``data: {"candidates": ...}``
    records rather than one final JSON body.  Accumulate first-candidate parts
    and translate only ``functionCall`` proposals into Phobos' existing native
    planning boundary; runtime schema validation, ROE previews, approvals,
    explicit execution intent, and transcript redaction remain authoritative.
    """

    if not isinstance(raw, dict):
        return {}
    response_format = str(raw.get("_response_format") or "").strip().lower()
    events = _responses_stream_event_items(raw)
    if not events:
        return {}
    saw_gemini_stream = response_format in {"gemini_sse", "gemini_stream", "gemini-generatecontent-sse"}
    parts: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_data = event.get("data") if isinstance(event.get("data"), dict) else event
        if not isinstance(event_data, dict):
            continue
        candidates = _candidate_items(event_data)
        if not candidates:
            continue
        saw_gemini_stream = True
        first = next((candidate for candidate in candidates if isinstance(candidate, dict)), None)
        if not isinstance(first, dict):
            continue
        content = first.get("content") if isinstance(first.get("content"), dict) else {}
        raw_parts = content.get("parts") if isinstance(content, dict) else None
        if isinstance(raw_parts, dict):
            raw_parts = [raw_parts]
        if not isinstance(raw_parts, list):
            continue
        for part in raw_parts:
            if isinstance(part, dict):
                parts.append(part)
    if not saw_gemini_stream or not parts:
        return {}
    return _candidate_content_to_message(
        {"candidates": [{"content": {"parts": parts}}]},
        provider_shape="gemini.stream.candidate",
    )


def _responses_stream_events_to_message(raw: Any) -> dict[str, Any]:
    """Normalize captured Responses streaming events into message shape.

    Some OpenAI/Responses-compatible gateways expose a bounded JSON capture of
    SSE events instead of the final ``output[]`` object.  Assemble function-call
    argument deltas locally, then pass only the reconstructed registered-call
    shape into the normal Responses output parser.  This remains an adapter-only
    translation boundary: no tool dispatch, approval queueing, evidence writes,
    or target activity can happen here.
    """

    events = _responses_stream_event_items(raw)
    if not events:
        return {}
    output_items: list[dict[str, Any]] = []
    buckets: dict[str, dict[str, Any]] = {}
    bucket_aliases: dict[str, str] = {}

    def resolve_bucket_key(event: dict[str, Any], item: dict[str, Any] | None, *, fallback: str) -> str:
        keys = _responses_stream_item_keys(event, item, fallback=fallback)
        canonical = next((bucket_aliases[key] for key in keys if key in bucket_aliases), keys[0])
        for key in keys:
            bucket_aliases[key] = canonical
        return canonical
    text_parts: list[str] = []
    saw_stream_event = False
    for position, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or event.get("event") or "").strip()
        data = event.get("data")
        if isinstance(data, dict) and not event_type:
            event_type = str(data.get("type") or data.get("event") or "").strip()
        if not event_type.startswith("response."):
            continue
        saw_stream_event = True
        if event_type in {"response.output_text.delta", "response.refusal.delta"}:
            delta = _responses_stream_event_value(event, "delta", "text")
            if isinstance(delta, str):
                text_parts.append(delta)
            continue
        if event_type in {"response.output_text.done", "response.refusal.done"}:
            text = _responses_stream_event_value(event, "text", "delta")
            if isinstance(text, str):
                text_parts.append(text)
            continue
        response_obj = _responses_stream_event_value(event, "response")
        if isinstance(response_obj, dict):
            response_message = _responses_output_to_message(response_obj)
            if response_message:
                return response_message
        item = _responses_stream_event_item(event)
        if isinstance(item, dict):
            item_type = str(item.get("type") or "").strip()
            if item_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES or _native_provider_result_alias_value(item) is not None:
                output_items.append({"type": "tool_result", "content": "<provider tool result omitted>", "_provider_shape": "responses.stream.output"})
                continue
            if item_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
                output_items.append(dict(item, _provider_shape=str(item.get("_provider_shape") or "responses.stream.output")))
                continue
            if item_type in {"function_call", "tool_call", "tool_use"} or _responses_output_item_looks_like_message(item):
                key = resolve_bucket_key(event, item, fallback=f"position:{position}")
                bucket = buckets.get(key)
                if bucket is None:
                    bucket = dict(item, _provider_shape=str(item.get("_provider_shape") or "responses.stream.output"))
                    if any(bucket.get(alias) not in (None, "") for alias in ("call_id", "callId", "tool_call_id", "toolCallId", "tool_use_id", "toolUseId", "function_call_id", "functionCallId")):
                        bucket.pop("id", None)
                    buckets[key] = bucket
                    output_items.append(bucket)
                else:
                    _merge_native_tool_call_fragment(bucket, item)
                    if any(bucket.get(alias) not in (None, "") for alias in ("call_id", "callId", "tool_call_id", "toolCallId", "tool_use_id", "toolUseId", "function_call_id", "functionCallId")):
                        bucket.pop("id", None)
                continue
        if "function_call_arguments" in event_type or "tool_call_arguments" in event_type:
            key = resolve_bucket_key(event, item if isinstance(item, dict) else None, fallback=f"position:{position}")
            bucket = buckets.get(key)
            if bucket is None:
                bucket = {"type": "function_call", "_provider_shape": "responses.stream.output"}
                buckets[key] = bucket
                output_items.append(bucket)
            name = _responses_stream_event_value(event, "name", "function_name", "functionName", "toolName")
            if isinstance(name, str) and name.strip():
                _merge_native_tool_name_fragment(bucket, "name", name)
            call_id = _responses_stream_event_value(event, "call_id", "tool_call_id", "function_call_id", "toolCallId", "functionCallId", "callId")
            if call_id not in (None, "") and not bucket.get("call_id"):
                bucket["call_id"] = call_id
            if event_type.endswith(".delta"):
                delta = _responses_stream_event_value(
                    event,
                    *_native_argument_delta_keys(("arguments", "args", "input", "parameters", "params")),
                )
                if isinstance(delta, str):
                    bucket["arguments"] = str(bucket.get("arguments") or "") + delta
            if event_type.endswith(".done"):
                arguments = _responses_stream_event_value(
                    event,
                    *_native_argument_keys(("arguments", "args", "input", "parameters", "params")),
                )
                if arguments not in (None, ""):
                    bucket["arguments"] = arguments
    if not saw_stream_event:
        return {}
    payload: dict[str, Any] = {}
    if output_items:
        payload["output"] = output_items
    if text_parts:
        payload["output_text"] = "".join(text_parts)
    return _responses_output_to_message(payload) if payload else {}


def _responses_stream_event_items(raw: Any) -> list[Any]:
    if isinstance(raw, (bytes, bytearray)):
        return _parse_responses_sse_events(raw.decode("utf-8", errors="replace"))
    if isinstance(raw, str):
        return _parse_responses_sse_events(raw)
    if isinstance(raw, list):
        events: list[Any] = []
        for item in raw:
            if isinstance(item, (bytes, bytearray)):
                events.extend(_parse_responses_sse_events(item.decode("utf-8", errors="replace")))
            elif isinstance(item, str):
                events.extend(_parse_responses_sse_events(item))
            else:
                events.append(item)
        return events
    if not isinstance(raw, dict):
        return []
    for key in ("events", "stream", "chunks"):
        value = raw.get(key)
        if isinstance(value, list):
            events: list[Any] = []
            for item in value:
                if isinstance(item, (bytes, bytearray)):
                    events.extend(_parse_responses_sse_events(item.decode("utf-8", errors="replace")))
                elif isinstance(item, str):
                    events.extend(_parse_responses_sse_events(item))
                else:
                    events.append(item)
            return events
        if isinstance(value, str):
            return _parse_responses_sse_events(value)
    data = raw.get("data")
    if isinstance(data, list) and any(isinstance(item, dict) and str(item.get("type") or item.get("event") or "").startswith("response.") for item in data):
        return data
    if isinstance(data, str):
        parsed = _parse_responses_sse_events(data)
        if parsed:
            return parsed
    if _is_anthropic_stream_wrapper_event(raw):
        return [raw]
    if str(raw.get("type") or raw.get("event") or "").startswith("response."):
        return [raw]
    return []


def _parse_responses_sse_events(raw: str) -> list[dict[str, Any]]:
    """Parse raw Responses API SSE captures into bounded event dictionaries.

    Direct Responses streams and some local gateways persist ``event:``/``data:``
    frames rather than a final JSON object.  Only JSON ``data:`` payloads are
    accepted here; opaque text frames are ignored so provider output or secrets do
    not become tool-call summaries.  The caller still performs normal native
    tool-call translation plus runtime schema/ROE/policy validation before any
    dispatch can occur.
    """

    if not isinstance(raw, str) or not raw.strip():
        return []
    blocks = re.split(r"\r?\n\r?\n", raw.replace("\r\n", "\n"))
    events: list[dict[str, Any]] = []
    for block in blocks:
        event_name = ""
        sse_id = ""
        data_lines: list[str] = []
        for raw_line in block.split("\n"):
            line = raw_line.rstrip("\r")
            if not line or line.startswith(":"):
                continue
            field, sep, value = line.partition(":")
            if not sep:
                continue
            if value.startswith(" "):
                value = value[1:]
            if field == "event":
                event_name = value.strip()
            elif field == "id":
                sse_id = value.strip()
            elif field == "data":
                data_lines.append(value)
        if not data_lines:
            continue
        data_text = "\n".join(data_lines).strip()
        if not data_text or data_text == "[DONE]":
            continue
        try:
            data = json.loads(data_text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        event = dict(data)
        if event_name and "event" not in event and "type" not in event:
            event["event"] = event_name
        elif event_name and "event" not in event:
            event["event"] = event_name
        if sse_id and "sse_id" not in event:
            event["sse_id"] = _sanitize_native_call_id(sse_id)
        events.append(event)
    return events


_ANTHROPIC_STREAM_EVENT_ALIASES = {
    "messageStart": "message_start",
    "messageDelta": "message_delta",
    "messageStop": "message_stop",
    "contentBlockStart": "content_block_start",
    "contentBlockDelta": "content_block_delta",
    "contentBlockStop": "content_block_stop",
}
_ANTHROPIC_STREAM_WRAPPER_KEYS = tuple(_ANTHROPIC_STREAM_EVENT_ALIASES)


def _bedrock_converse_stream_events_to_message(raw: Any) -> dict[str, Any]:
    """Normalize Bedrock ConverseStream frames into an inert message shape.

    Bedrock's ConverseStream iterator yields camelCase wrapper events such as
    ``messageStart``, ``contentBlockStart`` and ``contentBlockDelta``.  The
    content blocks are structurally the same as Anthropic-style stream wrappers,
    but keeping a Bedrock-specific provider shape preserves source provenance in
    plan transcripts and execution ledgers.  This remains a translation-only
    adapter boundary; schema validation, runtime policy, ROE previews, approval
    queueing, and explicit execution gating happen later in the Phobos runtime.
    """

    if not isinstance(raw, dict):
        return {}
    response_format = str(raw.get("_response_format") or "").strip().lower()
    if not isinstance(raw.get("stream"), list) and response_format not in {"bedrock_converse_stream", "bedrock-converse-stream"}:
        return {}
    return _anthropic_stream_events_to_message(raw, provider_shape="bedrock.converse.stream.content")


def _is_anthropic_stream_wrapper_event(value: Any) -> bool:
    return isinstance(value, dict) and any(key in value for key in _ANTHROPIC_STREAM_WRAPPER_KEYS)


def _anthropic_stream_event_type_and_payload(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    raw_event_type = str(_responses_stream_event_value(event, "type", "event") or "").strip()
    payload = event
    if not raw_event_type:
        for key in _ANTHROPIC_STREAM_WRAPPER_KEYS:
            wrapped = event.get(key)
            if isinstance(wrapped, dict):
                raw_event_type = key
                payload = wrapped
                break
    return _ANTHROPIC_STREAM_EVENT_ALIASES.get(raw_event_type, raw_event_type), payload if isinstance(payload, dict) else event


def _anthropic_stream_start_block(event: dict[str, Any], *, provider_shape: str = "anthropic.messages.stream.content") -> dict[str, Any] | None:
    content_block = _responses_stream_event_value(event, "content_block", "contentBlock", "block")
    if isinstance(content_block, dict):
        return content_block
    start = _responses_stream_event_value(event, "start")
    if not isinstance(start, dict):
        return None
    tool_use_key, tool_use = _native_content_tool_use_alias(start)
    if isinstance(tool_use, dict):
        return {"type": tool_use_key or "toolUse", tool_use_key or "toolUse": tool_use}
    function_call = start.get("functionCall") or start.get("function_call")
    if isinstance(function_call, dict):
        return {"type": "functionCall", "functionCall": function_call}
    if _native_provider_result_alias_value(start) is not None:
        return {"type": "tool_result", "content": "<provider tool result omitted>", "_provider_shape": provider_shape}
    if any(key in start for key in ("type", "text", "name", "toolName", "functionName", "input", "inputJson", "arguments", "args")):
        return start
    return None


def _merge_anthropic_stream_tool_use_delta(block: dict[str, Any], delta: dict[str, Any]) -> bool:
    tool_use_key, tool_use = _native_content_tool_use_alias(delta)
    if not isinstance(tool_use, dict):
        return False
    block["type"] = tool_use_key or "toolUse"
    destination_key = "toolUse" if tool_use_key == "toolUse" or "toolUse" in block else "tool_use"
    existing = block.get(destination_key)
    if not isinstance(existing, dict):
        existing = {}
        block[destination_key] = existing
    for key in _native_argument_keys(("input", "arguments", "args", "parameters", "params")):
        if key in tool_use and isinstance(tool_use.get(key), str) and existing.get(key) == {}:
            existing[key] = ""
    _merge_native_tool_call_fragment(existing, tool_use)
    return True


def _anthropic_stream_events_to_message(raw: Any, *, provider_shape: str = "anthropic.messages.stream.content") -> dict[str, Any]:
    """Assemble Anthropic Messages SSE tool_use fragments into message shape.

    Anthropic streaming emits ``content_block_start`` plus
    ``content_block_delta`` frames; tool arguments arrive as
    ``input_json_delta.partial_json`` fragments.  Assemble those fragments only
    into inert provider-native planning proposals.  The runtime still owns tool
    name/schema validation, runtime policy, ROE preview, approval queueing,
    explicit execution gating, and transcript redaction before any dispatch.
    """

    events = _responses_stream_event_items(raw)
    if not events:
        return {}
    blocks: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    saw_anthropic_stream = False

    def block_key(event: dict[str, Any], position: int) -> str:
        value = _responses_stream_event_value(event, "index", "content_block_index", "contentBlockIndex")
        if isinstance(value, bool) or value in (None, ""):
            return f"position:{position}"
        return f"index:{value}"

    def ensure_block(key: str, initial: dict[str, Any] | None = None) -> dict[str, Any]:
        if key not in blocks:
            block = dict(initial or {})
            block.setdefault("type", "text")
            block.setdefault("_provider_shape", provider_shape)
            blocks[key] = block
            order.append(key)
        elif initial:
            _merge_native_tool_call_fragment(blocks[key], initial)
            blocks[key].setdefault("_provider_shape", provider_shape)
        return blocks[key]

    for position, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        event_type, event_payload = _anthropic_stream_event_type_and_payload(event)
        if not event_type.startswith(("message_", "content_block_")):
            continue
        saw_anthropic_stream = True
        if event_type == "message_start":
            message = _responses_stream_event_value(event_payload, "message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            ensure_block(f"message:{len(order)}", dict(item, _provider_shape=provider_shape))
            continue
        if event_type == "content_block_start":
            content_block = _anthropic_stream_start_block(event_payload, provider_shape=provider_shape)
            if isinstance(content_block, dict):
                ensure_block(block_key(event_payload, position), dict(content_block, _provider_shape=provider_shape))
            continue
        if event_type != "content_block_delta":
            continue
        delta = _responses_stream_event_value(event_payload, "delta")
        if not isinstance(delta, dict):
            continue
        block = ensure_block(block_key(event_payload, position))
        delta_type = str(delta.get("type") or "").strip()
        text_delta = delta.get("text")
        if delta_type == "text_delta" and isinstance(text_delta, str):
            block["text"] = str(block.get("text") or "") + text_delta
            block["type"] = str(block.get("type") or "text") or "text"
            continue
        if _merge_anthropic_stream_tool_use_delta(block, delta):
            continue
        partial = None
        for key in ("partial_json", "partialJson", "partial", *_native_argument_delta_keys(("input", "arguments", "args", "parameters", "params"))):
            value = delta.get(key)
            if isinstance(value, str):
                partial = value
                break
        if partial is not None:
            block["_partial_input_json"] = str(block.get("_partial_input_json") or "") + partial
            if str(block.get("type") or "") == "text":
                block["type"] = "tool_use"

    if not saw_anthropic_stream:
        return {}
    content_blocks: list[dict[str, Any]] = []
    for key in order:
        block = dict(blocks[key])
        partial = block.pop("_partial_input_json", "")
        if isinstance(partial, str) and partial:
            try:
                parsed = json.loads(partial)
                block["input"] = parsed if isinstance(parsed, dict) else partial
            except json.JSONDecodeError:
                block["input"] = partial
        content_blocks.append(block)
    return {"content": content_blocks} if content_blocks else {}


def _responses_stream_event_value(event: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in event:
            return event.get(key)
    data = event.get("data")
    if isinstance(data, dict):
        for key in keys:
            if key in data:
                return data.get(key)
    return None


def _responses_stream_event_item(event: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("item", "output_item", "outputItem"):
        value = _responses_stream_event_value(event, key)
        if isinstance(value, dict):
            return value
    return None


def _responses_stream_item_key(event: dict[str, Any], item: dict[str, Any] | None, *, fallback: str) -> str:
    return _responses_stream_item_keys(event, item, fallback=fallback)[0]


def _responses_stream_item_keys(event: dict[str, Any], item: dict[str, Any] | None, *, fallback: str) -> list[str]:
    """Return all safe correlation keys for a Responses stream item.

    Raw Responses/SSE captures do not always use the same identifier on every
    event: an ``output_item.added`` frame may carry an internal item ``id`` while
    later argument deltas carry only the provider ``call_id``.  Return every
    recognizable alias so the stream assembler can merge those fragments into a
    single planned call while still preserving the provider call id separately in
    transcripts and execution ledgers.
    """

    candidates = [
        _responses_stream_event_value(event, "item_id", "itemId", "output_item_id", "outputItemId"),
        _responses_stream_event_value(event, "call_id", "callId", "tool_call_id", "toolCallId", "function_call_id", "functionCallId"),
    ]
    if isinstance(item, dict):
        candidates.extend([
            item.get("id"),
            item.get("item_id"),
            item.get("call_id"),
            item.get("callId"),
            item.get("tool_call_id"),
            item.get("toolCallId"),
            item.get("function_call_id"),
            item.get("functionCallId"),
        ])
    output_index = _responses_stream_event_value(event, "output_index", "outputIndex", "index")
    if output_index not in (None, ""):
        candidates.append(f"index:{output_index}")
    keys: list[str] = []
    for candidate in candidates:
        if candidate not in (None, ""):
            key = str(candidate)
            if key not in keys:
                keys.append(key)
    if fallback not in keys:
        keys.append(fallback)
    return keys


def _merge_choice_delta_tool_call_chunks(chunks: list[Any]) -> list[Any]:
    merged: list[Any] = []
    buckets: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(chunks):
        if not isinstance(item, dict):
            merged.append(item)
            continue
        key = _choice_delta_tool_call_merge_key(item, fallback_position=position)
        if not key:
            merged.append(item)
            continue
        if key not in buckets:
            buckets[key] = {}
            merged.append(buckets[key])
        _merge_native_tool_call_fragment(buckets[key], item)
    return merged


def _choice_delta_tool_call_merge_key(item: dict[str, Any], *, fallback_position: int) -> str:
    for key in ("index", "tool_call_index", "toolCallIndex"):
        value = item.get(key)
        if isinstance(value, bool) or value in (None, ""):
            continue
        return f"index:{value}"
    provider_shape = str(item.get("_provider_shape") or "")
    call_id = _native_call_id(
        item,
        item.get("function") if isinstance(item.get("function"), dict) else None,
        item.get("functionCall") if isinstance(item.get("functionCall"), dict) else None,
        item.get("function_call") if isinstance(item.get("function_call"), dict) else None,
        item.get("toolUse") if isinstance(item.get("toolUse"), dict) else None,
        item.get("tool_use") if isinstance(item.get("tool_use"), dict) else None,
    )
    if call_id:
        return f"id:{call_id}"
    if (
        provider_shape.endswith(".function_call")
        and provider_shape.startswith(("choice.delta", "chat.completions.sse.delta"))
        and isinstance(item.get("function"), dict)
    ):
        # Legacy OpenAI-compatible Chat Completions streams expose a single
        # ``delta.function_call`` object with the name and JSON arguments split
        # across multiple chunks, but without modern ``tool_calls[].index`` or a
        # provider call id.  Merge those chunks as one inert planner proposal;
        # runtime schema, ROE, policy, and execute gates still own dispatch.
        return f"{provider_shape}:legacy_function_call"
    return f"position:{fallback_position}"


_NATIVE_TOOL_NAME_ALIAS_KEYS = ("name", "tool", "tool_name", "toolName", "function_name", "functionName")


def _merge_native_tool_call_fragment(destination: dict[str, Any], source: dict[str, Any]) -> None:
    argument_keys = set(_native_argument_keys(("arguments", "args", "input", "parameters", "params")))
    name_keys = set(_NATIVE_TOOL_NAME_ALIAS_KEYS) | {"function"}
    nested_keys = {"function", "functionCall", "function_call", "toolUse", "tool_use"}
    for key, value in source.items():
        if key in nested_keys and isinstance(value, dict):
            existing = destination.get(key)
            if not isinstance(existing, dict):
                existing = {}
                destination[key] = existing
            _merge_native_tool_call_fragment(existing, value)
            continue
        if key in argument_keys and isinstance(value, str) and isinstance(destination.get(key), str):
            destination[key] = str(destination.get(key) or "") + value
            continue
        if key in name_keys and isinstance(value, str):
            if _merge_native_tool_name_fragment(destination, key, value):
                continue
        if key not in destination or destination.get(key) in (None, ""):
            destination[key] = value


def _merge_native_tool_name_fragment(destination: dict[str, Any], key: str, value: str) -> bool:
    """Merge streamed tool/function-name fragments without creating new calls.

    Chat Completions and Responses streams can fragment the tool name just like
    argument JSON. Keep the fragments inside the same inert provider proposal so
    the runtime still performs registered-tool/schema/ROE validation before any
    dispatch. Repeated full-name echoes are ignored; differing same-bucket name
    fragments are appended and will fail closed later if they do not form a
    registered tool name.
    """

    if not isinstance(value, str):
        return False
    if isinstance(destination.get(key), dict):
        return _merge_native_tool_name_fragment(destination[key], "name", value)
    existing_key = next(
        (
            alias
            for alias in (*_NATIVE_TOOL_NAME_ALIAS_KEYS, "function")
            if isinstance(destination.get(alias), str) and str(destination.get(alias) or "")
        ),
        "",
    )
    if existing_key:
        existing = str(destination.get(existing_key) or "")
        if value and value != existing and not existing.endswith(value):
            overlap = 0
            max_overlap = min(len(existing), len(value))
            for width in range(max_overlap, 0, -1):
                if existing.endswith(value[:width]):
                    overlap = width
                    break
            destination[existing_key] = existing + value[overlap:]
        return True
    destination[key] = value
    return True


def _provider_message_wrapper_to_message(raw: dict[str, Any], *, provider_shape_prefix: str) -> dict[str, Any]:
    """Build a chat message from a provider wrapper carrying message fields."""

    result_echo = _native_provider_result_role_message(raw, provider_shape=provider_shape_prefix)
    if result_echo:
        return result_echo
    message: dict[str, Any] = {}
    if "content" in raw:
        content_blocks: list[dict[str, Any]] = []
        _extend_responses_content_blocks(
            content_blocks,
            raw.get("content"),
            provider_shape=f"{provider_shape_prefix}.content",
        )
        if content_blocks:
            message["content"] = content_blocks
        else:
            content_value = raw.get("content")
            if isinstance(content_value, (str, list, dict)) or content_value is None:
                message["content"] = content_value
    tool_calls: list[dict[str, Any]] = []
    _extend_responses_message_tool_calls(tool_calls, raw, provider_shape_prefix=provider_shape_prefix)
    if tool_calls:
        message["tool_calls"] = tool_calls
    function_response = _native_provider_result_alias_value(raw)
    if isinstance(function_response, dict):
        _append_message_content_block(
            message,
            {"type": "tool_result", "content": _native_provider_result_content(function_response)},
        )
    return message if message else {}


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
                if (
                    block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES | _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES | _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES
                    or _native_provider_result_alias_value(item) is not None
                ):
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


def _native_argument_delta_keys(preferred: tuple[str, ...]) -> list[str]:
    """Return streaming delta aliases for provider-native argument fragments.

    Responses/SSE captures normally use ``delta`` or ``arguments_delta``, but a
    few OpenAI-compatible gateways preserve JSON-alias spellings such as
    ``argumentsJsonDelta`` or ``input_json_delta``.  Assemble those fragments at
    the adapter boundary only; normal schema/ROE/runtime-policy validation still
    owns any eventual dispatch.
    """

    keys = ["delta"]
    for key in _native_argument_keys(preferred):
        for candidate in (f"{key}_delta", f"{key}Delta"):
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


def _native_tool_name(mapping: dict[str, Any]) -> str:
    """Return a provider-native tool/function name from common aliases.

    Most providers use ``name`` for function calls, but some local shims and
    Gemini/OpenAI bridges preserve JS-ish aliases such as ``toolName`` or
    ``functionName``.  Normalize the label at the adapter boundary only; the
    runtime still validates that the resulting name is a registered tool before
    any dispatch, approval queueing, or ROE side effects can occur.
    """

    if not isinstance(mapping, dict):
        return ""
    for key in _NATIVE_TOOL_NAME_ALIAS_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


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


_NATIVE_CALL_ID_ALIAS_KEYS = (
    "id",
    "call_id",
    "tool_call_id",
    "tool_use_id",
    "function_call_id",
    "callId",
    "toolCallId",
    "toolUseId",
    "functionCallId",
)


def _native_tool_call_batch_items(raw_calls: Any, *, provider_shape: str) -> list[Any]:
    """Return provider-native tool-call items from array, single-object, or object-map batches.

    Most providers return ``tool_calls`` as a list, and Phobos already accepts a
    few single-object shims.  Some lightweight OpenAI-compatible gateways expose
    a keyed object map instead, e.g. ``{"call_1": {"function": ...}}``.  Expand
    that map into inert provider-native proposals, preserving the map key as a
    bounded call id only; schema validation, runtime policy, ROE previews,
    approval gates, and execution controls still happen in the runtime.
    """

    if isinstance(raw_calls, list):
        return [
            dict(item, _provider_shape=str(item.get("_provider_shape") or provider_shape))
            if provider_shape and isinstance(item, dict) and "_provider_shape" not in item
            else item
            for item in raw_calls
        ]
    if not isinstance(raw_calls, dict):
        return [raw_calls] if raw_calls is not None else []
    if _native_tool_call_object_looks_like_single(raw_calls):
        shape = provider_shape or "single_top_level.tool_calls"
        return [dict(raw_calls, _provider_shape=str(raw_calls.get("_provider_shape") or shape))]

    shape = f"{provider_shape}.object_map" if provider_shape else "tool_calls.object_map"
    items: list[Any] = []
    for map_key, value in raw_calls.items():
        if not isinstance(value, dict):
            items.append(value)
            continue
        entry = dict(value)
        entry.setdefault("_provider_shape", shape)
        if not _native_tool_call_has_id(entry):
            entry["call_id"] = str(map_key)
        items.append(entry)
    return items


def _native_tool_call_object_looks_like_single(value: dict[str, Any]) -> bool:
    single_markers = {
        "function",
        "functionCall",
        "function_call",
        "toolUse",
        "tool_use",
        "tool",
        "name",
        "tool_name",
        "toolName",
        "function_name",
        "functionName",
        "type",
        *_NATIVE_CALL_ID_ALIAS_KEYS,
        *_native_argument_keys(("arguments", "args", "input", "parameters", "params")),
    }
    return any(key in value for key in single_markers)


def _native_tool_call_has_id(value: dict[str, Any]) -> bool:
    return any(value.get(key) not in (None, "") for key in _NATIVE_CALL_ID_ALIAS_KEYS)


def _native_neutral_tool_call(provider_shape: str, item: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    """Return an inert call object for neutral nested ``tool`` wrappers.

    Most providers use ``function`` / ``functionCall`` / ``toolUse``.  A few
    OpenAI-compatible routers expose a registered function proposal as a neutral
    ``tool`` object at the response root or message level.  Flatten only the
    name/JSON arguments into Phobos' common native-call shape; schema checks,
    runtime policy, ROE preview, approval queues, and execution controls remain
    runtime boundaries.
    """

    return {
        "type": "tool_call",
        "name": _native_tool_name(tool),
        "arguments": _native_argument_value(tool, preferred=("input", "arguments", "args", "parameters", "params")),
        "call_id": str(_native_call_id(item, tool)),
        "_provider_shape": provider_shape,
    }


def _native_provider_result_role_message(raw: Any, *, provider_shape: str) -> dict[str, Any]:
    """Return an inert message for provider role=tool/function result echoes.

    Some hosted/model gateways echo previous tool outputs as full messages with
    ``role=tool`` or legacy ``role=function`` instead of typed ``tool_result``
    blocks.  Treat those as provider-side result state, not assistant summary
    text and never as fresh tool requests.  Do not preserve raw content: it may
    contain upstream command output or secrets and is not needed for Phobos'
    local validation boundary.
    """

    if not isinstance(raw, dict):
        return {}
    role_value = raw.get("role")
    author = raw.get("author")
    if role_value in (None, "") and isinstance(author, dict):
        role_value = author.get("role")
    role = str(role_value or "").strip().lower()
    if role not in _NATIVE_PROVIDER_RESULT_MESSAGE_ROLES:
        return {}
    return {
        "content": [
            {
                "type": "tool_result",
                "content": "<provider tool result omitted>",
                "_provider_shape": f"{provider_shape}.role_result",
            }
        ]
    }


def _extend_result_echo_content_blocks(blocks: list[dict[str, Any]], message: dict[str, Any]) -> None:
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        blocks.extend([item for item in content if isinstance(item, dict)])
    elif isinstance(content, dict):
        blocks.append(content)


_NATIVE_TOOL_USE_ALIAS_KEYS = ("tool_use", "toolUse", "tool_uses", "toolUses")


def _root_message_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize root-level provider ``message`` wrappers into chat shape.

    Some local or OpenAI-compatible shims return ``{"message": {...}}`` at the
    response root instead of Chat-Completions ``choices[0].message`` or Responses
    ``output[]`` wrappers.  Treat only the recognizable assistant message fields
    as native planner proposals; Phobos still validates tool names/schemas,
    runtime policy, ROE, approvals, execution intent, and transcript redaction
    before any registry handler can dispatch.
    """

    if not isinstance(raw, dict):
        return {}
    root_message = raw.get("message")
    if not isinstance(root_message, dict):
        return {}
    result_echo = _native_provider_result_role_message(root_message, provider_shape="root.message")
    if result_echo:
        return result_echo
    message: dict[str, Any] = {}
    if "content" in root_message:
        content_blocks: list[dict[str, Any]] = []
        _extend_responses_content_blocks(
            content_blocks,
            root_message.get("content"),
            provider_shape="root.message.content",
        )
        if content_blocks:
            message["content"] = content_blocks
        else:
            content_value = root_message.get("content")
            if isinstance(content_value, (str, list, dict)) or content_value is None:
                message["content"] = content_value
    tool_calls: list[dict[str, Any]] = []
    _extend_responses_message_tool_calls(tool_calls, root_message, provider_shape_prefix="root.message")
    if tool_calls:
        message["tool_calls"] = tool_calls
    function_response = _native_provider_result_alias_value(root_message)
    if isinstance(function_response, dict):
        _append_message_content_block(
            message,
            {"type": "tool_result", "content": _native_provider_result_content(function_response)},
        )
    return message if message else {}


def _root_messages_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize root-level ``messages[]`` transcript wrappers into one assistant message.

    A few local/OpenAI-compatible shims return a bounded chat transcript as
    ``{"messages": [...]}`` rather than a final ``choices[0].message``.  Select
    the latest non-result assistant/model message and translate only its native
    tool-call fields into the existing planner boundary.  Prior ``tool`` or
    ``function`` role result messages are ignored so upstream tool output cannot
    become Phobos summary text or dispatch input.
    """

    if not isinstance(raw, dict):
        return {}
    root_messages = raw.get("messages")
    if not isinstance(root_messages, list) or not root_messages:
        return {}
    for item in reversed(root_messages):
        if not isinstance(item, dict):
            continue
        if _native_provider_result_role_message(item, provider_shape="root.messages"):
            continue
        role_value = item.get("role")
        author = item.get("author")
        if role_value in (None, "") and isinstance(author, dict):
            role_value = author.get("role")
        role = str(role_value or "").strip().lower()
        if role and role not in {"assistant", "model"}:
            continue
        if not _responses_output_item_looks_like_message(item):
            continue
        message = _provider_message_wrapper_to_message(item, provider_shape_prefix="root.messages")
        if message:
            return message
    return {}


def _root_contents_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize root-level Gemini/Vertex ``contents[]`` transcript wrappers.

    Some local provider gateways return a bounded Gemini-style transcript as
    ``{"contents": [...]}`` instead of the final ``candidates[]`` response or a
    Chat-Completions ``messages[]`` wrapper.  Select the latest assistant/model
    content item, translate only its ``parts[]`` tool-call proposals, and ignore
    prior tool/function result messages so upstream tool output cannot become a
    Phobos summary or dispatch input.  This remains adapter-only translation:
    schema validation, runtime policy, ROE preview, approvals, explicit execute
    intent, and transcript redaction stay in the Phobos runtime.
    """

    if not isinstance(raw, dict):
        return {}
    contents = raw.get("contents")
    if isinstance(contents, dict):
        content_items = [contents]
    elif isinstance(contents, list):
        content_items = [item for item in contents if isinstance(item, dict)]
    else:
        return {}
    if not content_items:
        return {}
    for item in reversed(content_items):
        if _native_provider_result_role_message(item, provider_shape="root.contents"):
            continue
        role_value = item.get("role")
        author = item.get("author")
        if role_value in (None, "") and isinstance(author, dict):
            role_value = author.get("role")
        role = str(role_value or "").strip().lower()
        if role and role not in {"assistant", "model"}:
            continue
        candidate = dict(item)
        if "content" not in candidate and "parts" in candidate:
            candidate["content"] = {"parts": candidate.get("parts")}
        if not _responses_output_item_looks_like_message(candidate):
            continue
        message = _provider_message_wrapper_to_message(candidate, provider_shape_prefix="root.contents")
        if message:
            return message
    return {}


def _root_prediction_wrapper_items(raw: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Return Vertex/AI-gateway prediction objects plus their root wrapper key."""

    if not isinstance(raw, dict):
        return "", []
    predictions = raw.get("predictions")
    if isinstance(predictions, dict):
        return "predictions", [predictions]
    if isinstance(predictions, list):
        return "predictions", [prediction for prediction in predictions if isinstance(prediction, dict)]
    prediction = raw.get("prediction")
    if isinstance(prediction, dict):
        return "prediction", [prediction]
    return "", []


def _root_prediction_items(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Vertex/AI-gateway prediction objects from plural or singular wrappers."""

    return _root_prediction_wrapper_items(raw)[1]


def _root_predictions_to_message(raw: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Normalize root-level Vertex/AI-gateway ``predictions[]`` wrappers.

    Several local or Vertex-compatible gateways return a final model payload as
    ``{"predictions": [...]}`` or a collapsed singular ``{"prediction": ...}``
    rather than Chat Completions ``choices`` or a Gemini ``candidates`` object.
    Walk newest-first, treat each prediction as an inert assistant
    message/proposal candidate, skip provider result echoes, and let the normal
    Phobos runtime boundary validate schemas, runtime policy, ROE previews,
    approvals, explicit execute intent, transcripts, and redaction before any
    handler can run.  Recursion is bounded so malformed nested prediction
    envelopes fail closed as no-tool responses.
    """

    if depth >= 3 or not isinstance(raw, dict):
        return {}
    wrapper_key, prediction_items = _root_prediction_wrapper_items(raw)
    if not prediction_items:
        return {}
    provider_shape_prefix = "root.predictions" if wrapper_key == "predictions" else "root.prediction"
    for item in reversed(prediction_items):
        if _native_provider_result_role_message(item, provider_shape=provider_shape_prefix):
            continue
        message_obj = item.get("message")
        if isinstance(message_obj, dict):
            result_echo = _native_provider_result_role_message(message_obj, provider_shape=provider_shape_prefix)
            if result_echo:
                continue
            message = _provider_message_wrapper_to_message(message_obj, provider_shape_prefix=provider_shape_prefix)
            if message:
                return message
        if _responses_output_item_looks_like_message(item):
            message = _provider_message_wrapper_to_message(item, provider_shape_prefix=provider_shape_prefix)
            if message:
                return message
        nested = _first_choice_message(item, _wrapper_depth=depth + 1)
        if nested:
            return nested
    return {}


def _root_output_wrapper_items(raw: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Return provider output objects from root-level output wrappers.

    OpenAI Responses uses ``output[]`` while some OpenAI-compatible routers and
    trace gateways expose pluralized ``outputs[]`` or raw item captures as
    ``output_items[]`` / ``outputItems[]``. A few router transcript APIs shorten
    the same final provider-output capture to root ``items[]`` / ``item``. Some
    lightweight routers expose plural wrappers as keyed object maps instead of
    arrays, for example ``{"output_items": {"call_1": {"type": "function_call", ...}}}``.
    Normalize only those explicit output wrappers here; the resulting tool calls
    still pass through Phobos runtime schema, policy, ROE, approval, execute,
    transcript, and ledger boundaries.
    """

    if not isinstance(raw, dict):
        return "", []
    plural_map_wrappers = {"outputs", "output_items", "outputItems", "items"}
    for wrapper_key in ("outputs", "output_items", "outputItems", "output_item", "outputItem", "items", "item"):
        outputs = raw.get(wrapper_key)
        if isinstance(outputs, dict):
            if wrapper_key in plural_map_wrappers:
                mapped = _root_output_object_map_items(outputs, provider_shape=f"root.{wrapper_key}.object_map")
                if mapped:
                    return wrapper_key, mapped
            return wrapper_key, [outputs]
        if isinstance(outputs, list):
            return wrapper_key, [output for output in outputs if isinstance(output, dict)]
    return "", []


def _root_output_object_map_items(outputs: dict[str, Any], *, provider_shape: str) -> list[dict[str, Any]]:
    """Expand keyed root output-wrapper maps into inert provider output items.

    Provider maps are provenance only.  Preserve a bounded map key as ``call_id``
    when the nested output item lacks one, but do not validate schemas, queue
    approvals, write evidence, or dispatch handlers in the adapter.
    """

    if _root_output_mapping_looks_like_single(outputs):
        return []
    items: list[dict[str, Any]] = []
    for map_key, value in outputs.items():
        if not isinstance(value, dict):
            continue
        entry = dict(value)
        entry.setdefault("_provider_shape", provider_shape)
        if not _native_tool_call_has_id(entry):
            entry["call_id"] = str(map_key)
        items.append(entry)
    return items


def _root_output_mapping_looks_like_single(value: dict[str, Any]) -> bool:
    """Return True when a root output wrapper dict is a collapsed single item.

    This keeps already-supported collapsed ``{"output_items": {"type": ...}}``
    responses working while allowing dicts whose keys are only provider call IDs
    to be treated as object maps.
    """

    if _root_output_item_is_direct_tool_call(value):
        return True
    if _responses_output_item_looks_like_message(value):
        return True
    return any(
        key in value
        for key in (
            "message",
            "role",
            "author",
            *_NATIVE_CALL_ID_ALIAS_KEYS,
        )
    )


def _root_output_item_is_direct_tool_call(item: dict[str, Any]) -> bool:
    """Return True for raw Responses-style tool-call items inside ``outputs[]``."""

    if not isinstance(item, dict):
        return False
    if isinstance(item.get("message"), dict):
        return False
    block_type = str(item.get("type") or "").strip()
    if block_type in {"function", "function_call", "tool_call", "tool_use"}:
        return True
    if isinstance(item.get("function"), dict):
        return True
    if isinstance(item.get("functionCall") or item.get("function_call"), dict):
        return True
    if isinstance(item.get("tool"), dict):
        return True
    return any(isinstance(item.get(alias), dict) for alias in _NATIVE_TOOL_USE_ALIAS_KEYS)


def _root_outputs_direct_tool_calls_to_message(items: list[dict[str, Any]], *, provider_shape_prefix: str = "root.outputs") -> dict[str, Any]:
    """Normalize contiguous direct root output-wrapper tool-call blocks as one response.

    Some OpenAI-compatible routers pluralize Responses API ``output[]`` as
    ``outputs[]`` or persist raw item captures as ``output_items[]`` and place
    flat ``function_call``/``function`` items there directly instead of wrapping
    them in an assistant ``message``.  Keep this as an adapter-only translation
    boundary: collect only the latest contiguous direct-call block, preserve root
    output provenance, and let runtime schema, policy, ROE, approval, explicit
    execution, and transcript checks decide what can run.
    """

    output_items: list[dict[str, Any]] = []
    for item in items:
        entry = dict(item)
        block_type = str(entry.get("type") or "").strip() or "tool_call"
        entry.setdefault("_provider_shape", f"{provider_shape_prefix}.{block_type}")
        output_items.append(entry)
    return _responses_output_to_message({"output": output_items}) if output_items else {}


def _root_outputs_to_message(raw: dict[str, Any], *, depth: int = 0) -> dict[str, Any]:
    """Normalize root-level ``outputs[]`` wrappers from provider gateways.

    Some AI-gateway and model-router responses use ``{"outputs": [...]}`` as
    the outer envelope for assistant messages or native tool-call proposals.
    Translate only recognizable message/function-call content into the existing
    inert planner boundary, skip provider result echoes, and recurse with a hard
    depth cap so malformed nested wrappers fail closed.  Runtime schema
    validation, runtime policy, ROE previews, approval replay, explicit execute
    intent, transcript redaction, and dispatch remain Phobos runtime concerns.
    """

    if depth >= 3 or not isinstance(raw, dict):
        return {}
    wrapper_key, items = _root_output_wrapper_items(raw)
    if not items:
        return {}
    provider_shape_prefix = "root.outputs" if wrapper_key == "outputs" else f"root.{wrapper_key}"
    direct_items: list[dict[str, Any]] = []
    for item in reversed(items):
        if _native_provider_result_role_message(item, provider_shape=provider_shape_prefix):
            if direct_items:
                break
            continue
        if _root_output_item_is_direct_tool_call(item):
            direct_items.append(item)
            continue
        if direct_items:
            break
        message_obj = item.get("message")
        if isinstance(message_obj, dict):
            result_echo = _native_provider_result_role_message(message_obj, provider_shape=provider_shape_prefix)
            if result_echo:
                continue
            message = _provider_message_wrapper_to_message(message_obj, provider_shape_prefix=provider_shape_prefix)
            if message:
                return message
        if _responses_output_item_looks_like_message(item):
            message = _provider_message_wrapper_to_message(item, provider_shape_prefix=provider_shape_prefix)
            if message:
                return message
        nested = _first_choice_message(item, _wrapper_depth=depth + 1)
        if nested:
            return nested
    if direct_items:
        return _root_outputs_direct_tool_calls_to_message(list(reversed(direct_items)), provider_shape_prefix=provider_shape_prefix)
    return {}


def _candidate_items(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Return Gemini-style candidate objects from plural or collapsed wrappers."""

    if not isinstance(raw, dict):
        return []
    candidates = raw.get("candidates")
    if isinstance(candidates, dict):
        return [candidates]
    if isinstance(candidates, list):
        return [candidate for candidate in candidates if isinstance(candidate, dict)]
    candidate = raw.get("candidate")
    if isinstance(candidate, dict):
        return [candidate]
    return []


def _candidate_direct_part_like(mapping: dict[str, Any]) -> bool:
    """Return True when a collapsed candidate/content object is itself a part.

    Most Gemini-compatible providers use ``candidate.content.parts[]``.  Some
    local gateways collapse a single-part response further and put
    ``functionCall``/``function_call`` directly on ``content`` or the candidate
    object itself.  Treat only recognizable part-like keys as native planner
    state so unrelated metadata on a candidate does not become dispatch input.
    """

    if not isinstance(mapping, dict):
        return False
    if any(key in mapping for key in ("text", "functionCall", "function_call", *_NATIVE_TOOL_USE_ALIAS_KEYS)):
        return True
    if _native_provider_result_alias_value(mapping) is not None:
        return True
    block_type = str(mapping.get("type") or "").strip()
    return block_type in (_NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES | _NATIVE_PROVIDER_RESULT_BLOCK_TYPES)


def _candidate_content_parts(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """Return candidate parts from list/dict/direct collapsed forms."""

    if not isinstance(candidate, dict):
        return []
    content = candidate.get("content") if isinstance(candidate.get("content"), dict) else {}
    parts = content.get("parts") if isinstance(content, dict) else None
    if isinstance(parts, dict):
        return [parts]
    if isinstance(parts, list):
        return [part for part in parts if isinstance(part, dict)]
    if isinstance(content, dict) and "parts" in content:
        # A present-but-malformed parts field should fail closed rather than
        # falling back to looser direct-candidate parsing.
        return []
    if isinstance(content, dict) and _candidate_direct_part_like(content):
        return [content]
    if _candidate_direct_part_like(candidate):
        return [candidate]
    return []


def _candidate_content_to_message(raw: dict[str, Any], *, provider_shape: str = "gemini.candidate") -> dict[str, Any]:
    """Normalize candidate/part native function calls into the common shape.

    Some OpenAI-compatible gateways front providers that expose Gemini-style
    ``candidates[].content.parts[]`` payloads, while lighter shims may collapse
    that into ``candidates: {...}`` or a singular ``candidate`` object.  Normalize
    those wrappers at the adapter boundary; camelCase ``functionCall`` entries
    and ``args``/``parameters`` objects become inert calls instead of Chat Completions
    ``tool_calls``.  Treat them exactly like other planner proposals: translate
    only the requested registered-call shape and leave all ROE/schema/runtime
    enforcement to the Phobos runtime.  Provider-side ``functionResponse``
    echoes are preserved only as ignored result blocks so their content never
    becomes summary text or dispatch input.
    """

    if not isinstance(raw, dict):
        return {}
    candidates = _candidate_items(raw)
    if not candidates:
        return {}
    first = candidates[0]
    parts = _candidate_content_parts(first)
    if not parts:
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
            # Gemini-compatible candidate parts may put the correlation id on the
            # part wrapper rather than inside functionCall itself. Preserve both
            # as bounded provenance while leaving schema/ROE validation in the
            # runtime boundary.
            call_id = _native_call_id(part, function_call)
            tool_calls.append({
                "type": "tool_call",
                "name": _native_tool_name(function_call),
                "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                "call_id": str(call_id),
                "_provider_shape": provider_shape,
            })
        function_response = _native_provider_result_alias_value(part)
        if isinstance(function_response, dict):
            content_blocks.append({"type": "tool_result", "content": _native_provider_result_content(function_response)})
    if not content_blocks and not tool_calls:
        return {}
    return {"content": content_blocks, "tool_calls": tool_calls}


def _bedrock_converse_output_to_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Bedrock/Converse ``output.message`` tool-use responses.

    AWS Bedrock Converse and Anthropic-compatible gateways commonly return a
    non-stream response as ``{"output": {"message": {"content": [...]}}}``
    where tool requests are content-block ``toolUse`` objects and prior results
    are ``toolResult`` blocks.  Translate only those inert planner proposals into
    the normal message shape; runtime schema validation, policy, ROE previews,
    approvals, explicit execute intent, and transcript redaction remain
    authoritative before any Phobos handler can dispatch.
    """

    if not isinstance(raw, dict):
        return {}
    output = raw.get("output")
    if not isinstance(output, dict):
        return {}
    message_obj = output.get("message")
    if not isinstance(message_obj, dict):
        return {}
    result_echo = _native_provider_result_role_message(message_obj, provider_shape="bedrock.converse.message")
    if result_echo:
        return result_echo
    message: dict[str, Any] = {}
    if "content" in message_obj:
        content_blocks: list[dict[str, Any]] = []
        _extend_responses_content_blocks(
            content_blocks,
            message_obj.get("content"),
            provider_shape="bedrock.converse.message.content",
        )
        if content_blocks:
            message["content"] = content_blocks
        else:
            content_value = message_obj.get("content")
            if isinstance(content_value, (str, list, dict)) or content_value is None:
                message["content"] = content_value
    tool_calls: list[dict[str, Any]] = []
    _extend_responses_message_tool_calls(tool_calls, message_obj, provider_shape_prefix="bedrock.converse.message")
    if tool_calls:
        message["tool_calls"] = tool_calls
    function_response = _native_provider_result_alias_value(message_obj)
    if isinstance(function_response, dict):
        _append_message_content_block(
            message,
            {"type": "tool_result", "content": _native_provider_result_content(function_response)},
        )
    return message if message else {}


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
        nested_message = item.get("message")
        is_typeless_nested_message = not block_type and isinstance(nested_message, dict)
        is_typeless_direct_message = not block_type and not isinstance(nested_message, dict) and _responses_output_item_looks_like_message(item)
        is_message_item = block_type == "message" or is_typeless_nested_message or is_typeless_direct_message
        if is_message_item:
            direct_prefix = "responses.output.message_typeless" if is_typeless_direct_message else "responses.message"
            direct_result_echo = _native_provider_result_role_message(item, provider_shape=direct_prefix)
            if direct_result_echo:
                _extend_result_echo_content_blocks(content_blocks, direct_result_echo)
                continue
            nested_result_echo = _native_provider_result_role_message(nested_message, provider_shape="responses.output.message") if isinstance(nested_message, dict) else {}
            if nested_result_echo:
                _extend_result_echo_content_blocks(content_blocks, nested_result_echo)
                continue
            direct_content_shape = f"{direct_prefix}.content"
            _extend_responses_content_blocks(content_blocks, item.get("content"), provider_shape=direct_content_shape)
            _extend_responses_message_tool_calls(tool_calls, item, provider_shape_prefix=direct_prefix)
            if isinstance(nested_message, dict):
                # A few Responses-compatible shims wrap the assistant message
                # under output[].message rather than putting content/tool-call
                # aliases directly on the output[] item. Some omit
                # output[].type="message" entirely; still keep this in the same
                # native planning boundary so schema, runtime policy, ROE,
                # approval, and transcript rules remain authoritative.
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
                "name": _native_tool_name(item),
                "call_id": str(call_id),
                "_provider_shape": provider_shape,
            })
            continue
        if block_type in {"function", "function_call", "tool_call", "tool_use"}:
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
                    "name": _native_tool_name(function_call),
                    "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                    "call_id": str(_native_call_id(item, function_call)),
                    "_provider_shape": f"{provider_shape}.functionCall",
                })
                continue
            tool = item.get("tool")
            if isinstance(tool, dict):
                # A few provider routers use a neutral nested ``tool`` object
                # inside Responses-style output items rather than OpenAI's
                # ``function`` or Gemini's ``functionCall`` wrappers.  Keep this
                # as inert planner provenance; runtime schema, ROE, approval,
                # and explicit execution gates still own dispatch.
                tool_calls.append({
                    "type": "tool_call",
                    "tool": tool,
                    "call_id": str(_native_call_id(item, tool)),
                    "_provider_shape": f"{provider_shape}.tool",
                })
                continue
            name = _native_tool_name(item)
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
        if block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES or _native_provider_result_alias_value(item) is not None:
            content_blocks.append({"type": "tool_result", "content": _native_provider_result_content(item)})
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


def _responses_output_item_looks_like_message(item: dict[str, Any]) -> bool:
    """Return True for typeless Responses output items carrying message fields.

    Some OpenAI-compatible shims omit ``output[].type = "message"`` but put
    ``content`` and/or tool-call aliases directly on the output item instead of
    nesting them under ``output[].message``.  Treat only recognizable message
    fields as a message wrapper so unrelated typeless objects remain inert at the
    adapter boundary until Phobos can validate a registered tool call explicitly.
    """

    return any(
        key in item
        for key in (
            "content",
            "tool_calls",
            "toolCalls",
            "tool_call",
            "toolCall",
            "tool",
            *_NATIVE_TOOL_USE_ALIAS_KEYS,
            "function_call",
            "functionCall",
            "function_calls",
            "functionCalls",
        )
    )


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


def _anthropic_message_with_provider_shape(message: dict[str, Any]) -> dict[str, Any]:
    """Mark Anthropic Messages content blocks with provider provenance.

    Anthropic's native ``tool_use`` calls live inside top-level ``content``
    blocks.  Preserve a bounded provider-shape label for transcripts/ledgers
    while keeping provider text/result blocks out of summaries and dispatch.
    """

    if not isinstance(message, dict):
        return {}
    content = message.get("content")
    if not isinstance(content, list):
        return message
    shaped: list[Any] = []
    for item in content:
        if isinstance(item, dict):
            block_type = str(item.get("type") or "").strip()
            has_native_alias = any(
                isinstance(item.get(key), dict)
                for key in ("functionCall", "function_call", "toolUse", "tool_use")
            ) or _native_provider_result_alias_value(item) is not None
            if (
                block_type in _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES
                or block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES
                or block_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES
                or has_native_alias
            ):
                item = dict(item, _provider_shape=str(item.get("_provider_shape") or "anthropic.messages.content"))
        shaped.append(item)
    out = dict(message)
    out["content"] = shaped
    return out


def _responses_content_block(block: dict[str, Any], *, provider_shape: str) -> dict[str, Any]:
    out = dict(block)
    block_type = str(out.get("type") or "").strip()
    has_native_call_alias = isinstance(out.get("functionCall") or out.get("function_call"), dict)
    has_native_tool_use_alias = isinstance(out.get("toolUse") or out.get("tool_use"), dict)
    has_native_result_alias = _native_provider_result_alias_value(out) is not None
    if provider_shape and "_provider_shape" not in out and (
        block_type in (
            _NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES
            | _NATIVE_PROVIDER_RESULT_BLOCK_TYPES
            | _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES
        )
        or has_native_call_alias
        or has_native_tool_use_alias
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
        tool_calls.extend(_native_tool_call_batch_items(raw, provider_shape=provider_shape))

    append_raw(item.get("tool_calls"), provider_shape=f"{provider_shape_prefix}.tool_calls")
    append_raw(item.get("toolCalls"), provider_shape=f"{provider_shape_prefix}.toolCalls")
    append_raw(item.get("tool_call"), provider_shape=f"{provider_shape_prefix}.tool_call")
    append_raw(item.get("toolCall"), provider_shape=f"{provider_shape_prefix}.toolCall")

    neutral_tool = item.get("tool")
    if isinstance(neutral_tool, dict):
        tool_calls.append(_native_neutral_tool_call(f"{provider_shape_prefix}.tool", item, neutral_tool))

    function_call = item.get("functionCall")
    if isinstance(function_call, dict):
        tool_calls.append({
            "type": "tool_call",
            "name": _native_tool_name(function_call),
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
    for alias in _NATIVE_TOOL_USE_ALIAS_KEYS:
        raw_tool_uses = item.get(alias)
        if isinstance(raw_tool_uses, (list, dict)):
            tool_calls.extend(_native_tool_use_batch_items(f"{provider_shape_prefix}.{alias}", raw_tool_uses))


def _top_level_content_message(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize top-level content/tool-call payloads into chat message shape.

    Some local shims expose Anthropic-style Messages responses directly instead
    of wrapping them in Chat Completions ``choices`` or Responses ``output``.
    Those payloads commonly put ``content`` blocks (including ``tool_use``) at
    the response root.  Treat them as planner proposals only: this adapter-level
    conversion does not dispatch handlers or queue approvals, and the runtime's
    normal schema, runtime-policy, ROE, and transcript boundaries remain
    authoritative.  Gemini/OpenAI-compatible bridges may also collapse a single
    function proposal into a root ``functionCall`` object, a root ``toolUse``
    object, or plural root ``functionCalls``/``toolUses`` arrays. Normalize
    those into the same provider-native call boundary rather than letting them
    become terminal no-tool responses.
    """

    if not isinstance(raw, dict):
        return {}
    result_echo = _native_provider_result_role_message(raw, provider_shape="root")
    if result_echo:
        return result_echo
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
                "name": _native_tool_name(root_function_call),
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
    root_tool_use_batches: list[tuple[str, Any]] = []
    if isinstance(raw.get("tool_use"), (list, dict)):
        root_tool_use_batches.append(("root.tool_use", raw.get("tool_use")))
    if isinstance(raw.get("toolUse"), (list, dict)):
        root_tool_use_batches.append(("root.toolUse", raw.get("toolUse")))
    if isinstance(raw.get("tool_uses"), (list, dict)):
        root_tool_use_batches.append(("root.tool_uses", raw.get("tool_uses")))
    if isinstance(raw.get("toolUses"), (list, dict)):
        root_tool_use_batches.append(("root.toolUses", raw.get("toolUses")))
    for provider_shape, root_tool_uses in root_tool_use_batches:
        for call in _native_tool_use_batch_items(provider_shape, root_tool_uses):
            _append_message_tool_call(message, call)
    root_tool = raw.get("tool")
    if isinstance(root_tool, dict):
        _append_message_tool_call(message, _native_neutral_tool_call("root.tool", raw, root_tool))
    root_function_response = _native_provider_result_alias_value(raw)
    if isinstance(root_function_response, dict):
        _append_message_content_block(
            message,
            {"type": "tool_result", "content": _native_provider_result_content(root_function_response)},
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

    items = _native_tool_call_batch_items(raw_function_calls, provider_shape=provider_shape)
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
                "name": _native_tool_name(function_call),
                "arguments": _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params")),
                "call_id": str(_native_call_id(item, function_call)),
                "_provider_shape": provider_shape,
            })
            continue
        calls.append({
            "type": "tool_call",
            "name": _native_tool_name(item),
            "arguments": _native_argument_value(item, preferred=("args", "arguments", "parameters", "input", "params")),
            "call_id": str(_native_call_id(item)),
            "_provider_shape": provider_shape,
        })
    return calls


def _native_tool_use_batch_items(provider_shape: str, raw_tool_uses: Any) -> list[dict[str, Any]]:
    """Return tool-call objects for root-level provider ``toolUse`` aliases.

    Anthropic-style responses normally carry ``tool_use`` blocks in ``content``.
    Some OpenAI-compatible shims instead lift those blocks to root fields such
    as ``toolUse`` or ``toolUses``. Normalize only the registered function-call
    shape here; runtime schema validation, ROE previews, approvals, and dry-run
    execution boundaries remain authoritative.
    """

    items = _native_tool_call_batch_items(raw_tool_uses, provider_shape=provider_shape)
    calls: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        call = dict(item)
        call.setdefault("type", "tool_use")
        call["_provider_shape"] = str(call.get("_provider_shape") or provider_shape)
        calls.append(call)
    return calls


def _native_tool_calls_to_plan_content(message: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    role_result_message = _native_provider_result_role_message(message, provider_shape="message")
    if role_result_message:
        message = role_result_message
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
    raw_call_items = _native_tool_call_batch_items(
        raw_calls,
        provider_shape=raw_calls_shape,
    )
    message_function_call = message.get("functionCall")
    if isinstance(message_function_call, dict):
        raw_call_items.append({
            "type": "tool_call",
            "name": _native_tool_name(message_function_call),
            "arguments": _native_argument_value(message_function_call, preferred=("args", "arguments", "parameters", "input", "params")),
            "call_id": str(_native_call_id(message_function_call)),
            "_provider_shape": "message.functionCall",
        })
    if isinstance(message.get("functionCalls"), (list, dict)):
        raw_call_items.extend(_native_function_call_batch_items("message.functionCalls", message.get("functionCalls")))
    if isinstance(message.get("function_calls"), (list, dict)):
        raw_call_items.extend(_native_function_call_batch_items("message.function_calls", message.get("function_calls")))
    for alias in _NATIVE_TOOL_USE_ALIAS_KEYS:
        raw_tool_uses = message.get(alias)
        if isinstance(raw_tool_uses, (list, dict)):
            raw_call_items.extend(_native_tool_use_batch_items(f"message.{alias}", raw_tool_uses))
    message_tool = message.get("tool")
    if isinstance(message_tool, dict):
        raw_call_items.append(_native_neutral_tool_call("message.tool", message, message_tool))
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
        function_response = _native_provider_result_alias_value(item)
        if isinstance(function_response, dict) and (not block_type or block_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES):
            warnings.append("Native provider tool_result/functionResponse content ignored; Phobos only accepts model-requested tool calls at this boundary.")
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
        tool_use_alias_key, tool_use_alias = _native_content_tool_use_alias(item)
        if isinstance(tool_use_alias, dict) and (not block_type or block_type in {"toolUse", "tool_use"}):
            parsed, rejected_item, warning = _parse_native_content_tool_use_alias_block(
                item,
                tool_use_alias,
                alias_key=tool_use_alias_key,
                index=index,
            )
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


def _native_content_tool_use_alias(item: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Return nested content-block ``toolUse``/``tool_use`` wrappers.

    Bedrock/Anthropic-compatible gateways sometimes place the actual tool-use
    payload under a camelCase or snake_case key inside a content block, e.g.
    ``{"toolUse": {"toolUseId": "...", "name": "remember", "input": {}}}``,
    instead of using the Anthropic ``type=tool_use`` flat block.  Normalize that
    at the adapter boundary only; the runtime still owns name/schema validation,
    runtime policy, ROE preview, approval queueing, and execution gating.
    """

    for key in ("toolUse", "tool_use"):
        value = item.get(key)
        if isinstance(value, dict):
            return key, value
    return "", None


def _native_content_label(provider_shape: str, native_kind: str) -> str:
    if provider_shape == "responses.message.content":
        return f"native provider responses message content {native_kind}"
    if provider_shape == "responses.message.content.parts":
        return f"native provider responses message content parts {native_kind}"
    if provider_shape == "responses.output.message_typeless.content":
        return f"native provider typeless responses output message content {native_kind}"
    if provider_shape == "responses.output.message_typeless.content.parts":
        return f"native provider typeless responses output message content parts {native_kind}"
    if provider_shape == "responses.output.message.content":
        return f"native provider responses output message content {native_kind}"
    if provider_shape == "responses.output.message.content.parts":
        return f"native provider responses output message content parts {native_kind}"
    if provider_shape == "root.message.content":
        return f"native provider root message content {native_kind}"
    if provider_shape == "root.message.content.parts":
        return f"native provider root message content parts {native_kind}"
    if provider_shape == "root.messages.content":
        return f"native provider root messages content {native_kind}"
    if provider_shape == "root.messages.content.parts":
        return f"native provider root messages content parts {native_kind}"
    if provider_shape == "root.contents.content":
        return f"native provider root contents content {native_kind}"
    if provider_shape == "root.contents.content.parts":
        return f"native provider root contents content parts {native_kind}"
    if provider_shape == "root.predictions.content":
        return f"native provider root predictions content {native_kind}"
    if provider_shape == "root.predictions.content.parts":
        return f"native provider root predictions content parts {native_kind}"
    if provider_shape == "bedrock.converse.message.content":
        return f"native provider bedrock converse message content {native_kind}"
    if provider_shape == "bedrock.converse.message.content.parts":
        return f"native provider bedrock converse message content parts {native_kind}"
    if provider_shape == "bedrock.converse.stream.content":
        return f"native provider bedrock converse stream content {native_kind}"
    if provider_shape == "bedrock.converse.stream.content.parts":
        return f"native provider bedrock converse stream content parts {native_kind}"
    if provider_shape == "content.parts":
        return f"native provider content parts {native_kind}"
    if provider_shape == "anthropic.messages.content":
        return f"native provider anthropic messages content {native_kind}"
    if provider_shape == "anthropic.messages.stream.content":
        return f"native provider anthropic messages stream content {native_kind}"
    if provider_shape.startswith("choice."):
        return f"native provider {provider_shape.replace('.', ' ')} {native_kind}"
    if provider_shape.startswith("chat.completions.sse."):
        return f"native provider {provider_shape.replace('.', ' ')} {native_kind}"
    return f"native content-block {native_kind}"


def _parse_native_content_tool_block(
    item: dict[str, Any],
    *,
    index: int,
    block_type: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    function = item.get("function")
    call_id = _native_call_id(item, function if isinstance(function, dict) else None)
    provider_shape = str(item.get("_provider_shape") or "")
    label = _native_content_label(provider_shape, block_type)
    if isinstance(function, dict):
        return _parse_native_function_call(
            function,
            index=index,
            legacy=False,
            call_id=call_id,
            label=label,
        )
    nested_tool = item.get("tool")
    if isinstance(nested_tool, dict):
        return _parse_native_function_call(
            {
                "name": _native_tool_name(nested_tool),
                "arguments": _native_argument_value(nested_tool, preferred=("input", "arguments", "args", "parameters", "params")),
            },
            index=index,
            legacy=False,
            call_id=_native_call_id(item, nested_tool),
            label=_native_content_label(provider_shape, "tool"),
        )
    arguments = _native_argument_value(item, preferred=("input", "arguments", "args", "parameters", "params"))
    return _parse_native_function_call(
        {"name": _native_tool_name(item), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=call_id,
        label=label,
    )


def _parse_native_content_tool_use_alias_block(
    item: dict[str, Any],
    tool_use: dict[str, Any],
    *,
    alias_key: str,
    index: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    provider_shape = str(item.get("_provider_shape") or "")
    label = _native_content_label(provider_shape, alias_key or "toolUse")
    arguments = _native_argument_value(tool_use, preferred=("input", "arguments", "args", "parameters", "params"))
    return _parse_native_function_call(
        {"name": _native_tool_name(tool_use), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=_native_call_id(item, tool_use),
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
    elif provider_shape == "responses.output.message_typeless.content":
        label = "native provider typeless responses output message content functionCall"
    elif provider_shape == "responses.output.message_typeless.content.parts":
        label = "native provider typeless responses output message content parts functionCall"
    elif provider_shape == "responses.output.message.content":
        label = "native provider responses output message content functionCall"
    elif provider_shape == "responses.output.message.content.parts":
        label = "native provider responses output message content parts functionCall"
    elif provider_shape == "root.message.content":
        label = "native provider root message content functionCall"
    elif provider_shape == "root.message.content.parts":
        label = "native provider root message content parts functionCall"
    elif provider_shape == "root.messages.content":
        label = "native provider root messages content functionCall"
    elif provider_shape == "root.messages.content.parts":
        label = "native provider root messages content parts functionCall"
    elif provider_shape == "root.contents.content":
        label = "native provider root contents content functionCall"
    elif provider_shape == "root.contents.content.parts":
        label = "native provider root contents content parts functionCall"
    elif provider_shape == "root.predictions.content":
        label = "native provider root predictions content functionCall"
    elif provider_shape == "root.predictions.content.parts":
        label = "native provider root predictions content parts functionCall"
    elif provider_shape == "bedrock.converse.message.content":
        label = "native provider bedrock converse message content functionCall"
    elif provider_shape == "bedrock.converse.message.content.parts":
        label = "native provider bedrock converse message content parts functionCall"
    elif provider_shape == "bedrock.converse.stream.content":
        label = "native provider bedrock converse stream content functionCall"
    elif provider_shape == "bedrock.converse.stream.content.parts":
        label = "native provider bedrock converse stream content parts functionCall"
    elif provider_shape == "content.parts":
        label = "native provider content parts functionCall"
    elif provider_shape == "anthropic.messages.content":
        label = "native provider anthropic messages content functionCall"
    elif provider_shape.startswith("choice."):
        label = f"native provider {provider_shape.replace('.', ' ')} functionCall"
    elif provider_shape.startswith("chat.completions.sse."):
        label = f"native provider {provider_shape.replace('.', ' ')} functionCall"
    else:
        label = "native content-block functionCall"
    arguments = _native_argument_value(function_call, preferred=("args", "arguments", "parameters", "input", "params"))
    return _parse_native_function_call(
        {"name": _native_tool_name(function_call), "arguments": arguments},
        index=index,
        legacy=False,
        call_id=_native_call_id(item, function_call),
        label=label,
    )


def _parse_native_tool_call(item: Any, *, index: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    if not isinstance(item, dict):
        return None, {"tool": None, "reason": "Native tool call must be an object.", "args": {"value_type": type(item).__name__}}, "Native tool call was not an object; skipped."
    native_type = item.get("type")
    if native_type in _NATIVE_PROVIDER_RESULT_BLOCK_TYPES or _native_provider_result_alias_value(item) is not None:
        return None, None, "Native provider tool_result entry ignored; Phobos only accepts model-requested tool calls at this boundary."
    if native_type in _NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES:
        return _reject_unsupported_native_tool_call(item, index=index, native_type=str(native_type))
    if native_type not in {None, "function", "tool_call", "tool_use", "toolUse", "function_call", "functionCall"}:
        return None, {"tool": None, "reason": "Only function tool calls are supported.", "args": {"native_type": str(native_type)}}, "Native non-function tool call skipped."
    provider_shape = str(item.get("_provider_shape") or "")
    if isinstance(item.get("functionCall"), dict):
        nested_function_call = item.get("functionCall")
        alias_key = "functionCall"
    elif isinstance(item.get("function_call"), dict):
        nested_function_call = item.get("function_call")
        alias_key = "function_call"
    else:
        nested_function_call = None
        alias_key = ""
    if isinstance(nested_function_call, dict):
        return _parse_native_function_call(
            {
                "name": _native_tool_name(nested_function_call),
                "arguments": _native_argument_value(nested_function_call, preferred=("args", "arguments", "parameters", "input", "params")),
            },
            index=index,
            legacy=False,
            call_id=_native_call_id(item, nested_function_call),
            label=_native_nested_tool_call_alias_label(provider_shape, alias_key),
        )
    nested_tool_use_key, nested_tool_use = _native_content_tool_use_alias(item)
    if isinstance(nested_tool_use, dict):
        return _parse_native_function_call(
            {
                "name": _native_tool_name(nested_tool_use),
                "arguments": _native_argument_value(nested_tool_use, preferred=("input", "arguments", "args", "parameters", "params")),
            },
            index=index,
            legacy=False,
            call_id=_native_call_id(item, nested_tool_use),
            label=_native_nested_tool_call_alias_label(provider_shape, nested_tool_use_key or "toolUse"),
        )
    nested_tool = item.get("tool")
    if isinstance(nested_tool, dict):
        return _parse_native_function_call(
            {
                "name": _native_tool_name(nested_tool),
                "arguments": _native_argument_value(nested_tool, preferred=("input", "arguments", "args", "parameters", "params")),
            },
            index=index,
            legacy=False,
            call_id=_native_call_id(item, nested_tool),
            label=_native_nested_tool_call_alias_label(provider_shape, "tool"),
        )
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
        elif provider_shape == "responses.output.message_typeless.tool_calls":
            label = "native provider typeless responses output message tool_calls"
        elif provider_shape == "responses.output.message_typeless.tool_call":
            label = "native provider typeless responses output message tool_call"
        elif provider_shape == "responses.output.message_typeless.toolCalls":
            label = "native provider typeless responses output message toolCalls"
        elif provider_shape == "responses.output.message_typeless.toolCall":
            label = "native provider typeless responses output message toolCall"
        elif provider_shape == "responses.output.message_typeless.function_call":
            label = "native provider typeless responses output message function_call"
        elif provider_shape == "responses.output.message_typeless.functionCall":
            label = "native provider typeless responses output message functionCall"
        elif provider_shape == "responses.output.message_typeless.functionCalls":
            label = "native provider typeless responses output message functionCalls"
        elif provider_shape == "responses.output.message_typeless.function_calls":
            label = "native provider typeless responses output message function_calls"
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
        elif provider_shape in {"root.tool_use", "root.toolUse", "root.tool_uses", "root.toolUses", "message.tool_use", "message.toolUse", "message.tool_uses", "message.toolUses"}:
            label = "native provider " + provider_shape.replace(".", " ")
        elif provider_shape.startswith("responses.message.") and provider_shape.rsplit(".", 1)[-1] in _NATIVE_TOOL_USE_ALIAS_KEYS:
            label = "native provider responses message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("responses.output.message_typeless.") and provider_shape.rsplit(".", 1)[-1] in _NATIVE_TOOL_USE_ALIAS_KEYS:
            label = "native provider typeless responses output message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("responses.output.message.") and provider_shape.rsplit(".", 1)[-1] in _NATIVE_TOOL_USE_ALIAS_KEYS:
            label = "native provider responses output message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.message."):
            label = "native provider root message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.messages."):
            label = "native provider root messages " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith(("root.predictions.", "root.prediction.")):
            wrapper_label = provider_shape.split(".", 2)[1]
            label = "native provider root " + wrapper_label + " " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.outputs."):
            label = "native provider root outputs " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith(("root.output_items.", "root.outputItems.", "root.output_item.", "root.outputItem.", "root.items.", "root.item.")):
            wrapper_label = provider_shape.split(".", 2)[1]
            label = "native provider root " + wrapper_label + " " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("bedrock.converse.message."):
            label = "native provider bedrock converse message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.endswith(".object_map") or provider_shape == "tool_calls.object_map":
            label = "native provider " + provider_shape.replace("_", " ").replace(".", " ")
        elif provider_shape.startswith("choice."):
            label = "native provider " + provider_shape.replace(".", " ")
        elif provider_shape.startswith("chat.completions.sse."):
            label = "native provider " + provider_shape.replace(".", " ")
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
    name = _native_tool_name(item)
    if isinstance(function, str) and not name:
        name = function
    if name:
        arguments = _native_argument_value(item, preferred=("arguments", "args", "input", "parameters", "params"))
        if item.get("_provider_shape") == "responses.output":
            label = "native provider responses output function_call"
        elif item.get("_provider_shape") == "responses.stream.output":
            label = "native provider responses stream function_call"
        elif item.get("_provider_shape") == "single_responses.output":
            label = "native provider single responses output function_call"
        elif item.get("_provider_shape") == "responses.output.functionCall":
            label = "native provider responses output nested functionCall"
        elif item.get("_provider_shape") == "single_responses.output.functionCall":
            label = "native provider single responses output nested functionCall"
        elif item.get("_provider_shape") == "gemini.candidate":
            label = "native provider candidate functionCall"
        elif item.get("_provider_shape") == "gemini.stream.candidate":
            label = "native provider Gemini stream candidate functionCall"
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
        elif item.get("_provider_shape") == "responses.output.message_typeless.tool_calls":
            label = "native provider typeless responses output message tool_calls"
        elif item.get("_provider_shape") == "responses.output.message_typeless.tool_call":
            label = "native provider typeless responses output message tool_call"
        elif item.get("_provider_shape") == "responses.output.message_typeless.toolCalls":
            label = "native provider typeless responses output message toolCalls"
        elif item.get("_provider_shape") == "responses.output.message_typeless.toolCall":
            label = "native provider typeless responses output message toolCall"
        elif item.get("_provider_shape") == "responses.output.message_typeless.function_call":
            label = "native provider typeless responses output message function_call"
        elif item.get("_provider_shape") == "responses.output.message_typeless.functionCall":
            label = "native provider typeless responses output message functionCall"
        elif item.get("_provider_shape") == "responses.output.message_typeless.functionCalls":
            label = "native provider typeless responses output message functionCalls"
        elif item.get("_provider_shape") == "responses.output.message_typeless.function_calls":
            label = "native provider typeless responses output message function_calls"
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
        elif provider_shape in {"root.tool", "message.tool"}:
            label = "native provider " + provider_shape.replace(".", " ")
        elif provider_shape in {"root.tool_use", "root.toolUse", "root.tool_uses", "root.toolUses", "message.tool_use", "message.toolUse", "message.tool_uses", "message.toolUses"}:
            label = "native provider " + provider_shape.replace(".", " ")
        elif provider_shape.startswith("responses.message.") and provider_shape.rsplit(".", 1)[-1] in (*_NATIVE_TOOL_USE_ALIAS_KEYS, "tool"):
            label = "native provider responses message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("responses.output.message_typeless.") and provider_shape.rsplit(".", 1)[-1] in (*_NATIVE_TOOL_USE_ALIAS_KEYS, "tool"):
            label = "native provider typeless responses output message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("responses.output.message.") and provider_shape.rsplit(".", 1)[-1] in (*_NATIVE_TOOL_USE_ALIAS_KEYS, "tool"):
            label = "native provider responses output message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.message."):
            label = "native provider root message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.messages."):
            label = "native provider root messages " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith(("root.predictions.", "root.prediction.")):
            wrapper_label = provider_shape.split(".", 2)[1]
            label = "native provider root " + wrapper_label + " " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("root.outputs."):
            label = "native provider root outputs " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith(("root.output_items.", "root.outputItems.", "root.output_item.", "root.outputItem.", "root.items.", "root.item.")):
            wrapper_label = provider_shape.split(".", 2)[1]
            label = "native provider root " + wrapper_label + " " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape.startswith("bedrock.converse.message."):
            label = "native provider bedrock converse message " + provider_shape.rsplit(".", 1)[-1]
        elif provider_shape == "single_top_level.tool_calls":
            label = "native provider single top-level tool_call"
        elif provider_shape == "singular.tool_call":
            label = "native provider singular tool_call"
        elif provider_shape in {"camelCase.toolCalls", "singular.toolCall"}:
            label = "native provider camelCase toolCall"
        elif provider_shape.endswith(".object_map") or provider_shape == "tool_calls.object_map":
            label = "native provider " + provider_shape.replace("_", " ").replace(".", " ")
        elif provider_shape.startswith("choice."):
            label = "native provider " + provider_shape.replace(".", " ")
        elif provider_shape.startswith("chat.completions.sse."):
            label = "native provider " + provider_shape.replace(".", " ")
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


def _native_nested_tool_call_alias_label(provider_shape: str, alias_key: str) -> str:
    """Return transcript labels for nested functionCall/toolUse wrappers.

    Most Chat-Completions compatible providers put ``function`` directly under
    ``tool_calls[]``.  Some Gemini/Bedrock/OpenAI shims instead keep the native
    object nested under ``functionCall`` or ``toolUse`` inside each tool-call
    entry.  Preserve that provenance while keeping execution behind Phobos'
    normal schema, runtime-policy, ROE, approval, and transcript boundaries.
    """

    alias = alias_key or "functionCall"
    if provider_shape:
        return "native provider " + provider_shape.replace(".", " ") + f" nested {alias}"
    return f"native provider tool_call nested {alias}"


def _native_call_id(*items: Any) -> str:
    """Return a provider call identifier from common native-tool-call aliases.

    Provider bridges disagree on where they place the opaque correlation id:
    OpenAI-style content blocks usually use ``id``, Responses-style blocks often
    use ``call_id``, some shims use ``tool_call_id``/``function_call_id``, and
    Anthropic-compatible bridges may use ``tool_use_id``.  Preserve the bounded
    id as provenance only; runtime schema/ROE checks still decide whether any
    call can be applied.
    """

    for item in items:
        if not isinstance(item, dict):
            continue
        for key in ("id", "call_id", "tool_call_id", "tool_use_id", "function_call_id", "callId", "toolCallId", "toolUseId", "functionCallId"):
            value = item.get(key)
            if value not in (None, ""):
                return _sanitize_native_call_id(value)
    return ""


def _sanitize_native_call_id(value: Any, *, limit: int = 200) -> str:
    """Return a transcript-safe provider tool-call correlation id.

    Provider call ids are useful provenance, but they are still model/provider
    controlled strings.  Keep them single-line, redacted, and bounded before they
    reach reasons, metadata, ledgers, or transcript Markdown.
    """

    text = redact_secrets(str(value)) or ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()
    if len(text) > limit:
        suffix = "...[truncated]"
        text = text[: max(0, limit - len(suffix))] + suffix
    return text


_NATIVE_PROVIDER_TOOL_CALL_BLOCK_TYPES = {"tool_use", "toolUse", "tool_call", "function_call", "functionCall"}
_NATIVE_PROVIDER_RESULT_BLOCK_TYPES = {
    "tool_result",
    "toolResult",
    "function_result",
    "functionResult",
    "function_call_output",
    "functionCallOutput",
    "functionResponse",
    "function_response",
    "tool_call_result",
    "toolCallResult",
}
_NATIVE_PROVIDER_RESULT_MESSAGE_ROLES = {"tool", "function", "tool_result", "function_result"}
_NATIVE_PROVIDER_RESULT_ALIAS_KEYS = (
    "toolResult",
    "tool_result",
    "functionResult",
    "function_result",
    "functionCallOutput",
    "function_call_output",
    "functionResponse",
    "function_response",
    "toolCallResult",
    "tool_call_result",
)
_NATIVE_PROVIDER_UNSUPPORTED_TOOL_CALL_BLOCK_TYPES = {
    "custom_tool_call",
    "computer_call",
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "local_shell_call",
    "server_tool_use",
    "mcp_tool_use",
    "mcp_call",
    "mcp_list_tools",
    "mcp_approval_request",
}


def _native_provider_result_alias_value(mapping: dict[str, Any]) -> dict[str, Any] | None:
    """Return a provider result-echo alias payload without surfacing content.

    Provider bridges are inconsistent about result blocks: some use typed
    ``tool_result`` / ``function_call_output`` entries while others put
    camelCase aliases such as ``toolResult`` or ``functionCallOutput`` on a
    typeless content block.  Treat every form as prior-tool output that must be
    ignored at the planning boundary, not as assistant text or a fresh tool call.
    """

    if not isinstance(mapping, dict):
        return None
    for key in _NATIVE_PROVIDER_RESULT_ALIAS_KEYS:
        value = mapping.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return {"content": value}
    return None


def _native_provider_result_content(mapping: dict[str, Any]) -> str:
    """Extract bounded result echo text for internal ignored blocks only."""

    if not isinstance(mapping, dict):
        return ""
    alias_value = _native_provider_result_alias_value(mapping)
    source = alias_value if isinstance(alias_value, dict) else mapping
    for key in ("output", "content", "response", "result", "text"):
        value = source.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(value)
    return ""


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

    raw_tool_name = str(_native_tool_name(item) or "").strip()
    tool_name = redact_secrets(raw_tool_name[:200]) or None
    call_id = _native_call_id(item).strip()
    args: dict[str, Any] = {"native_type": str(native_type or "custom_tool_call"), "native_tool_call_index": index}
    if call_id:
        args["provider_tool_call_id"] = redact_secrets(call_id[:200]) or ""
    reason = "Custom/freeform native tool calls are not supported; provider-hosted tools must be exposed as registered JSON-schema function calls."
    warning = "Native custom/freeform/hosted tool call skipped; Phobos only accepts registered JSON-schema function calls."
    return None, {"tool": tool_name, "reason": reason, "args": args}, warning


def _parse_native_function_call(
    function: dict[str, Any],
    *,
    index: int,
    legacy: bool,
    call_id: str = "",
    label: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    name = str(_native_tool_name(function) or "").strip()
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


def _responses_tool_from_spec(spec: dict[str, Any]) -> dict[str, Any] | None:
    """Return a Responses API function-tool schema from a registry spec."""

    base = _openai_tool_from_spec(spec)
    if not isinstance(base, dict):
        return None
    raw_function = base.get("function")
    if not isinstance(raw_function, dict):
        return None
    name = str(raw_function.get("name") or "").strip()
    if not name:
        return None
    parameters = raw_function.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {"type": "object", "properties": {}}
    return {
        "type": "function",
        "name": name,
        "description": str(raw_function.get("description") or name),
        "parameters": parameters,
    }


def _gemini_function_declaration_from_spec(spec: dict[str, Any]) -> dict[str, Any] | None:
    """Return a Gemini functionDeclaration from a registry spec."""

    base = _responses_tool_from_spec(spec)
    if not isinstance(base, dict):
        return None
    name = str(base.get("name") or "").strip()
    if not name:
        return None
    parameters = base.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {"type": "object", "properties": {}}
    return {
        "name": name,
        "description": _truncate(str(base.get("description") or name), 1024),
        "parameters": parameters,
    }


def _anthropic_tool_from_spec(spec: dict[str, Any]) -> dict[str, Any] | None:
    """Return an Anthropic Messages tool spec from a registry schema."""

    base = _responses_tool_from_spec(spec)
    if not isinstance(base, dict):
        return None
    name = str(base.get("name") or "").strip()
    if not name:
        return None
    input_schema = base.get("parameters")
    if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
        input_schema = {"type": "object", "properties": {}}
    input_schema.setdefault("properties", {})
    return {
        "name": name,
        "description": _truncate(str(base.get("description") or name), 1024),
        "input_schema": input_schema,
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
