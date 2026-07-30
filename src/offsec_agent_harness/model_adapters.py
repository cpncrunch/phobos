from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import os
import shlex
import subprocess
import tempfile
import urllib.error
import urllib.request


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
        api_key = os.environ.get(self.key_env, "")
        if not api_key and not _is_local_base_url(self.base_url):
            raise RuntimeError(f"Missing API key environment variable {self.key_env}")
        messages = [
            {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
            {"role": "user", "content": (context + "\n\n" if context else "") + prompt},
        ]
        payload = {"model": self.model, "messages": messages, "temperature": 0.2}
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(self.base_url + "/chat/completions", data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Model endpoint HTTP {exc.code}: {body[:500]}") from exc
        content = raw.get("choices", [{}])[0].get("message", {}).get("content", "")
        return ModelResponse(provider=self.provider, role=role, content=content, raw={"model": self.model, "base_url": self.base_url})


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
                attempts.append({"provider": getattr(adapter, "provider", adapter.__class__.__name__), "error": str(exc)[:500]})
        raise RuntimeError("All model providers failed: " + json.dumps(attempts))


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
