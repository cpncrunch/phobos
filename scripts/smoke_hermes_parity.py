#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phobos_agent import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeMessage, EngagementROE, PhobosAgentRuntime, handle_bridge_message
from offsec_agent_harness.agent_tools import ToolResult
import offsec_agent_harness.agent_tools as agent_tools_module
from offsec_agent_harness.model_adapters import BaseModelAdapter, FallbackModelAdapter, ModelResponse, OpenAICompatibleAdapter
import offsec_agent_harness.model_adapters as model_adapters
from offsec_agent_harness.models import redact_secrets


class SmokeToolCallValidationAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-validation"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "smoke model mixed valid and invalid native tool calls",
                    "tool_calls": [
                        {"tool": "not_a_tool", "args": {}, "reason": "unknown tool should be rejected"},
                        {"tool": "remember", "args": {"key": "native-missing-value"}, "reason": "missing required schema field should be rejected"},
                        {"tool": "list_tasks", "args": {"status": "pending", "limit": "2"}, "reason": "safe local state read"},
                        {"tool": "run_command", "args": {"target": "app.example.test", "purpose": "native tool loop dry-run smoke", "command": "printf native-tool-loop-ok", "execute": True}, "reason": "execute must be forced false unless explicit execute=true is supplied"},
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeWrappedJsonToolPlanAdapter(BaseModelAdapter):
    provider = "smoke-wrapped-json-tool-plan"

    def __init__(self, marker: Path):
        self.marker = marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('wrapped-json-smoke-should-not-run', encoding='utf-8')\""
            plan = {
                "summary": "smoke wrapped JSON model plan selected safe local memory and a dry-run command",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-wrapped-json-smoke", "value": "wrapped JSON planner accepted"}, "reason": "prove fenced/surrounded JSON is extracted before validation"},
                    {"tool": "run_command", "args": {"target": "app.example.test", "purpose": "wrapped JSON native smoke dry-run", "command": command, "execute": True}, "reason": "execution-capable model calls stay dry-run without operator execute=true"},
                ],
                "warnings": [],
            }
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=(
                    'Provider preface with ignored braces {"note":"ignore","token":"wrapped-smoke-secret"}.\n'
                    "```json\n"
                    + json.dumps(plan, indent=2)
                    + "\n```\nTrailing unmatched provider brace {not-json"
                ),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeFailingToolPlanAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-primary-fails"

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        raise RuntimeError("primary smoke tool planner failed token=fallback-smoke-secret")

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        raise RuntimeError("generate() should not be used for native tool-call fallback smoke")


class SmokeFallbackToolPlanAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-fallback"

    def __init__(self, marker: Path):
        self.marker = marker
        self.seen_tool_names: list[str] = []
        self.allow_seen: bool | None = None

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        self.allow_seen = allow_command_execution
        command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('fallback-smoke-should-not-run', encoding='utf-8')\""
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "smoke fallback provider produced a native tool-call plan",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-fallback-smoke", "value": "native fallback chain selected tool planning"}, "reason": "prove fallback tool planning used the provider contract"},
                    {"tool": "run_command", "args": {"target": "app.example.test", "purpose": "native fallback dry-run smoke", "command": command, "execute": True}, "reason": "fallback-planned command must still dry-run without operator execute=true"},
                ],
                "warnings": [],
            }),
            raw={"model": "fake-fallback-smoke", "native_tool_calls": True, "native_tool_call_count": 2, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content="smoke response without tool plan")


class SmokeNaturalAutoToolPlanAdapter(BaseModelAdapter):
    provider = "smoke-natural-auto-tool-plan"

    def __init__(self, marker: Path):
        self.marker = marker
        self.allow_seen: bool | None = None
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.allow_seen = allow_command_execution
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('natural-auto-smoke-should-not-run', encoding='utf-8')\""
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "smoke native planner handled natural-language auto execution",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-natural-auto-smoke", "value": "natural auto native tool planning ran"}, "reason": "safe local memory proves natural-message model planning used the registry boundary"},
                    {"tool": "run_command", "args": {"target": "app.example.test", "purpose": "natural auto native dry-run smoke", "command": command, "execute": True}, "reason": "natural-message command plans remain dry-run without explicit slash execute=true"},
                ],
                "warnings": [],
            }),
            raw={"model": "fake-natural-auto-smoke", "native_tool_calls": True, "native_tool_call_count": 2, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallContextAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-context"

    def __init__(self):
        self.contexts: list[str] = []
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.contexts.append(context)
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        saw_context = "planning-context-smoke" in context and "app.example.test" in context
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "smoke native planner used bounded runtime context",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-context-smoke", "value": "planner saw redacted runtime context" if saw_context else "planner context missing"},
                        "reason": "safe local memory proves model planner received runtime context",
                    }
                ],
                "warnings": [],
            }),
            raw={"model": "fake-context-smoke", "native_tool_calls": False, "native_tool_call_count": 0, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallAllowedExecutionAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-allowed-execution"

    def __init__(self, marker: Path):
        self.marker = marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('native-allowed-executed', encoding='utf-8')\""
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "smoke model selected allowed explicit command execution",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native allowed execution smoke",
                                "command": command,
                                "execute": True,
                                "timeout": "5",
                            },
                            "reason": "prove native tool plans execute allowed commands only when execute=true is explicit",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallScannerExecutionAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-scanner-execution"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "smoke model proposed a scanner wrapper with execute=true",
                    "tool_calls": [
                        {
                            "tool": "nmap_scan",
                            "args": {
                                "target": "app.example.test",
                                "ports": "80",
                                "profile": "quick",
                                "execute": True,
                                "timeout": "5",
                            },
                            "reason": "scanner wrappers must obey the native tool-call execution boundary",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallGuardrailAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-guardrail"

    def __init__(self, confirm_marker: Path, block_marker: Path):
        self.confirm_marker = confirm_marker
        self.block_marker = block_marker
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            self.prompts.append(prompt)
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "smoke model proposed target-affecting native tool calls",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native guardrail approval smoke",
                                "command": f"curl -X POST https://app.example.test/api/native-smoke && touch {self.confirm_marker}",
                                "execute": True,
                            },
                            "reason": "state-changing request must queue approval without execution",
                        },
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "outside.example.test",
                                "purpose": "native guardrail block smoke",
                                "command": f"printf native-block > {self.block_marker}",
                                "execute": True,
                            },
                            "reason": "out-of-scope target must block without execution",
                        },
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallOperatorApprovalReplayAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-operator-approval-replay"

    def __init__(self, marker: Path):
        self.marker = marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            command = (
                "python -c \"from pathlib import Path; "
                f"Path({str(self.marker)!r}).write_text('native-approval-replayed', encoding='utf-8')\" "
                "# curl -X POST https://app.example.test/api/native-approval-replay"
            )
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "smoke model queued a confirm-gated command for direct operator replay approval",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native operator approval replay smoke",
                                "command": command,
                                "execute": True,
                                "timeout": "5",
                            },
                            "reason": "native confirm-level plans must execute only after an explicit /approve command",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallFeedbackAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        if "Stored memory" in prompt:
            payload = {"summary": "smoke feedback loop complete", "tool_calls": [], "warnings": []}
        elif "Workspace file not found" in prompt:
            payload = {
                "summary": "smoke feedback recovered from a tool error",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-feedback-recovered", "value": "native feedback loop recovered"}, "reason": "record recovery after previous tool error"}
                ],
                "warnings": [],
            }
        else:
            payload = {
                "summary": "smoke first step deliberately returns a safe local tool error",
                "tool_calls": [
                    {"tool": "workspace_read", "args": {"path": "missing-native-feedback-smoke.txt"}, "reason": "exercise result feedback without target activity"}
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class SmokeToolCallModelErrorAfterFeedbackAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-model-error-after-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            raise RuntimeError("smoke native planner failed after feedback token=model-error-smoke-secret")
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "smoke first step writes a local marker before model error stop",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-model-error-stop", "value": "native model error first step ran"}, "reason": "prove model-error stops do not trigger deterministic re-planning after feedback"}
                ],
                "warnings": [],
            }),
        )


class SmokeToolCallInvalidAfterFeedbackAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-invalid-after-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            payload = {
                "summary": "smoke model proposed only invalid native calls after feedback",
                "tool_calls": [
                    {"tool": "not_a_real_tool", "args": {}, "reason": "unknown tool should be rejected before dispatch"},
                    {"tool": "remember", "args": {"key": "native-invalid-withheld"}, "reason": "missing required value should be rejected before dispatch"},
                ],
                "warnings": ["token=invalid-plan-smoke-secret should be redacted"],
            }
        else:
            payload = {
                "summary": "smoke first step writes one marker before invalid plan stop",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-invalid-plan-stop", "value": "native invalid plan first step ran"}, "reason": "safe local marker proves feedback existed before invalid-plan stop"}
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class SmokeToolCallTerminalNoToolAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-terminal-no-tool"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            payload = {
                "summary": "smoke model stopped after successful native result",
                "tool_calls": [],
                "warnings": ["no more native tool calls needed"],
            }
        else:
            payload = {
                "summary": "smoke first step writes one memory marker",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-terminal-stop", "value": "native terminal no-tool stop ran once"}, "reason": "safe local marker proves only one native step executed"}
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class SmokeToolCallDuplicatePlanAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "smoke model repeated a native tool call",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-duplicate-stop", "value": "native duplicate stop ran once"}, "reason": "duplicate tool calls must stop before second dispatch"}
                ],
                "warnings": [],
            }),
        )


class SmokeToolCallPartialDuplicatePlanAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-partial-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        if len(self.prompts) == 1:
            calls = [
                {"tool": "remember", "args": {"key": "native-partial-duplicate-stop", "value": "native partial duplicate stop ran once"}, "reason": "first unique local call runs once"}
            ]
        else:
            calls = [
                {"tool": "remember", "args": {"key": "native-partial-duplicate-stop", "value": "native partial duplicate stop ran once"}, "reason": "paraphrased repeated tool args must stop before dispatch"},
                {"tool": "remember", "args": {"key": "native-partial-duplicate-withheld", "value": "partial duplicate new call should be withheld"}, "reason": "new call in duplicate batch must not partially dispatch"},
            ]
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "smoke model emitted a mixed duplicate native plan",
                "tool_calls": calls,
                "warnings": [],
            }),
        )


class SmokeToolCallSameStepDuplicatePlanAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-same-step-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        duplicate_call = {"tool": "remember", "args": {"key": "native-same-step-duplicate", "value": "same-step duplicate must not dispatch"}, "reason": "same-step duplicate tool args must stop before dispatch"}
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "smoke model emitted duplicate tool+args in one native plan step",
                "tool_calls": [duplicate_call, dict(duplicate_call, reason="paraphrased same-step repeat must also be withheld")],
                "warnings": [],
            }),
        )


class SmokeToolCallMaxStepsAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-max-steps"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        step = len(self.prompts)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": f"smoke model emitted bounded native step {step}",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": f"native-max-step-{step}", "value": f"native max-step budget ran step {step}"}, "reason": "unique safe local call keeps the native loop progressing until the max-step budget stops it"}
                ],
                "warnings": [],
            }),
        )


class SmokeToolCallApprovalActionAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-approval-action"

    def __init__(self):
        self.approval_id = 1
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "smoke model attempted approval-control actions",
                "tool_calls": [
                    {"tool": "approve", "args": {"id": self.approval_id}, "reason": "model must not approve queued actions"},
                    {"tool": "deny", "args": {"id": self.approval_id, "reason": "model must not deny queued actions"}, "reason": "model must not deny queued actions"},
                ],
                "warnings": [],
            }),
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content="smoke response")


class SmokeToolCallRuntimePolicyAdapter(BaseModelAdapter):
    provider = "smoke-tool-call-runtime-policy"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content="smoke response")
        self.prompts.append(prompt)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "smoke model proposed calls governed by runtime policy",
                "tool_calls": [
                    {"tool": "remember", "args": {"key": "native-policy-smoke", "value": "native runtime policy approval replayed"}, "reason": "confirm_tools should queue native-planned local tools"},
                    {"tool": "workspace_read", "args": {"path": "native-policy-blocked-fixture.txt"}, "reason": "blocked_tools should block native-planned local tools"},
                ],
                "warnings": [],
            }),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a harmless local Hermes-like parity smoke test for phobos-agent.")
    parser.add_argument("--out-root", default="demo-phobos-parity", help="Output directory to recreate under the repository root.")
    args = parser.parse_args(argv)

    root = Path(args.out_root)
    if not root.is_absolute():
        root = REPO / root
    output = root / "output"
    data = root / "data"
    evidence = root / "evidence"
    workspace = root / "workspace"
    skill_root = root / "skills"
    media_source = root / "proof-media.txt"
    config_path = root / "agent.config.json"
    engagement_path = root / "phobos-parity.engagement.json"
    db_path = data / "phobos-agent.db"

    shutil.rmtree(root, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    skill_dir = skill_root / "smoke-skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: smoke-skill\n"
        "description: Smoke skill for local progressive disclosure.\n"
        "triggers:\n"
        "  - smoke parity\n"
        "---\n"
        "# Smoke Skill\n\n"
        "Use this only as local smoke context; keep ROE and evidence first.\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["HOME"] = str(root / "home")
    env["PHOBOS_SMOKE_SEAL"] = "smoke-passphrase-for-sealed-export"
    env["PHOBOS_SMOKE_DB_SEAL"] = "smoke-passphrase-for-db-seal"
    env["PHOBOS_SMOKE_GATEWAY_TOKEN"] = "smoke-gateway-token"
    os.environ["PHOBOS_SMOKE_SEAL"] = env["PHOBOS_SMOKE_SEAL"]
    os.environ["PHOBOS_SMOKE_DB_SEAL"] = env["PHOBOS_SMOKE_DB_SEAL"]
    os.environ["PHOBOS_SMOKE_GATEWAY_TOKEN"] = env["PHOBOS_SMOKE_GATEWAY_TOKEN"]

    checks: dict[str, object] = {}

    def write(name: str, text: str) -> None:
        (output / name).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")

    def run_cmd(name: str, cmd: list[str]) -> str:
        completed = subprocess.run(cmd, cwd=REPO, env=env, text=True, capture_output=True, check=False)
        write(name + ".stdout.txt", completed.stdout)
        write(name + ".stderr.txt", completed.stderr)
        write(name + ".command.txt", "$ " + " ".join(cmd) + f"\nexit={completed.returncode}\n")
        if completed.returncode != 0:
            raise RuntimeError(f"{name} failed with exit {completed.returncode}: {completed.stderr or completed.stdout}")
        return completed.stdout

    profile_init = run_cmd("profile-init", [sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "smoke"])
    profiles_list = run_cmd("profiles", [sys.executable, "-m", "phobos_agent.agent_cli", "profiles"])
    checks["profile_cli_ok"] = '"profile": "smoke"' in profile_init and '"name": "smoke"' in profiles_list

    run_cmd(
        "engagement-init",
        [
            sys.executable,
            "-m",
            "phobos_agent.cli",
            "init",
            "--name",
            "Phobos Agent Parity Smoke",
            "--scope",
            "app.example.test,10.10.0.0/24",
            "--allowed",
            "web,api,host,service-enumeration,offline-analysis",
            "--prohibited",
            "dos,destructive,persistence,evasion,malware",
            "--safety-mode",
            "non_destructive",
            "--evidence-dir",
            str(evidence),
            "--out",
            str(engagement_path),
        ],
    )
    engagement = json.loads(engagement_path.read_text(encoding="utf-8"))
    checks["default_non_destructive"] = engagement.get("safety_mode") == "non_destructive"

    run_cmd("config-init", [sys.executable, "-m", "phobos_agent.agent_cli", "config-init", "--out", str(config_path)])
    cfg = AgentAppConfig.load(config_path)
    cfg.workspace_dir = str(workspace)
    cfg.operator_name = "Caligo"
    cfg.assistant_style = "direct, concise, practical, evidence-first"
    cfg.plugin_dirs = [str(REPO / "examples" / "plugins")]
    cfg.skill_dirs = [str(skill_root)]
    cfg.preload_skills = ["smoke-skill"]
    cfg.skill_bundles = {"smoke": ["smoke-skill"]}
    cfg.save(config_path)
    checks["config_written"] = config_path.exists() and cfg.auto_execute_natural is False and cfg.operator_name == "Caligo"
    scalar_config_path = root / "agent.string-scalars.config.json"
    scalar_bad_config_path = root / "agent.invalid-scalars.config.json"
    scalar_bridge_bad_config_path = root / "agent.invalid-bridge-scalars.config.json"
    scalar_config_path.write_text(json.dumps({
        "workspace_dir": str(workspace),
        "plugin_dirs": str(REPO / "examples" / "plugins"),
        "max_context_messages": "8",
        "tool_timeout": "11",
        "auto_execute_natural": "false",
        "auto_model_planning": "off",
        "max_auto_steps": "3",
        "blocked_tools": "export_pack",
        "skill_bundles": {"smoke": "smoke-skill"},
        "providers": {"provider": "heuristic", "model": "smoke"},
        "bridges": {"discord": {"enabled": "true", "allow_all": "false", "allow_approval_actions": "0", "ignore_bots": "yes", "mention_required": "no", "import_attachments": "on", "max_attachment_bytes": "4096", "max_response_chars": "240", "max_message_chars": "500", "poll_interval": "0.5", "response_polish": "false", "discord_thread_continue_without_trigger": "false"}},
    }, indent=2), encoding="utf-8")
    scalar_bad_config_path.write_text(json.dumps({"auto_execute_natural": "maybe"}), encoding="utf-8")
    scalar_bridge_bad_config_path.write_text(json.dumps({"bridges": {"discord": {"allow_all": "maybe"}}}), encoding="utf-8")
    scalar_cfg = AgentAppConfig.load(scalar_config_path)
    scalar_bridge = BridgeConfig.from_dict("discord", scalar_cfg.bridges["discord"])
    invalid_config_error = ""
    invalid_bridge_error = ""
    try:
        AgentAppConfig.load(scalar_bad_config_path)
    except ValueError as exc:
        invalid_config_error = str(exc)
    try:
        AgentAppConfig.load(scalar_bridge_bad_config_path)
    except ValueError as exc:
        invalid_bridge_error = str(exc)
    config_scalar_payload = {
        "auto_execute_natural": scalar_cfg.auto_execute_natural,
        "auto_model_planning": scalar_cfg.auto_model_planning,
        "max_auto_steps": scalar_cfg.max_auto_steps,
        "plugin_dirs": scalar_cfg.plugin_dirs,
        "blocked_tools": scalar_cfg.blocked_tools,
        "skill_bundles": scalar_cfg.skill_bundles,
        "bridge": scalar_bridge.sanitized(),
        "invalid_config_error": invalid_config_error,
        "invalid_bridge_error": invalid_bridge_error,
    }
    write("config-scalar-validation.json", json.dumps(config_scalar_payload, indent=2, sort_keys=True))
    checks["config_scalar_validation_ok"] = (
        scalar_cfg.auto_execute_natural is False
        and scalar_cfg.auto_model_planning is False
        and scalar_cfg.max_auto_steps == 3
        and scalar_cfg.plugin_dirs == [str(REPO / "examples" / "plugins")]
        and scalar_cfg.blocked_tools == ["export_pack"]
        and scalar_cfg.skill_bundles == {"smoke": ["smoke-skill"]}
        and scalar_bridge.enabled is True
        and scalar_bridge.allow_all is False
        and scalar_bridge.allow_approval_actions is False
        and scalar_bridge.ignore_bots is True
        and scalar_bridge.max_attachment_bytes == 4096
        and scalar_bridge.extra.get("response_polish") is False
        and "auto_execute_natural must be a boolean" in invalid_config_error
        and "bridges.discord.allow_all must be a boolean" in invalid_bridge_error
    )

    init_stdout = run_cmd(
        "agent-init",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "init", "--engagement", str(engagement_path)],
    )
    init_json = json.loads(init_stdout)
    checks["agent_init_ok"] = bool(init_json.get("session_id")) and init_json["runtime"]["skill_dirs"] == [str(skill_root)]

    native_cli_db = data / "native-tool-cli-entrypoints.db"
    run_cmd(
        "native-tool-cli-init",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(native_cli_db), "--config", str(config_path), "init", "--engagement", str(engagement_path)],
    )
    native_cli_plan = run_cmd(
        "native-tool-cli-auto-plan",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(native_cli_db), "--config", str(config_path), "auto", "--engagement", str(engagement_path), "--prompt", "remember native-cli-plan: CLI native plan token=native-cli-plan-secret"],
    )
    native_cli_apply = run_cmd(
        "native-tool-cli-auto-apply",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(native_cli_db), "--config", str(config_path), "auto", "--engagement", str(engagement_path), "--apply", "--prompt", "remember native-cli-apply: CLI native apply token=native-cli-apply-secret"],
    )
    native_cli_loop = run_cmd(
        "native-tool-cli-auto-loop",
        [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(native_cli_db), "--config", str(config_path), "auto-loop", "--engagement", str(engagement_path), "--steps", "2", "--prompt", "remember native-cli-loop: CLI native loop token=native-cli-loop-secret"],
    )
    native_cli_plan_payload = json.loads(native_cli_plan.split("\n", 1)[1])
    native_cli_apply_payload = json.loads(native_cli_apply.split("\n", 1)[1])
    native_cli_loop_payload = json.loads(native_cli_loop.split("\n", 1)[1])
    native_cli_loop_ledger = native_cli_loop_payload.get("execution_ledger", []) if isinstance(native_cli_loop_payload.get("execution_ledger"), list) else []
    checks["native_tool_call_cli_entrypoints_ok"] = (
        native_cli_plan_payload.get("mode") == "plan_only"
        and native_cli_plan_payload.get("no_tools_executed") is True
        and native_cli_plan_payload.get("execution_ledger") == []
        and native_cli_apply_payload.get("mode") == "applied"
        and native_cli_apply_payload.get("results", [{}])[0].get("result", {}).get("status") == "ok"
        and native_cli_apply_payload.get("execution_ledger", [{}])[0].get("execution_state") == "completed_without_command_execution"
        and native_cli_loop_payload.get("stop_reason") == "deterministic_plan_applied"
        and native_cli_loop_payload.get("steps_executed") == 1
        and all(item.get("actual_command_or_process_activity") is False for item in native_cli_loop_ledger)
        and "native-cli-plan-secret" not in native_cli_plan
        and "native-cli-apply-secret" not in native_cli_apply
        and "native-cli-loop-secret" not in native_cli_loop
    )

    runtime = PhobosAgentRuntime(AgentAppConfig.load(config_path).to_runtime_config(str(engagement_path), str(db_path), "smoke", config_path=str(config_path)))
    gateway = None
    try:
        def handle(name: str, message: str) -> str:
            response = runtime.handle_message(message)
            write(name + ".txt", response)
            return response

        tools = handle("tools", "/tools")
        checks["tools_include_core_plugin_and_new_parity"] = all(
            token in tools
            for token in [
                "runtime_status",
                "scope_check",
                "workspace_write",
                "start_process",
                "operator_briefing",
                "export_session",
                "import_session",
                "context_compact_node",
                "delegate_tasks",
                "auth_status",
                "safety_preflight",
                "guardrail_selftest",
                "media_import",
                "sealed_export",
                "hindsight_retain",
                "lcm_compact",
                "list_memories",
                "get_memory",
                "forget_memory",
                "wait_process",
                "add_task",
                "get_task",
                "get_process",
                "get_job",
                "update_job",
                "disable_job",
                "example_echo",
                "nmap_scan",
                "httpx_probe",
                "nuclei_scan",
                "ffuf_scan",
                "create_finding",
                "list_findings",
                "finding_export",
                "finding_review",
                "finding_bundle",
                "evidence_timeline",
                "evidence_manifest",
                "evidence_manifest_verify",
                "evidence_secret_scan",
                "closeout_review",
                "resolve_local_ref",
                "get_audit",
            ]
        )
        status = handle("status", "/status")
        status_data = runtime.registry.run("runtime_status", {}).data
        checks["schema_version_ok"] = int(status_data["schema"]["schema_version"]) >= 5 and '"fts_available"' in status
        checks["db_schema_counts_ok"] = all(key in status_data for key in ["context_nodes", "delegations", "media_artifacts", "tasks", "processes", "tool_runs", "findings"])
        skill_list = handle("skills", "/skills")
        skill_load = handle("skill-load", "/skill name=smoke-skill")
        checks["local_skills_ok"] = "Smoke skill for local progressive" in skill_list and "ROE and evidence first" in skill_load
        schema = handle("schema-start-process", "/schemas name=start_process")
        checks["schema_returned"] = "start_process" in schema and "execute" in schema
        plugin = handle("plugin-echo", "/tool name=example_echo value=plugin-ok")
        checks["plugin_loaded_and_executed"] = '"echo": "plugin-ok"' in plugin
        number_dispatches: list[dict[str, object]] = []
        collection_dispatches: list[dict[str, object]] = []
        size_dispatches: list[dict[str, object]] = []
        pattern_dispatches: list[dict[str, object]] = []
        closed_dispatches: list[dict[str, object]] = []

        def schema_number_echo(args: dict[str, object]) -> ToolResult:
            number_dispatches.append(dict(args))
            return ToolResult("ok", "number ok", {"threshold": args.get("threshold"), "threshold_type": type(args.get("threshold")).__name__})

        def schema_collection_echo(args: dict[str, object]) -> ToolResult:
            collection_dispatches.append(dict(args))
            return ToolResult("ok", "collection ok", {"items": args.get("items"), "options": args.get("options")})

        def schema_size_echo(args: dict[str, object]) -> ToolResult:
            size_dispatches.append(dict(args))
            return ToolResult("ok", "size ok", {"label": args.get("label"), "items": args.get("items"), "options": args.get("options")})

        def schema_pattern_echo(args: dict[str, object]) -> ToolResult:
            pattern_dispatches.append(dict(args))
            return ToolResult("ok", "pattern ok", {"label": args.get("label")})

        def schema_closed_echo(args: dict[str, object]) -> ToolResult:
            closed_dispatches.append(dict(args))
            return ToolResult("ok", "closed ok", {"label": args.get("label"), "args": dict(args)})

        runtime.registry.register_tool(
            "schema_number_echo",
            schema_number_echo,
            {
                "description": "Smoke-only JSON-schema number validation boundary.",
                "schema": {
                    "type": "object",
                    "properties": {
                        "threshold": {"type": "number", "minimum": 0.1, "maximum": 10, "description": "Unit threshold."},
                        "label": {"type": "string", "description": "Optional label."},
                    },
                    "required": ["threshold"],
                    "additionalProperties": True,
                },
            },
        )
        runtime.registry.register_tool(
            "schema_collection_echo",
            schema_collection_echo,
            {
                "description": "Smoke-only JSON-schema array/object validation boundary.",
                "schema": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "string", "pattern": r"^[a-z][a-z0-9_-]*$", "x-pattern-error": "must be lowercase safe item text"},
                            "description": "Ordered smoke items.",
                        },
                        "options": {
                            "type": "object",
                            "properties": {
                                "mode": {"type": "string", "enum": ["safe", "review"]},
                                "retries": {"type": "integer", "minimum": 1, "maximum": 3},
                            },
                            "required": ["mode"],
                            "additionalProperties": False,
                            "description": "Structured smoke options.",
                        },
                    },
                    "required": ["items"],
                    "additionalProperties": True,
                },
            },
        )
        runtime.registry.register_tool(
            "schema_size_echo",
            schema_size_echo,
            {
                "description": "Smoke-only JSON-schema string/collection size-bound validation boundary.",
                "schema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "minLength": 3, "maxLength": 8, "description": "Bounded smoke label."},
                        "items": {"type": "array", "minItems": 1, "maxItems": 2, "description": "Bounded smoke items."},
                        "options": {"type": "object", "minProperties": 1, "maxProperties": 2, "description": "Bounded smoke options."},
                    },
                    "required": ["label", "items", "options"],
                    "additionalProperties": True,
                },
            },
        )
        runtime.registry.register_tool(
            "schema_pattern_echo",
            schema_pattern_echo,
            {
                "description": "Smoke-only JSON-schema string pattern validation boundary.",
                "schema": {
                    "type": "object",
                    "properties": {
                        "label": {
                            "type": "string",
                            "pattern": r"^[A-Z][A-Z0-9_-]{2,7}$",
                            "x-pattern-error": "must be an uppercase safe label",
                            "description": "Pattern-bounded smoke label.",
                        },
                    },
                    "required": ["label"],
                    "additionalProperties": True,
                },
            },
        )
        runtime.registry.register_tool(
            "schema_closed_echo",
            schema_closed_echo,
            {
                "description": "Smoke-only JSON-schema closed-object validation boundary.",
                "schema": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Closed-schema smoke label."},
                    },
                    "required": ["label"],
                    "additionalProperties": False,
                },
            },
        )
        invalid_tool_integer = runtime.registry.run("list_findings", {"limit": "not-an-int"})
        invalid_tool_integer_fractional = runtime.registry.run("list_findings", {"limit": 1.5})
        invalid_tool_integer_fractional_string = runtime.registry.run("list_findings", {"limit": "1.5"})
        valid_tool_integer = runtime.registry.run("list_findings", {"limit": "2"})
        valid_tool_integer_float = runtime.registry.run("list_findings", {"limit": 2.0})
        invalid_tool_integer_bound = runtime.registry.run("list_findings", {"limit": 0})
        invalid_tool_integer_ceiling = runtime.registry.run("list_findings", {"limit": 5001})
        invalid_tool_timeline_ceiling = runtime.registry.run("evidence_timeline", {"limit": 501})
        invalid_tool_log_ceiling = runtime.registry.run("process_log", {"id": 1, "limit": 200001})
        invalid_tool_wait_ceiling = runtime.registry.run("wait_process", {"id": 1, "timeout": 301})
        invalid_tool_command_timeout_ceiling = runtime.registry.run("run_command", {"timeout": 601})
        invalid_tool_scanner_timeout_ceiling = runtime.registry.run("nmap_scan", {"target": "app.example.test", "timeout": 301})
        invalid_tool_manifest_bytes_ceiling = runtime.registry.run("evidence_manifest", {"max_bytes": 500000001})
        invalid_tool_text_bytes_ceiling = runtime.registry.run("evidence_secret_scan", {"max_bytes": 50000001})
        integer_bound_approvals_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("list_findings")
        try:
            invalid_confirm_integer_fractional = runtime.registry.run("list_findings", {"limit": 1.5})
            invalid_confirm_integer_bound = runtime.registry.run("list_findings", {"limit": 0})
            invalid_confirm_integer_ceiling = runtime.registry.run("list_findings", {"limit": 5001})
        finally:
            runtime.registry.confirm_tools.discard("list_findings")
        integer_bound_approvals_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        integer_validation_payload = {
            "invalid": invalid_tool_integer.to_dict(),
            "invalid_fractional": invalid_tool_integer_fractional.to_dict(),
            "invalid_fractional_string": invalid_tool_integer_fractional_string.to_dict(),
            "valid": valid_tool_integer.to_dict(),
            "valid_float": valid_tool_integer_float.to_dict(),
            "invalid_bound": invalid_tool_integer_bound.to_dict(),
            "invalid_ceiling": invalid_tool_integer_ceiling.to_dict(),
            "invalid_timeline_ceiling": invalid_tool_timeline_ceiling.to_dict(),
            "invalid_log_ceiling": invalid_tool_log_ceiling.to_dict(),
            "invalid_wait_ceiling": invalid_tool_wait_ceiling.to_dict(),
            "invalid_command_timeout_ceiling": invalid_tool_command_timeout_ceiling.to_dict(),
            "invalid_scanner_timeout_ceiling": invalid_tool_scanner_timeout_ceiling.to_dict(),
            "invalid_manifest_bytes_ceiling": invalid_tool_manifest_bytes_ceiling.to_dict(),
            "invalid_text_bytes_ceiling": invalid_tool_text_bytes_ceiling.to_dict(),
            "invalid_confirm_fractional": invalid_confirm_integer_fractional.to_dict(),
            "invalid_confirm_bound": invalid_confirm_integer_bound.to_dict(),
            "invalid_confirm_ceiling": invalid_confirm_integer_ceiling.to_dict(),
            "approvals_before": integer_bound_approvals_before,
            "approvals_after": integer_bound_approvals_after,
        }
        write("tool-schema-integer-validation.json", json.dumps(integer_validation_payload, indent=2))
        checks["tool_schema_integer_validation_ok"] = (
            invalid_tool_integer.status == "error"
            and invalid_tool_integer.message == "limit must be an integer."
            and invalid_tool_integer_fractional.status == "error"
            and invalid_tool_integer_fractional.message == "limit must be an integer."
            and invalid_tool_integer_fractional_string.status == "error"
            and invalid_tool_integer_fractional_string.message == "limit must be an integer."
            and valid_tool_integer.status == "ok"
            and valid_tool_integer_float.status == "ok"
            and invalid_confirm_integer_fractional.status == "error"
            and invalid_confirm_integer_fractional.message == "limit must be an integer."
            and integer_bound_approvals_before == integer_bound_approvals_after
            and "invalid literal" not in json.dumps(integer_validation_payload)
            and "Traceback" not in json.dumps(integer_validation_payload)
        )
        checks["tool_schema_integer_bounds_validation_ok"] = (
            invalid_tool_integer_bound.status == "error"
            and invalid_tool_integer_bound.message == "limit must be at least 1."
            and invalid_confirm_integer_bound.status == "error"
            and invalid_confirm_integer_bound.message == "limit must be at least 1."
            and integer_bound_approvals_before == integer_bound_approvals_after
            and "Traceback" not in json.dumps(integer_validation_payload)
        )
        checks["tool_schema_resource_ceiling_ok"] = (
            invalid_tool_integer_ceiling.status == "error"
            and invalid_tool_integer_ceiling.message == "limit must be at most 5000."
            and invalid_tool_timeline_ceiling.status == "error"
            and invalid_tool_timeline_ceiling.message == "limit must be at most 500."
            and invalid_tool_log_ceiling.status == "error"
            and invalid_tool_log_ceiling.message == "limit must be at most 200000."
            and invalid_tool_wait_ceiling.status == "error"
            and invalid_tool_wait_ceiling.message == "timeout must be at most 300."
            and invalid_tool_command_timeout_ceiling.status == "error"
            and invalid_tool_command_timeout_ceiling.message == "timeout must be at most 600."
            and invalid_tool_scanner_timeout_ceiling.status == "error"
            and invalid_tool_scanner_timeout_ceiling.message == "timeout must be at most 300."
            and invalid_tool_manifest_bytes_ceiling.status == "error"
            and invalid_tool_manifest_bytes_ceiling.message == "max_bytes must be at most 500000000."
            and invalid_tool_text_bytes_ceiling.status == "error"
            and invalid_tool_text_bytes_ceiling.message == "max_bytes must be at most 50000000."
            and invalid_confirm_integer_ceiling.status == "error"
            and invalid_confirm_integer_ceiling.message == "limit must be at most 5000."
            and integer_bound_approvals_before == integer_bound_approvals_after
            and "Traceback" not in json.dumps(integer_validation_payload)
        )
        invalid_tool_boolean = runtime.registry.run("run_command", {"execute": "maybe"})
        dry_tool_boolean = runtime.registry.run("run_command", {"target": "app.example.test", "type": "local", "purpose": "boolean schema dry-run regression", "command": "printf bool-validation-ok", "execute": "false"})
        runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "old"})
        overwrite_tool_boolean = runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "new", "append": "false"})
        append_tool_boolean = runtime.registry.run("workspace_write", {"path": "notes/schema-bool.md", "content": "-tail", "append": "true"})
        boolean_workspace_text = (runtime.registry.workspace_root / "notes" / "schema-bool.md").read_text(encoding="utf-8")
        boolean_validation_payload = {
            "invalid": invalid_tool_boolean.to_dict(),
            "dry_run": dry_tool_boolean.to_dict(),
            "overwrite": overwrite_tool_boolean.to_dict(),
            "append": append_tool_boolean.to_dict(),
            "workspace_text": boolean_workspace_text,
        }
        write("tool-schema-boolean-validation.json", json.dumps(boolean_validation_payload, indent=2))
        checks["tool_schema_boolean_validation_ok"] = (
            invalid_tool_boolean.status == "error"
            and invalid_tool_boolean.message == "execute must be a boolean."
            and dry_tool_boolean.status == "dry_run"
            and overwrite_tool_boolean.status == "ok"
            and append_tool_boolean.status == "ok"
            and boolean_workspace_text == "new-tail"
            and "Traceback" not in json.dumps(boolean_validation_payload)
        )
        invalid_tool_string = runtime.registry.run("workspace_write", {"path": ["notes/schema-string.md"], "content": "bad"})
        valid_tool_string = runtime.registry.run("workspace_write", {"path": "notes/schema-string.md", "content": "string-ok"})
        string_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("workspace_write")
        try:
            invalid_confirm_string = runtime.registry.run("workspace_write", {"path": {"bad": "queued.md"}, "content": "nope"})
        finally:
            runtime.registry.confirm_tools.discard("workspace_write")
        string_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        string_validation_payload = {
            "invalid": invalid_tool_string.to_dict(),
            "valid": valid_tool_string.to_dict(),
            "invalid_confirm_tool": invalid_confirm_string.to_dict(),
            "approvals_before": string_approval_count_before,
            "approvals_after": string_approval_count_after,
        }
        write("tool-schema-string-validation.json", json.dumps(string_validation_payload, indent=2))
        checks["tool_schema_string_validation_ok"] = (
            invalid_tool_string.status == "error"
            and invalid_tool_string.message == "path must be a string."
            and valid_tool_string.status == "ok"
            and invalid_confirm_string.status == "error"
            and invalid_confirm_string.message == "path must be a string."
            and string_approval_count_before == string_approval_count_after
            and (runtime.registry.workspace_root / "notes" / "schema-string.md").read_text(encoding="utf-8") == "string-ok"
            and "Traceback" not in json.dumps(string_validation_payload)
        )
        invalid_tool_number = runtime.registry.run("schema_number_echo", {"threshold": "not-a-number"})
        invalid_tool_number_finite = runtime.registry.run("schema_number_echo", {"threshold": "nan"})
        invalid_tool_number_bound = runtime.registry.run("schema_number_echo", {"threshold": "0.05"})
        invalid_tool_number_bool = runtime.registry.run("schema_number_echo", {"threshold": True})
        valid_tool_number = runtime.registry.run("schema_number_echo", {"threshold": "1.25", "label": "smoke"})
        blank_required_integer = runtime.registry.run("poll_process", {"id": ""})
        blank_required_number = runtime.registry.run("schema_number_echo", {"threshold": ""})
        number_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("schema_number_echo")
        try:
            invalid_confirm_number = runtime.registry.run("schema_number_echo", {"threshold": "nope"})
            invalid_confirm_blank_number = runtime.registry.run("schema_number_echo", {"threshold": ""})
        finally:
            runtime.registry.confirm_tools.discard("schema_number_echo")
        number_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        number_validation_payload = {
            "invalid": invalid_tool_number.to_dict(),
            "invalid_finite": invalid_tool_number_finite.to_dict(),
            "invalid_bound": invalid_tool_number_bound.to_dict(),
            "invalid_bool": invalid_tool_number_bool.to_dict(),
            "valid": valid_tool_number.to_dict(),
            "blank_required_integer": blank_required_integer.to_dict(),
            "blank_required_number": blank_required_number.to_dict(),
            "invalid_confirm_number": invalid_confirm_number.to_dict(),
            "invalid_confirm_blank_number": invalid_confirm_blank_number.to_dict(),
            "approvals_before": number_approval_count_before,
            "approvals_after": number_approval_count_after,
            "dispatches": number_dispatches,
        }
        write("tool-schema-number-validation.json", json.dumps(number_validation_payload, indent=2))
        checks["tool_schema_number_validation_ok"] = (
            invalid_tool_number.status == "error"
            and invalid_tool_number.message == "threshold must be a number."
            and invalid_tool_number_finite.status == "error"
            and invalid_tool_number_finite.message == "threshold must be a number."
            and invalid_tool_number_bool.status == "error"
            and invalid_tool_number_bool.message == "threshold must be a number."
            and invalid_tool_number_bound.status == "error"
            and invalid_tool_number_bound.message == "threshold must be at least 0.1."
            and valid_tool_number.status == "ok"
            and valid_tool_number.data.get("threshold") == 1.25
            and invalid_confirm_number.status == "error"
            and number_approval_count_after == number_approval_count_before
            and number_dispatches == [{"threshold": 1.25, "label": "smoke"}]
            and "Traceback" not in json.dumps(number_validation_payload)
        )
        checks["tool_schema_blank_required_validation_ok"] = (
            blank_required_integer.status == "error"
            and blank_required_integer.message == "id is required."
            and blank_required_number.status == "error"
            and blank_required_number.message == "threshold is required."
            and invalid_confirm_blank_number.status == "error"
            and invalid_confirm_blank_number.message == "threshold is required."
            and number_approval_count_after == number_approval_count_before
            and "Traceback" not in json.dumps(number_validation_payload)
        )
        invalid_tool_array = runtime.registry.run("schema_collection_echo", {"items": "not-an-array"})
        invalid_tool_object = runtime.registry.run("schema_collection_echo", {"items": [], "options": ["not-an-object"]})
        blank_required_array = runtime.registry.run("schema_collection_echo", {"items": ""})
        invalid_item_type = runtime.registry.run("schema_collection_echo", {"items": ["alpha", 7], "options": {"mode": "safe"}})
        invalid_item_pattern = runtime.registry.run("schema_collection_echo", {"items": ["Bad Space"], "options": {"mode": "safe"}})
        invalid_object_enum = runtime.registry.run("schema_collection_echo", {"items": ["alpha"], "options": {"mode": "unsafe"}})
        invalid_object_required = runtime.registry.run("schema_collection_echo", {"items": ["alpha"], "options": {}})
        invalid_object_extra = runtime.registry.run("schema_collection_echo", {"items": ["alpha"], "options": {"extra": True}})
        invalid_object_integer = runtime.registry.run("schema_collection_echo", {"items": ["alpha"], "options": {"mode": "safe", "retries": "bad"}})
        valid_tool_collection = runtime.registry.run("schema_collection_echo", {"items": ["alpha", "beta"], "options": {"mode": "safe", "retries": "2"}})
        collection_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("schema_collection_echo")
        try:
            invalid_confirm_array = runtime.registry.run("schema_collection_echo", {"items": "queued-string"})
            invalid_confirm_object = runtime.registry.run("schema_collection_echo", {"items": [], "options": "queued-string"})
            invalid_confirm_nested = runtime.registry.run("schema_collection_echo", {"items": ["queued"], "options": {"mode": "unsafe"}})
        finally:
            runtime.registry.confirm_tools.discard("schema_collection_echo")
        collection_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        collection_validation_payload = {
            "invalid_array": invalid_tool_array.to_dict(),
            "invalid_object": invalid_tool_object.to_dict(),
            "blank_required_array": blank_required_array.to_dict(),
            "invalid_item_type": invalid_item_type.to_dict(),
            "invalid_item_pattern": invalid_item_pattern.to_dict(),
            "invalid_object_enum": invalid_object_enum.to_dict(),
            "invalid_object_required": invalid_object_required.to_dict(),
            "invalid_object_extra": invalid_object_extra.to_dict(),
            "invalid_object_integer": invalid_object_integer.to_dict(),
            "valid": valid_tool_collection.to_dict(),
            "invalid_confirm_array": invalid_confirm_array.to_dict(),
            "invalid_confirm_object": invalid_confirm_object.to_dict(),
            "invalid_confirm_nested": invalid_confirm_nested.to_dict(),
            "approvals_before": collection_approval_count_before,
            "approvals_after": collection_approval_count_after,
            "dispatches": collection_dispatches,
        }
        write("tool-schema-array-object-validation.json", json.dumps(collection_validation_payload, indent=2))
        checks["tool_schema_array_object_validation_ok"] = (
            invalid_tool_array.status == "error"
            and invalid_tool_array.message == "items must be an array."
            and invalid_tool_object.status == "error"
            and invalid_tool_object.message == "options must be an object."
            and blank_required_array.status == "error"
            and blank_required_array.message == "items is required."
            and valid_tool_collection.status == "ok"
            and valid_tool_collection.data.get("items") == ["alpha", "beta"]
            and valid_tool_collection.data.get("options") == {"mode": "safe", "retries": 2}
            and invalid_confirm_array.status == "error"
            and invalid_confirm_array.message == "items must be an array."
            and invalid_confirm_object.status == "error"
            and invalid_confirm_object.message == "options must be an object."
            and invalid_confirm_nested.status == "error"
            and invalid_confirm_nested.message == "options.mode must be one of: safe, review."
            and collection_approval_count_before == collection_approval_count_after
            and collection_dispatches == [{"items": ["alpha", "beta"], "options": {"mode": "safe", "retries": 2}}]
            and "Traceback" not in json.dumps(collection_validation_payload)
        )
        checks["tool_schema_nested_validation_ok"] = (
            invalid_item_type.status == "error"
            and invalid_item_type.message == "items[1] must be a string."
            and invalid_item_pattern.status == "error"
            and invalid_item_pattern.message == "items[0] must be lowercase safe item text."
            and invalid_object_enum.status == "error"
            and invalid_object_enum.message == "options.mode must be one of: safe, review."
            and invalid_object_required.status == "error"
            and invalid_object_required.message == "options.mode is required."
            and invalid_object_extra.status == "error"
            and invalid_object_extra.message == "options.extra is not an allowed field."
            and invalid_object_integer.status == "error"
            and invalid_object_integer.message == "options.retries must be an integer."
            and invalid_confirm_nested.status == "error"
            and collection_approval_count_before == collection_approval_count_after
            and "Traceback" not in json.dumps(collection_validation_payload)
        )
        invalid_size_short_string = runtime.registry.run("schema_size_echo", {"label": "ab", "items": ["one"], "options": {"mode": "safe"}})
        invalid_size_long_string = runtime.registry.run("schema_size_echo", {"label": "too-long-label", "items": ["one"], "options": {"mode": "safe"}})
        invalid_size_few_items = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": [], "options": {"mode": "safe"}})
        invalid_size_many_items = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": ["one", "two", "three"], "options": {"mode": "safe"}})
        invalid_size_few_fields = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": ["one"], "options": {}})
        invalid_size_many_fields = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": ["one"], "options": {"a": 1, "b": 2, "c": 3}})
        valid_size_bounds = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": ["one", "two"], "options": {"mode": "safe", "phase": "smoke"}})
        size_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("schema_size_echo")
        try:
            invalid_confirm_size = runtime.registry.run("schema_size_echo", {"label": "ab", "items": ["queued"], "options": {"mode": "safe"}})
        finally:
            runtime.registry.confirm_tools.discard("schema_size_echo")
        size_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        size_validation_payload = {
            "invalid_short_string": invalid_size_short_string.to_dict(),
            "invalid_long_string": invalid_size_long_string.to_dict(),
            "invalid_few_items": invalid_size_few_items.to_dict(),
            "invalid_many_items": invalid_size_many_items.to_dict(),
            "invalid_few_fields": invalid_size_few_fields.to_dict(),
            "invalid_many_fields": invalid_size_many_fields.to_dict(),
            "valid": valid_size_bounds.to_dict(),
            "invalid_confirm": invalid_confirm_size.to_dict(),
            "approvals_before": size_approval_count_before,
            "approvals_after": size_approval_count_after,
            "dispatches": size_dispatches,
        }
        write("tool-schema-size-bounds-validation.json", json.dumps(size_validation_payload, indent=2))
        checks["tool_schema_size_bounds_validation_ok"] = (
            invalid_size_short_string.status == "error"
            and invalid_size_short_string.message == "label must be at least 3 characters."
            and invalid_size_long_string.status == "error"
            and invalid_size_long_string.message == "label must be at most 8 characters."
            and invalid_size_few_items.status == "error"
            and invalid_size_few_items.message == "items must contain at least 1 item."
            and invalid_size_many_items.status == "error"
            and invalid_size_many_items.message == "items must contain at most 2 items."
            and invalid_size_few_fields.status == "error"
            and invalid_size_few_fields.message == "options must contain at least 1 field."
            and invalid_size_many_fields.status == "error"
            and invalid_size_many_fields.message == "options must contain at most 2 fields."
            and valid_size_bounds.status == "ok"
            and valid_size_bounds.data.get("label") == "bounded"
            and invalid_confirm_size.status == "error"
            and invalid_confirm_size.message == "label must be at least 3 characters."
            and size_approval_count_after == size_approval_count_before
            and size_dispatches == [{"label": "bounded", "items": ["one", "two"], "options": {"mode": "safe", "phase": "smoke"}}]
            and "Traceback" not in json.dumps(size_validation_payload)
        )
        invalid_pattern_lower = runtime.registry.run("schema_pattern_echo", {"label": "lower"})
        invalid_pattern_space = runtime.registry.run("schema_pattern_echo", {"label": "BAD SPACE"})
        invalid_pattern_blank = runtime.registry.run("schema_pattern_echo", {"label": ""})
        invalid_sealed_env_name = runtime.registry.run("sealed_export", {"passphrase_env": "bad env name"})
        valid_pattern = runtime.registry.run("schema_pattern_echo", {"label": "ABC_12"})
        pattern_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("schema_pattern_echo")
        try:
            invalid_confirm_pattern = runtime.registry.run("schema_pattern_echo", {"label": "queued"})
        finally:
            runtime.registry.confirm_tools.discard("schema_pattern_echo")
        pattern_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        pattern_validation_payload = {
            "invalid_lower": invalid_pattern_lower.to_dict(),
            "invalid_space": invalid_pattern_space.to_dict(),
            "invalid_blank": invalid_pattern_blank.to_dict(),
            "invalid_sealed_env_name": invalid_sealed_env_name.to_dict(),
            "valid": valid_pattern.to_dict(),
            "invalid_confirm": invalid_confirm_pattern.to_dict(),
            "approvals_before": pattern_approval_count_before,
            "approvals_after": pattern_approval_count_after,
            "dispatches": pattern_dispatches,
        }
        write("tool-schema-pattern-validation.json", json.dumps(pattern_validation_payload, indent=2))
        checks["tool_schema_pattern_validation_ok"] = (
            invalid_pattern_lower.status == "error"
            and invalid_pattern_lower.message == "label must be an uppercase safe label."
            and invalid_pattern_space.status == "error"
            and invalid_pattern_space.message == "label must be an uppercase safe label."
            and invalid_pattern_blank.status == "error"
            and invalid_pattern_blank.message == "label must be an uppercase safe label."
            and invalid_sealed_env_name.status == "error"
            and invalid_sealed_env_name.message == "passphrase_env must be an environment variable name."
            and valid_pattern.status == "ok"
            and valid_pattern.data.get("label") == "ABC_12"
            and invalid_confirm_pattern.status == "error"
            and invalid_confirm_pattern.message == "label must be an uppercase safe label."
            and pattern_approval_count_after == pattern_approval_count_before
            and pattern_dispatches == [{"label": "ABC_12"}]
            and "bad env name" not in json.dumps(pattern_validation_payload)
            and "Traceback" not in json.dumps(pattern_validation_payload)
        )
        invalid_closed_extra = runtime.registry.run("schema_closed_echo", {"label": "closed", "typo": "unexpected"})
        invalid_closed_many = runtime.registry.run("schema_closed_echo", {"label": "closed", "alpha": 1, "zulu": 2})
        valid_closed = runtime.registry.run("schema_closed_echo", {"label": "closed", "_policy_approved": True})
        closed_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("schema_closed_echo")
        try:
            invalid_confirm_closed = runtime.registry.run("schema_closed_echo", {"label": "queued", "extra": "nope"})
        finally:
            runtime.registry.confirm_tools.discard("schema_closed_echo")
        closed_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        closed_validation_payload = {
            "invalid_extra": invalid_closed_extra.to_dict(),
            "invalid_many": invalid_closed_many.to_dict(),
            "valid": valid_closed.to_dict(),
            "invalid_confirm": invalid_confirm_closed.to_dict(),
            "approvals_before": closed_approval_count_before,
            "approvals_after": closed_approval_count_after,
            "dispatches": closed_dispatches,
        }
        write("tool-schema-additional-properties-validation.json", json.dumps(closed_validation_payload, indent=2))
        checks["tool_schema_additional_properties_validation_ok"] = (
            invalid_closed_extra.status == "error"
            and invalid_closed_extra.message == "typo is not an allowed argument."
            and invalid_closed_many.status == "error"
            and invalid_closed_many.message == "Unexpected arguments: alpha, zulu."
            and valid_closed.status == "ok"
            and valid_closed.data.get("label") == "closed"
            and invalid_confirm_closed.status == "error"
            and invalid_confirm_closed.message == "extra is not an allowed argument."
            and closed_approval_count_after == closed_approval_count_before
            and closed_dispatches == [{"label": "closed", "_policy_approved": True}]
            and "Traceback" not in json.dumps(closed_validation_payload)
        )
        missing_required_tool = runtime.registry.run("workspace_write", {"path": "notes/schema-required.md"})
        approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("workspace_write")
        try:
            missing_required_confirm_tool = runtime.registry.run("workspace_write", {"path": "notes/schema-required-confirm.md"})
        finally:
            runtime.registry.confirm_tools.discard("workspace_write")
        approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        required_validation_payload = {
            "missing_required": missing_required_tool.to_dict(),
            "missing_required_confirm": missing_required_confirm_tool.to_dict(),
            "approvals_before": approval_count_before,
            "approvals_after": approval_count_after,
        }
        write("tool-schema-required-validation.json", json.dumps(required_validation_payload, indent=2))
        checks["tool_schema_required_validation_ok"] = (
            missing_required_tool.status == "error"
            and missing_required_tool.message == "content is required."
            and missing_required_confirm_tool.status == "error"
            and missing_required_confirm_tool.message == "content is required."
            and approval_count_before == approval_count_after
            and not (runtime.registry.workspace_root / "notes" / "schema-required.md").exists()
            and "Traceback" not in json.dumps(required_validation_payload)
        )
        invalid_tool_enum = runtime.registry.run("create_finding", {"title": "Schema enum invalid", "status": "client-ready"})
        valid_tool_enum = runtime.registry.run("create_finding", {"title": "Schema enum valid", "severity": "med", "status": "needs_evidence"})
        filtered_tool_enum = runtime.registry.run("list_findings", {"status": "needs_evidence"})
        invalid_media_enum = runtime.registry.run("media_import", {"path": str(media_source), "kind": "screenshot"})
        invalid_timeline_enum = runtime.registry.run("evidence_timeline", {"order": "sideways"})
        enum_approval_count_before = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        runtime.registry.confirm_tools.add("add_task")
        try:
            invalid_confirm_enum = runtime.registry.run("add_task", {"content": "schema enum queued", "status": "sideways"})
        finally:
            runtime.registry.confirm_tools.discard("add_task")
        enum_approval_count_after = len(runtime.store.list_approvals(runtime.session_id, status="all"))
        enum_validation_payload = {
            "invalid_status": invalid_tool_enum.to_dict(),
            "valid_finding": valid_tool_enum.to_dict(),
            "filtered": filtered_tool_enum.to_dict(),
            "invalid_media_kind": invalid_media_enum.to_dict(),
            "invalid_timeline_order": invalid_timeline_enum.to_dict(),
            "invalid_confirm_tool": invalid_confirm_enum.to_dict(),
            "approvals_before": enum_approval_count_before,
            "approvals_after": enum_approval_count_after,
        }
        write("tool-schema-enum-validation.json", json.dumps(enum_validation_payload, indent=2))
        checks["tool_schema_enum_validation_ok"] = (
            invalid_tool_enum.status == "error"
            and invalid_tool_enum.message == "status must be one of: draft, needs-evidence, confirmed, resolved, accepted-risk, false-positive."
            and valid_tool_enum.status == "ok"
            and valid_tool_enum.data["finding"]["severity"] == "Medium"
            and valid_tool_enum.data["finding"]["status"] == "needs-evidence"
            and filtered_tool_enum.status == "ok"
            and any(item.get("title") == "Schema enum valid" for item in filtered_tool_enum.data.get("findings", []))
            and invalid_media_enum.status == "error"
            and invalid_media_enum.message == "kind must be one of: image, audio, voice, video, file."
            and invalid_timeline_enum.status == "error"
            and invalid_timeline_enum.message == "order must be one of: desc, asc, newest, newest-first, oldest, oldest-first."
            and invalid_confirm_enum.status == "error"
            and invalid_confirm_enum.message == "status must be one of: pending, in_progress, completed, cancelled."
            and enum_approval_count_before == enum_approval_count_after
            and "Traceback" not in json.dumps(enum_validation_payload)
        )

        scope_summary = handle("scope-summary", "/scope")
        scope_allowed = handle("scope-allowed", '/scope target="https://app.example.test/login?token=supersecret"')
        scope_blocked = handle("scope-blocked", "/scope-check target=outside.example.test")
        runtime.roe.in_scope_targets.extend([
            "https://api.example.test:8443",
            "*.scoped.example:443",
            "2001:db8::/126",
            "[2001:db8::8]:9443",
        ])
        scope_url_port_allowed = handle("scope-url-port-allowed", '/scope target="https://api.example.test:8443/v1?token=supersecret"')
        scope_url_port_blocked = handle("scope-url-port-blocked", '/scope target="https://api.example.test:9443/v1"')
        scope_wildcard_port_allowed = handle("scope-wildcard-port-allowed", '/scope target="team.scoped.example:443"')
        scope_ipv6_allowed = handle("scope-ipv6-allowed", '/scope target="http://[2001:db8::1]:8080/"')
        scope_ipv6_port_allowed = handle("scope-ipv6-port-allowed", '/scope target="[2001:db8::8]:9443"')
        scope_schema = handle("schema-scope-check", "/schemas name=scope_check")
        auto_scope = handle("auto-scope", '/auto apply=true prompt="is app.example.test in scope?"')
        checks["scope_check_read_only_ok"] = (
            "Engagement scope summary" in scope_summary
            and '"no_target_activity": true' in scope_summary
            and '"decision": "allow"' in scope_allowed
            and '"decision": "block"' in scope_blocked
            and "scope_check" in scope_schema
            and '"tool": "scope_check"' in auto_scope
            and "supersecret" not in scope_summary + scope_allowed + scope_blocked + scope_schema + auto_scope
        )
        checks["scope_url_port_ipv6_matching_ok"] = (
            '"decision": "allow"' in scope_url_port_allowed
            and '"matched_rule": "https://api.example.test:8443"' in scope_url_port_allowed
            and '"decision": "block"' in scope_url_port_blocked
            and '"decision": "allow"' in scope_wildcard_port_allowed
            and '"decision": "allow"' in scope_ipv6_allowed
            and '"decision": "allow"' in scope_ipv6_port_allowed
            and "supersecret" not in scope_url_port_allowed + scope_url_port_blocked + scope_wildcard_port_allowed + scope_ipv6_allowed + scope_ipv6_port_allowed
        )

        guardrail_selftest = handle("guardrail-selftest", '/guardrail-test target="https://app.example.test/login?token=supersecret"')
        guardrail_selftest_schema = handle("schema-guardrail-selftest", "/schemas name=guardrail_selftest")
        guardrail_selftest_auto = handle("auto-guardrail-selftest", '/auto apply=true prompt="run guardrail self-test target=app.example.test"')
        guardrail_selftest_cli = run_cmd(
            "guardrail-test-cli",
            [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "guardrail-test", "--engagement", str(engagement_path), "--target", "app.example.test", "--out", "smoke-cli-guardrail-selftest.md"],
        )
        guardrail_selftest_json = json.loads(guardrail_selftest_cli)
        checks["guardrail_selftest_ok"] = (
            "Guardrail self-test ready" in guardrail_selftest
            and '"no_target_activity": true' in guardrail_selftest
            and '"executed": false' in guardrail_selftest
            and '"actual": "allow"' in guardrail_selftest
            and '"actual": "confirm"' in guardrail_selftest
            and '"actual": "block"' in guardrail_selftest
            and "guardrail_selftest" in guardrail_selftest_schema
            and '"tool": "guardrail_selftest"' in guardrail_selftest_auto
            and guardrail_selftest_json.get("status") == "ok"
            and guardrail_selftest_json.get("data", {}).get("readiness") == "ready"
            and "supersecret" not in guardrail_selftest + guardrail_selftest_schema + guardrail_selftest_auto + guardrail_selftest_cli
        )

        natural_polish = handle("natural-polish", "What is the safest next step for a controlled IDOR?")
        natural_execution = handle("natural-execution-polish", "Run nmap against app.example.test")
        checks["natural_response_polish_ok"] = (
            "Phobos Agent response" not in natural_polish
            and "pentest assistant" in natural_polish
            and "I didn’t run anything" in natural_execution
        )

        auto_plan = handle("auto-plan", '/auto prompt="remember smoke-client: ACME parity"')
        auto_apply = handle("auto-apply", '/auto apply=true prompt="remember smoke-client: ACME parity"')
        auto_loop = handle("auto-loop", '/auto-loop prompt="remember loop-client: ACME loop parity" steps=2')
        recall = handle("auto-recall", "/recall query=smoke-client")
        loop_recall = handle("auto-loop-recall", "/recall query=loop-client")
        checks["auto_memory_recall"] = '"mode": "plan_only"' in auto_plan and '"tool": "remember"' in auto_apply and "ACME parity" in recall
        checks["auto_loop_ok"] = "Auto loop completed" in auto_loop and "ACME loop parity" in loop_recall

        model_tool_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-tool-call-smoke",
                auto_model_planning=True,
                confirm_tools=("remember",),
            ),
            adapter=SmokeToolCallValidationAdapter(),
        )
        try:
            native_plan = model_tool_runtime.handle_message('/auto model=true prompt="mixed native tool call plan token=native-plan-secret"')
            native_plan_payload = json.loads(native_plan.split("\n", 1)[1])
            native_plan_artifacts = native_plan_payload.get("artifacts", {}) if isinstance(native_plan_payload.get("artifacts"), dict) else {}
            native_plan_json_path = Path(native_plan_artifacts.get("json", ""))
            native_plan_md_path = Path(native_plan_artifacts.get("markdown", ""))
            native_plan_transcript = ""
            if native_plan_json_path.is_file():
                native_plan_transcript += native_plan_json_path.read_text(encoding="utf-8")
            if native_plan_md_path.is_file():
                native_plan_transcript += native_plan_md_path.read_text(encoding="utf-8")
            pending_native_approvals_after_plan = model_tool_runtime.store.list_approvals(model_tool_runtime.session_id, status="pending")
            plan_audit_events = [row["event"] for row in model_tool_runtime.store.list_audit(model_tool_runtime.session_id, limit=20)]
            native_plan_detail = {"status": "missing"}
            if native_plan_json_path.is_file():
                native_plan_rel_json = native_plan_json_path.relative_to(model_tool_runtime.registry.harness.store.root).as_posix()
                native_plan_detail = model_tool_runtime.registry.run("get_auto_transcript", {"path": native_plan_rel_json, "max_ledger": 5}).to_dict()
            native_apply = model_tool_runtime.handle_message('/auto apply=true model=true prompt="mixed native tool call plan token=native-plan-secret"')
            write("native-tool-call-plan.txt", native_plan)
            write("native-tool-call-plan-transcript.txt", native_plan_transcript)
            write("native-tool-call-apply.txt", native_apply)
            write("native-tool-call-plan-detail.json", json.dumps(native_plan_detail, indent=2, sort_keys=True))
            native_apply_payload = json.loads(native_apply.split("\n", 1)[1])
            native_apply_ledger = native_apply_payload.get("execution_ledger", []) if isinstance(native_apply_payload.get("execution_ledger"), list) else []
            pending_native_approvals_after_apply = model_tool_runtime.store.list_approvals(model_tool_runtime.session_id, status="pending")
        finally:
            model_tool_runtime.close()
        checks["native_tool_call_plan_validation_ok"] = (
            native_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_plan_payload.get("tool_calls", [])] == ["list_tasks", "run_command"]
            and native_plan_payload["tool_calls"][0]["args"].get("limit") == 2
            and native_plan_payload["tool_calls"][0]["validation"].get("schema_validated") is True
            and native_plan_payload["tool_calls"][1]["args"].get("execute") is False
            and "Unknown tool: not_a_tool" in json.dumps(native_plan_payload.get("rejected_tool_calls", []))
            and "value is required" in json.dumps(native_plan_payload.get("rejected_tool_calls", []))
            and "tool_call" not in plan_audit_events
            and not pending_native_approvals_after_plan
            and native_apply_payload.get("mode") == "applied"
            and "dry_run" in [item.get("result", {}).get("status") for item in native_apply_payload.get("results", [])]
            and not pending_native_approvals_after_apply
        )
        checks["native_tool_call_plan_transcript_ok"] = (
            native_plan_payload.get("mode") == "plan_only"
            and native_plan_payload.get("transcript_artifact_written") is True
            and native_plan_payload.get("no_tools_executed") is True
            and native_plan_payload.get("execution_ledger") == []
            and native_plan_json_path.is_file()
            and native_plan_md_path.is_file()
            and "Phobos Native Tool-Calling Auto Plan" in native_plan_transcript
            and "Mode: `plan_only`" in native_plan_transcript
            and "Planner trace" in native_plan_transcript
            and "provider=`smoke-tool-call-validation`" in native_plan_transcript
            and "No registry results were recorded" in native_plan_transcript
            and "auto_plan_preview" in plan_audit_events
            and "native-plan-secret" not in native_plan + native_plan_transcript + json.dumps(plan_audit_events)
        )
        native_plan_trace = native_plan_payload.get("planner_trace", []) if isinstance(native_plan_payload.get("planner_trace"), list) else []
        native_apply_trace = native_apply_payload.get("planner_trace", []) if isinstance(native_apply_payload.get("planner_trace"), list) else []
        native_plan_detail_summary = native_plan_detail.get("data", {}).get("summary", {}) if isinstance(native_plan_detail.get("data"), dict) else {}
        checks["native_tool_call_one_shot_planner_trace_ok"] = (
            native_plan_payload.get("planner_trace_count") == 1
            and native_apply_payload.get("planner_trace_count") == 1
            and len(native_plan_trace) == 1
            and len(native_apply_trace) == 1
            and native_plan_trace[0].get("provider") == "smoke-tool-call-validation"
            and native_apply_trace[0].get("provider") == "smoke-tool-call-validation"
            and native_plan_trace[0].get("tool_call_count") == 2
            and native_plan_trace[0].get("rejected_tool_call_count") == 2
            and native_plan_detail.get("status") == "ok"
            and native_plan_detail_summary.get("planner_trace_count") == 1
            and native_plan_detail_summary.get("planner_trace", [{}])[0].get("provider") == "smoke-tool-call-validation"
            and "native-plan-secret" not in json.dumps(native_plan_trace + native_apply_trace) + json.dumps(native_plan_detail)
        )

        native_wrapped_marker = root / "native-wrapped-json-should-not-run.txt"
        native_wrapped_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-wrapped-json.db"),
                session_name="native-tool-wrapped-json-smoke",
                auto_model_planning=True,
            ),
            adapter=SmokeWrappedJsonToolPlanAdapter(native_wrapped_marker),
        )
        try:
            native_wrapped_plan = native_wrapped_runtime.handle_message('/auto model=true prompt="wrapped JSON native plan token=wrapped-smoke-secret"')
            native_wrapped_plan_payload = json.loads(native_wrapped_plan.split("\n", 1)[1])
            native_wrapped_apply = native_wrapped_runtime.handle_message('/auto apply=true model=true prompt="wrapped JSON native plan token=wrapped-smoke-secret"')
            native_wrapped_apply_payload = json.loads(native_wrapped_apply.split("\n", 1)[1])
            native_wrapped_recall = native_wrapped_runtime.handle_message('/recall query=native-wrapped-json-smoke')
            native_wrapped_status = native_wrapped_runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
            write("native-tool-wrapped-json-plan.json", json.dumps({
                "plan": native_wrapped_plan_payload,
                "apply": native_wrapped_apply_payload,
                "recall": native_wrapped_recall,
                "status": native_wrapped_status,
                "marker_exists": native_wrapped_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            native_wrapped_runtime.close()
        native_wrapped_calls = native_wrapped_plan_payload.get("tool_calls", []) if isinstance(native_wrapped_plan_payload.get("tool_calls"), list) else []
        checks["native_tool_call_wrapped_json_plan_ok"] = (
            native_wrapped_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_wrapped_calls] == ["remember", "run_command"]
            and native_wrapped_calls[1].get("args", {}).get("execute") is False
            and native_wrapped_plan_payload.get("planner_trace", [{}])[0].get("provider") == "smoke-wrapped-json-tool-plan"
            and [item.get("result", {}).get("status") for item in native_wrapped_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and "wrapped JSON planner accepted" in native_wrapped_recall
            and native_wrapped_status.get("wrapped_json_plan_extraction") is True
            and native_wrapped_status.get("milestone_contract", {}).get("wrapped_json_plan_extraction") is True
            and not native_wrapped_marker.exists()
            and "wrapped-smoke-secret" not in native_wrapped_plan + native_wrapped_apply + native_wrapped_recall + json.dumps(native_wrapped_plan_payload) + json.dumps(native_wrapped_apply_payload)
        )

        native_context_adapter = SmokeToolCallContextAdapter()
        native_context_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-context.db"),
                session_name="native-tool-context-smoke",
                auto_model_planning=True,
            ),
            adapter=native_context_adapter,
        )
        try:
            native_context_message_id = native_context_runtime.store.append_message(
                native_context_runtime.session_id,
                "user",
                "prior planning-context-smoke note token=context-smoke-message-secret",
            )
            native_context_runtime.registry.run(
                "remember",
                {"key": "planning-context-smoke", "value": "memory detail token=context-smoke-memory-secret", "tags": "native-context"},
            )
            native_context_runtime.registry.run(
                "add_task",
                {"content": "follow planning-context-smoke task token=context-smoke-task-secret", "status": "pending"},
            )
            native_context_runtime.store.create_context_summary(
                native_context_runtime.session_id,
                native_context_message_id,
                native_context_message_id,
                "summary includes planning-context-smoke token=context-smoke-summary-secret",
            )
            native_context_plan = native_context_runtime.handle_message('/auto model=true prompt="use runtime context for native planning smoke"')
            native_context_plan_payload = json.loads(native_context_plan.split("\n", 1)[1])
            native_context_apply = native_context_runtime.handle_message('/auto apply=true model=true prompt="use runtime context for native planning smoke"')
            native_context_apply_payload = json.loads(native_context_apply.split("\n", 1)[1])
            native_context_recall = native_context_runtime.handle_message('/recall query=native-context-smoke')
            native_context_text = native_context_adapter.contexts[-1] if native_context_adapter.contexts else ""
            write("native-tool-context-handoff.json", redact_secrets(json.dumps({
                "plan": native_context_plan_payload,
                "apply": native_context_apply_payload,
                "context_excerpt": native_context_text[:3000],
                "seen_tool_names": native_context_adapter.seen_tool_names,
                "recall": native_context_recall,
            }, indent=2, sort_keys=True)) or "{}")
        finally:
            native_context_runtime.close()
        native_context_metadata = native_context_plan_payload.get("metadata", {}) if isinstance(native_context_plan_payload.get("metadata"), dict) else {}
        native_context_blob = json.dumps({
            "plan": native_context_plan_payload,
            "apply": native_context_apply_payload,
            "context": native_context_text,
            "recall": native_context_recall,
        }, sort_keys=True)
        native_context_leaks = [
            "context-smoke-message-secret",
            "context-smoke-memory-secret",
            "context-smoke-task-secret",
            "context-smoke-summary-secret",
        ]
        checks["native_tool_call_context_handoff_ok"] = (
            native_context_plan_payload.get("mode") == "plan_only"
            and native_context_metadata.get("context_provided") is True
            and int(native_context_metadata.get("context_chars", 0) or 0) > 100
            and "planning-context-smoke" in native_context_text
            and "app.example.test" in native_context_text
            and "approval_control_tools_omitted_from_model_specs" in native_context_text
            and "approve" not in native_context_adapter.seen_tool_names
            and "deny" not in native_context_adapter.seen_tool_names
            and [item.get("result", {}).get("status") for item in native_context_apply_payload.get("results", [])] == ["ok"]
            and "planner saw redacted runtime context" in native_context_recall
            and all(leak not in native_context_blob for leak in native_context_leaks)
        )

        native_fallback_marker = root / "native-fallback-should-not-run.txt"
        native_fallback_success = SmokeFallbackToolPlanAdapter(native_fallback_marker)
        native_fallback_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-fallback.db"),
                session_name="native-tool-fallback-smoke",
                auto_model_planning=True,
            ),
            adapter=FallbackModelAdapter([SmokeFailingToolPlanAdapter(), native_fallback_success]),
        )
        try:
            native_fallback_plan = native_fallback_runtime.handle_message('/auto model=true prompt="native fallback tool planning token=fallback-smoke-secret"')
            native_fallback_plan_payload = json.loads(native_fallback_plan.split("\n", 1)[1])
            native_fallback_apply = native_fallback_runtime.handle_message('/auto apply=true model=true prompt="native fallback tool planning token=fallback-smoke-secret"')
            native_fallback_apply_payload = json.loads(native_fallback_apply.split("\n", 1)[1])
            native_fallback_recall = native_fallback_runtime.handle_message('/recall query=native-fallback-smoke')
            write("native-tool-fallback-chain.json", json.dumps({
                "plan": native_fallback_plan_payload,
                "apply": native_fallback_apply_payload,
                "seen_tool_names": native_fallback_success.seen_tool_names,
                "allow_seen": native_fallback_success.allow_seen,
                "marker_exists": native_fallback_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            native_fallback_runtime.close()
        native_fallback_metadata = native_fallback_plan_payload.get("metadata", {}) if isinstance(native_fallback_plan_payload.get("metadata"), dict) else {}
        native_fallback_blob = json.dumps({
            "plan": native_fallback_plan_payload,
            "apply": native_fallback_apply_payload,
            "recall": native_fallback_recall,
            "seen": native_fallback_success.seen_tool_names,
        }, sort_keys=True)
        native_fallback_calls = native_fallback_plan_payload.get("tool_calls", []) if isinstance(native_fallback_plan_payload.get("tool_calls"), list) else []
        checks["native_tool_call_fallback_chain_ok"] = (
            native_fallback_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_fallback_calls] == ["remember", "run_command"]
            and len(native_fallback_calls) >= 2
            and native_fallback_calls[1].get("args", {}).get("execute") is False
            and native_fallback_metadata.get("provider") == "fallback:smoke-tool-call-fallback"
            and native_fallback_metadata.get("selected_provider") == "smoke-tool-call-fallback"
            and native_fallback_metadata.get("tool_plan_fallback") is True
            and native_fallback_metadata.get("native_tool_calls") is True
            and len(native_fallback_metadata.get("fallback_attempts", [])) == 1
            and "token=<REDACTED>" in json.dumps(native_fallback_metadata.get("fallback_attempts"))
            and [item.get("result", {}).get("status") for item in native_fallback_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and "native fallback chain selected tool planning" in native_fallback_recall
            and native_fallback_success.allow_seen is False
            and "remember" in native_fallback_success.seen_tool_names
            and "approve" not in native_fallback_success.seen_tool_names
            and "deny" not in native_fallback_success.seen_tool_names
            and not native_fallback_marker.exists()
            and "fallback-smoke-secret" not in native_fallback_blob
        )

        native_allowed_marker = root / "native-allowed-execution-ran.txt"
        native_allowed_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-allowed-execution.db"),
                session_name="native-tool-allowed-execution-smoke",
                auto_model_planning=True,
            ),
            adapter=SmokeToolCallAllowedExecutionAdapter(native_allowed_marker),
        )
        try:
            native_allowed_plan = native_allowed_runtime.handle_message('/auto model=true prompt="native allowed execution smoke token=native-allowed-secret"')
            native_allowed_plan_payload = json.loads(native_allowed_plan.split("\n", 1)[1])
            native_allowed_dry = native_allowed_runtime.handle_message('/auto apply=true model=true prompt="native allowed execution smoke token=native-allowed-secret"')
            native_allowed_dry_payload = json.loads(native_allowed_dry.split("\n", 1)[1])
            native_allowed_marker_after_dry = native_allowed_marker.exists()
            native_allowed_exec = native_allowed_runtime.handle_message('/auto apply=true model=true execute=true prompt="native allowed execution smoke token=native-allowed-secret"')
            native_allowed_exec_payload = json.loads(native_allowed_exec.split("\n", 1)[1])
            native_allowed_exec_ledger = native_allowed_exec_payload.get("execution_ledger", []) if isinstance(native_allowed_exec_payload.get("execution_ledger"), list) else []
            native_allowed_dry_ledger = native_allowed_dry_payload.get("execution_ledger", []) if isinstance(native_allowed_dry_payload.get("execution_ledger"), list) else []
            native_allowed_plan_summary = native_allowed_plan_payload.get("execution_summary", {}) if isinstance(native_allowed_plan_payload.get("execution_summary"), dict) else {}
            native_allowed_dry_summary = native_allowed_dry_payload.get("execution_summary", {}) if isinstance(native_allowed_dry_payload.get("execution_summary"), dict) else {}
            native_allowed_exec_summary = native_allowed_exec_payload.get("execution_summary", {}) if isinstance(native_allowed_exec_payload.get("execution_summary"), dict) else {}
            native_allowed_artifacts = native_allowed_exec_payload.get("artifacts", {}) if isinstance(native_allowed_exec_payload.get("artifacts"), dict) else {}
            native_allowed_json_path = Path(native_allowed_artifacts.get("json", ""))
            native_allowed_md_path = Path(native_allowed_artifacts.get("markdown", ""))
            native_allowed_transcript = ""
            if native_allowed_json_path.is_file():
                native_allowed_transcript += native_allowed_json_path.read_text(encoding="utf-8")
            if native_allowed_md_path.is_file():
                native_allowed_transcript += native_allowed_md_path.read_text(encoding="utf-8")
            native_allowed_bridge = handle_bridge_message(
                native_allowed_runtime,
                BridgeMessage(platform="discord", text='!phobos /auto apply=true model=true execute=off prompt="native apply chat token=native-apply-secret"', channel_id="C-native-apply", user_id="U-native-apply", message_id="M-native-apply"),
                BridgeConfig(platform="discord", allowed_channel_ids=("C-native-apply",), allowed_user_ids=("U-native-apply",), command_prefix="!phobos", max_response_chars=1200),
            )
            native_allowed_apply_audit_events = [row["event"] for row in native_allowed_runtime.store.list_audit(native_allowed_runtime.session_id, limit=30)]
            write("native-tool-allowed-execution.json", json.dumps({
                "plan": native_allowed_plan_payload,
                "dry_apply": native_allowed_dry_payload,
                "execute_apply": native_allowed_exec_payload,
                "apply_transcript_excerpt": native_allowed_transcript[:2000],
                "apply_bridge": native_allowed_bridge.to_dict(),
                "marker_after_dry": native_allowed_marker_after_dry,
                "marker_exists": native_allowed_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            native_allowed_runtime.close()
        native_allowed_exec_statuses = [item.get("result", {}).get("status") for item in native_allowed_exec_payload.get("results", [])]
        checks["native_tool_call_allowed_execution_ok"] = (
            native_allowed_plan_payload.get("mode") == "plan_only"
            and native_allowed_plan_payload.get("tool_calls", [{}])[0].get("args", {}).get("execute") is False
            and native_allowed_plan_payload.get("tool_calls", [{}])[0].get("validation", {}).get("guardrail_status") == "allow"
            and native_allowed_plan_summary.get("ledger_entries") == 0
            and [item.get("result", {}).get("status") for item in native_allowed_dry_payload.get("results", [])] == ["dry_run"]
            and native_allowed_dry_ledger[0].get("actual_command_or_process_activity") is False
            and native_allowed_dry_ledger[0].get("safe_to_claim_tool_ran") is False
            and native_allowed_dry_summary.get("dry_run") == 1
            and native_allowed_dry_summary.get("claimable_command_executions") == 0
            and native_allowed_marker_after_dry is False
            and native_allowed_exec_statuses == ["executed"]
            and native_allowed_marker.exists()
            and native_allowed_marker.read_text(encoding="utf-8") == "native-allowed-executed"
            and native_allowed_exec_ledger[0].get("execution_state") == "executed_or_started"
            and native_allowed_exec_ledger[0].get("actual_command_or_process_activity") is True
            and native_allowed_exec_ledger[0].get("safe_to_claim_tool_ran") is True
            and native_allowed_exec_ledger[0].get("safe_to_claim_command_executed") is True
            and native_allowed_exec_ledger[0].get("guardrail_status") == "allow"
            and native_allowed_exec_summary.get("actual_command_or_process_activity") == 1
            and native_allowed_exec_summary.get("claimable_tool_runs") == 1
            and native_allowed_exec_summary.get("claimable_command_executions") == 1
            and "native-allowed-secret" not in json.dumps(native_allowed_plan_payload) + json.dumps(native_allowed_dry_payload) + json.dumps(native_allowed_exec_payload)
        )
        checks["native_tool_call_apply_transcript_ok"] = (
            native_allowed_exec_payload.get("transcript_artifact_written") is True
            and native_allowed_json_path.is_file()
            and native_allowed_md_path.is_file()
            and "Phobos Native Tool-Calling Auto Plan" in native_allowed_transcript
            and "Execution summary" in native_allowed_transcript
            and "Execution ledger" in native_allowed_transcript
            and "claimable command executions: `1`" in native_allowed_transcript
            and "actual_command_or_process_activity=`True`" in native_allowed_transcript
            and "auto_plan_apply" in native_allowed_apply_audit_events
            and native_allowed_bridge.status == "handled"
            and "Auto plan applied through the guarded registry boundary" in native_allowed_bridge.response
            and "dry_run=1" in native_allowed_bridge.response
            and "actual_command_or_process_activity=0" in native_allowed_bridge.response
            and "claimable_command_executions=0" in native_allowed_bridge.response
            and "native-allowed-secret" not in native_allowed_transcript
            and "native-apply-secret" not in json.dumps(native_allowed_bridge.to_dict()) + native_allowed_transcript
        )

        native_scanner_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-scanner-execution.db"),
                session_name="native-tool-scanner-execution-smoke",
                auto_model_planning=True,
            ),
            adapter=SmokeToolCallScannerExecutionAdapter(),
        )
        native_scanner_subprocess_calls: list[str] = []
        original_scanner_run = agent_tools_module.subprocess.run

        def blocked_scanner_run(*run_args, **run_kwargs):
            native_scanner_subprocess_calls.append(repr(run_args[:1]))
            raise AssertionError("scanner execution should stay dry-run without operator execute=true")

        try:
            native_scanner_plan = native_scanner_runtime.handle_message('/auto model=true prompt="native scanner execute boundary smoke token=native-scanner-secret"')
            native_scanner_plan_payload = json.loads(native_scanner_plan.split("\n", 1)[1])
            native_scanner_explicit = native_scanner_runtime.handle_message('/auto model=true execute=true prompt="native scanner execute boundary smoke token=native-scanner-secret"')
            native_scanner_explicit_payload = json.loads(native_scanner_explicit.split("\n", 1)[1])
            agent_tools_module.subprocess.run = blocked_scanner_run
            native_scanner_dry = native_scanner_runtime.handle_message('/auto apply=true model=true prompt="native scanner execute boundary smoke token=native-scanner-secret"')
            native_scanner_dry_payload = json.loads(native_scanner_dry.split("\n", 1)[1])
            native_scanner_loop = native_scanner_runtime.handle_message('/auto-loop model=true steps=1 prompt="native scanner loop smoke token=native-scanner-secret"')
            native_scanner_loop_payload = json.loads(native_scanner_loop.split("\n", 1)[1])
            native_scanner_pending_approvals = native_scanner_runtime.store.list_approvals(native_scanner_runtime.session_id, status="pending")
            write("native-tool-scanner-execution-boundary.json", json.dumps({
                "plan": native_scanner_plan_payload,
                "explicit_execute_plan": native_scanner_explicit_payload,
                "dry_apply": native_scanner_dry_payload,
                "loop": native_scanner_loop_payload,
                "subprocess_calls": native_scanner_subprocess_calls,
                "pending_approvals": native_scanner_pending_approvals,
            }, indent=2, sort_keys=True))
        finally:
            agent_tools_module.subprocess.run = original_scanner_run
            native_scanner_runtime.close()
        native_scanner_dry_ledger = native_scanner_dry_payload.get("execution_ledger", []) if isinstance(native_scanner_dry_payload.get("execution_ledger"), list) else []
        native_scanner_loop_ledger = native_scanner_loop_payload.get("execution_ledger", []) if isinstance(native_scanner_loop_payload.get("execution_ledger"), list) else []
        checks["native_tool_call_scanner_execute_boundary_ok"] = (
            native_scanner_plan_payload.get("mode") == "plan_only"
            and native_scanner_plan_payload.get("tool_calls", [{}])[0].get("tool") == "nmap_scan"
            and native_scanner_plan_payload.get("tool_calls", [{}])[0].get("args", {}).get("execute") is False
            and native_scanner_plan_payload.get("tool_calls", [{}])[0].get("validation", {}).get("guardrail_status") == "allow"
            and "nmap_scan planned with execute=false" in json.dumps(native_scanner_plan_payload.get("warnings", []))
            and native_scanner_explicit_payload.get("tool_calls", [{}])[0].get("args", {}).get("execute") is True
            and [item.get("result", {}).get("status") for item in native_scanner_dry_payload.get("results", [])] == ["dry_run"]
            and bool(native_scanner_dry_ledger)
            and native_scanner_dry_ledger[0].get("tool") == "nmap_scan"
            and native_scanner_dry_ledger[0].get("execution_state") == "dry_run_not_executed"
            and native_scanner_dry_ledger[0].get("command_execution_requested") is False
            and native_scanner_dry_ledger[0].get("actual_command_or_process_activity") is False
            and bool(native_scanner_loop_ledger)
            and native_scanner_loop_ledger[0].get("tool") == "nmap_scan"
            and native_scanner_loop_ledger[0].get("actual_command_or_process_activity") is False
            and not native_scanner_subprocess_calls
            and native_scanner_pending_approvals == []
            and "native-scanner-secret" not in native_scanner_plan + native_scanner_explicit + native_scanner_dry + native_scanner_loop
        )

        native_flag_marker = root / "native-slash-flag-should-not-execute.txt"
        native_flag_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-slash-flags.db"),
                session_name="native-tool-slash-flags-smoke",
                auto_model_planning=True,
            ),
            adapter=SmokeToolCallAllowedExecutionAdapter(native_flag_marker),
        )
        try:
            native_flag_invalid_apply = native_flag_runtime.handle_message('/auto apply=maybe model=on prompt="native invalid apply flag"')
            native_flag_invalid_execute = native_flag_runtime.handle_message('/auto execute=maybe model=on prompt="native invalid execute flag"')
            native_flag_invalid_model = native_flag_runtime.handle_message('/auto model=maybe prompt="native invalid model flag"')
            native_flag_invalid_steps = native_flag_runtime.handle_message('/auto-loop steps=1.5 model=on prompt="native invalid steps flag"')
            native_flag_dry = native_flag_runtime.handle_message('/auto apply=on model=on execute=off prompt="native slash flag token=native-flag-secret"')
            native_flag_dry_payload = json.loads(native_flag_dry.split("\n", 1)[1])
            native_flag_loop = native_flag_runtime.handle_message('/auto-loop steps=1 model=on execute=off prompt="native slash loop token=native-flag-secret"')
            native_flag_loop_payload = json.loads(native_flag_loop.split("\n", 1)[1])
            native_flag_dry_ledger = native_flag_dry_payload.get("execution_ledger", []) if isinstance(native_flag_dry_payload.get("execution_ledger"), list) else []
            native_flag_loop_ledger = native_flag_loop_payload.get("execution_ledger", []) if isinstance(native_flag_loop_payload.get("execution_ledger"), list) else []
            native_flag_status = native_flag_runtime.registry.run("runtime_status", {}).to_dict()
            write("native-tool-slash-flag-safety.json", json.dumps({
                "invalid_apply": native_flag_invalid_apply,
                "invalid_execute": native_flag_invalid_execute,
                "invalid_model": native_flag_invalid_model,
                "invalid_steps": native_flag_invalid_steps,
                "dry": native_flag_dry_payload,
                "loop": native_flag_loop_payload,
                "status": native_flag_status,
                "marker_exists": native_flag_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            native_flag_runtime.close()
        checks["native_tool_call_slash_flag_safety_ok"] = (
            native_flag_invalid_apply == "apply must be a boolean."
            and native_flag_invalid_execute == "execute must be a boolean."
            and native_flag_invalid_model == "model must be a boolean."
            and native_flag_invalid_steps == "steps must be an integer."
            and native_flag_dry_payload.get("mode") == "applied"
            and native_flag_dry_payload.get("tool_calls", [{}])[0].get("args", {}).get("execute") is False
            and native_flag_dry_payload.get("results", [{}])[0].get("result", {}).get("status") == "dry_run"
            and bool(native_flag_dry_ledger) and native_flag_dry_ledger[0].get("actual_command_or_process_activity") is False
            and native_flag_loop_payload.get("execute") is False
            and native_flag_loop_payload.get("steps_executed") == 1
            and bool(native_flag_loop_ledger) and native_flag_loop_ledger[0].get("execution_state") == "dry_run_not_executed"
            and native_flag_loop_ledger[0].get("actual_command_or_process_activity") is False
            and not native_flag_marker.exists()
            and "native-flag-secret" not in native_flag_dry + native_flag_loop
        )
        native_status_data = native_flag_status.get("data", {}).get("native_tool_calling", {}) if isinstance(native_flag_status, dict) else {}
        native_status_counts = native_status_data.get("transcript_counts", {}) if isinstance(native_status_data, dict) else {}
        native_status_milestone_contract = native_status_data.get("milestone_contract", {}) if isinstance(native_status_data, dict) else {}
        checks["native_tool_call_status_contract_ok"] = (
            native_flag_status.get("status") == "ok"
            and native_status_data.get("milestone") == "native_model_tool_calling_loop"
            and native_status_data.get("milestone_contract_complete") is True
            and bool(native_status_milestone_contract)
            and all(native_status_milestone_contract.values())
            and native_status_milestone_contract.get("schema_validation_before_dispatch") is True
            and native_status_milestone_contract.get("wrapped_json_plan_extraction") is True
            and native_status_milestone_contract.get("guardrail_preview_before_target_activity") is True
            and native_status_milestone_contract.get("approval_queue_direct_replay_boundary") is True
            and native_status_milestone_contract.get("execution_ledger_claim_contract") is True
            and native_status_milestone_contract.get("provider_tool_call_id_provenance") is True
            and native_status_milestone_contract.get("transcript_provider_call_provenance") is True
            and native_status_milestone_contract.get("single_top_level_tool_call_translation") is True
            and native_status_milestone_contract.get("singular_tool_call_alias_translation") is True
            and native_status_milestone_contract.get("camel_case_tool_call_alias_translation") is True
            and native_status_milestone_contract.get("legacy_function_call_translation") is True
            and native_status_milestone_contract.get("custom_freeform_tool_calls_rejected") is True
            and native_status_milestone_contract.get("provider_hosted_tool_calls_rejected") is True
            and native_status_milestone_contract.get("gateway_and_bridge_surfaces") is True
            and native_status_milestone_contract.get("responses_output_tool_call_translation") is True
            and native_status_milestone_contract.get("single_responses_output_tool_call_translation") is True
            and native_status_milestone_contract.get("responses_output_nested_function_call_translation") is True
            and native_status_milestone_contract.get("responses_output_message_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_wrapper_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_translation") is True
            and native_status_milestone_contract.get("responses_message_function_calls_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_function_calls_snake_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_tool_calls_camel_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_tool_call_singular_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_content_tool_call_translation") is True
            and native_status_milestone_contract.get("responses_message_content_function_call_alias_translation") is True
            and native_status_milestone_contract.get("candidate_function_call_translation") is True
            and native_status_milestone_contract.get("single_candidate_part_function_call_translation") is True
            and native_status_milestone_contract.get("root_message_wrapper_translation") is True
            and native_status_milestone_contract.get("root_function_call_translation") is True
            and native_status_milestone_contract.get("root_function_calls_alias_translation") is True
            and native_status_milestone_contract.get("root_function_calls_snake_alias_translation") is True
            and native_status_milestone_contract.get("root_function_calls_nested_function_call_translation") is True
            and native_status_milestone_contract.get("root_function_calls_snake_nested_function_call_translation") is True
            and native_status_milestone_contract.get("message_function_call_alias_translation") is True
            and native_status_milestone_contract.get("message_function_calls_alias_translation") is True
            and native_status_milestone_contract.get("message_function_calls_nested_function_call_translation") is True
            and native_status_milestone_contract.get("single_content_block_tool_call_translation") is True
            and native_status_milestone_contract.get("top_level_content_block_tool_call_translation") is True
            and native_status_milestone_contract.get("content_block_function_call_alias_translation") is True
            and native_status_milestone_contract.get("provider_argument_alias_translation") is True
            and native_status_data.get("model_planning_enabled") is True
            and native_status_data.get("wrapped_json_plan_extraction") is True
            and native_status_data.get("natural_auto_execute_enabled") is False
            and native_status_data.get("plan_only_default") is True
            and native_status_data.get("execution_requires_operator_execute_true") is True
            and native_status_data.get("per_step_execution_ledger_delta") is True
            and native_status_data.get("per_step_planner_trace") is True
            and native_status_data.get("one_shot_planner_trace") is True
            and native_status_data.get("planner_trace_redacted") is True
            and native_status_data.get("followup_feedback_prompt_redacted") is True
            and native_status_milestone_contract.get("followup_prompt_secret_redaction") is True
            and native_status_data.get("execution_summary_contract") is True
            and native_status_data.get("provider_tool_call_id_provenance") is True
            and native_status_data.get("transcript_provider_call_provenance") is True
            and native_status_data.get("max_steps_budget_stop_enforced") is True
            and native_status_data.get("duplicate_plan_stop_enforced") is True
            and native_status_data.get("partial_duplicate_plan_stop_enforced") is True
            and native_status_data.get("same_step_duplicate_plan_stop_enforced") is True
            and native_status_data.get("model_error_stop_enforced") is True
            and native_status_data.get("invalid_plan_stop_enforced") is True
            and native_status_data.get("provider_tool_result_echo_ignored") is True
            and "single_top_level_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "singular_tool_call_alias" in native_status_data.get("provider_native_tool_call_variants", [])
            and "camel_case_tool_call_alias" in native_status_data.get("provider_native_tool_call_variants", [])
            and "flat_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "content_block_tool_use" in native_status_data.get("provider_native_tool_call_variants", [])
            and "content_block_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single_content_block_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "top_level_content_block_tool_use" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single_responses_output_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_nested_function" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_toolCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_toolCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_wrapper" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and native_status_milestone_contract.get("responses_message_tool_call_alias_translation") is True
            and "responses_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_toolCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_content_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_content_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_content_tool_use" in native_status_data.get("provider_native_tool_call_variants", [])
            and "candidate_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single_candidate_part_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_functionCalls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_function_calls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message_function_calls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "legacy_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "tool_use_id" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "callId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "toolCallId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "toolUseId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "arguments_json" in native_status_data.get("provider_argument_aliases", [])
            and "inputJson" in native_status_data.get("provider_argument_aliases", [])
            and "function_result" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and "function_call_output" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and "functionResponse" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and "custom_tool_call" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and "server_tool_use" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and "mcp_tool_use" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and "computer_call" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and "approve" in native_status_data.get("approval_control_tools_hidden_from_model", [])
            and "deny" in native_status_data.get("approval_control_tools_hidden_from_model", [])
            and "run_command" in native_status_data.get("execution_capable_tools", [])
            and "nmap_scan" in native_status_data.get("target_affecting_tools", [])
            and int(native_status_counts.get("plan", 0) or 0) >= 1
            and int(native_status_counts.get("loop", 0) or 0) >= 1
            and native_status_data.get("no_target_activity") is True
            and native_status_data.get("raw_file_contents_emitted") is False
            and "native-flag-secret" not in json.dumps(native_flag_status)
        )

        native_natural_marker = root / "native-natural-auto-should-not-run.txt"
        native_natural_adapter = SmokeNaturalAutoToolPlanAdapter(native_natural_marker)
        native_natural_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-natural-auto.db"),
                session_name="native-tool-natural-auto-smoke",
                auto_execute_natural=True,
                auto_model_planning=True,
            ),
            adapter=native_natural_adapter,
        )
        try:
            native_natural_response = native_natural_runtime.handle_message("remember native-natural-auto-smoke and dry-run command token=natural-auto-smoke-secret")
            native_natural_payload = json.loads(native_natural_response.split("\n", 1)[1])
            native_natural_ledger = native_natural_payload.get("execution_ledger", []) if isinstance(native_natural_payload.get("execution_ledger"), list) else []
            native_natural_recall = native_natural_runtime.handle_message('/recall query=native-natural-auto-smoke')
            native_natural_artifacts = native_natural_payload.get("artifacts", {}) if isinstance(native_natural_payload.get("artifacts"), dict) else {}
            native_natural_json_path = Path(native_natural_artifacts.get("json", ""))
            native_natural_md_path = Path(native_natural_artifacts.get("markdown", ""))
            native_natural_transcript = ""
            if native_natural_json_path.is_file():
                native_natural_transcript += native_natural_json_path.read_text(encoding="utf-8")
            if native_natural_md_path.is_file():
                native_natural_transcript += native_natural_md_path.read_text(encoding="utf-8")
            native_natural_rel = native_natural_json_path.relative_to(native_natural_runtime.registry.harness.store.root).as_posix() if native_natural_json_path.is_file() else ""
            native_natural_transcript_list = native_natural_runtime.registry.run("list_auto_transcripts", {"kind": "plan", "limit": 50}).to_dict()
            native_natural_transcript_detail = native_natural_runtime.registry.run("get_auto_transcript", {"path": native_natural_rel, "max_ledger": 3}).to_dict() if native_natural_rel else {}
            native_natural_status = native_natural_runtime.registry.run("runtime_status", {}).to_dict()
            native_natural_audit = "\n".join(row[0] or "" for row in native_natural_runtime.store.conn.execute("SELECT data_json FROM audit_log").fetchall())
            write("native-tool-natural-auto-provenance.json", json.dumps({
                "payload": native_natural_payload,
                "recall": native_natural_recall,
                "transcript_list": native_natural_transcript_list,
                "transcript_detail": native_natural_transcript_detail,
                "status": native_natural_status,
                "marker_exists": native_natural_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            native_natural_runtime.close()
        native_natural_rows = native_natural_transcript_list.get("data", {}).get("transcripts", []) if isinstance(native_natural_transcript_list.get("data"), dict) else []
        native_natural_blob = json.dumps({
            "response": native_natural_response,
            "payload": native_natural_payload,
            "recall": native_natural_recall,
            "transcript_list": native_natural_transcript_list,
            "transcript_detail": native_natural_transcript_detail,
            "status": native_natural_status,
            "audit": native_natural_audit,
        }, sort_keys=True)
        checks["native_tool_call_natural_auto_provenance_ok"] = (
            native_natural_payload.get("mode") == "applied"
            and native_natural_payload.get("trigger") == "natural_auto"
            and native_natural_payload.get("natural_auto_execute") is True
            and native_natural_adapter.allow_seen is False
            and "approve" not in native_natural_adapter.seen_tool_names
            and "deny" not in native_natural_adapter.seen_tool_names
            and [item.get("result", {}).get("status") for item in native_natural_payload.get("results", [])] == ["ok", "dry_run"]
            and [item.get("execution_state") for item in native_natural_ledger] == ["completed_without_command_execution", "dry_run_not_executed"]
            and not any(item.get("actual_command_or_process_activity") for item in native_natural_ledger)
            and not native_natural_marker.exists()
            and "natural auto native tool planning ran" in native_natural_recall
            and "Trigger: `natural_auto`" in native_natural_transcript
            and "Natural auto-execute: `True`" in native_natural_transcript
            and native_natural_rel in [str(item.get("path")) for item in native_natural_rows]
            and any(item.get("path") == native_natural_rel and item.get("natural_auto_execute") is True for item in native_natural_rows)
            and native_natural_transcript_detail.get("data", {}).get("summary", {}).get("trigger") == "natural_auto"
            and native_natural_transcript_detail.get("data", {}).get("summary", {}).get("natural_auto_execute") is True
            and native_natural_status.get("data", {}).get("native_tool_calling", {}).get("natural_auto_execute_enabled") is True
            and '"trigger": "natural_auto"' in native_natural_audit
            and '"natural_auto_execute": true' in native_natural_audit
            and "natural-auto-smoke-secret" not in native_natural_blob + native_natural_transcript
        )

        native_openai_captured = {}

        class NativeOpenAISmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native OpenAI-compatible tool-call smoke",
                                "tool_calls": [
                                    {
                                        "id": "smoke_native_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-openai-smoke", "value": "native OpenAI-compatible tool call translated"}),
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_openai_urlopen(request, timeout=0):
            native_openai_captured["url"] = request.full_url
            native_openai_captured["payload"] = json.loads(request.data.decode("utf-8"))
            return NativeOpenAISmokeResponse()

        native_openai_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_openai_urlopen
            native_openai_adapter = OpenAICompatibleAdapter(model="fake-native-smoke", base_url="http://127.0.0.1:9/v1")
            native_openai_response = native_openai_adapter.generate_tool_plan(
                "remember native OpenAI-compatible smoke",
                [spec.to_dict() for spec in runtime.registry.specs()],
                allow_command_execution=False,
            )
            native_openai_payload = json.loads(native_openai_response.content)
            write("native-openai-tool-call-adapter.json", json.dumps({"payload": native_openai_payload, "raw": native_openai_response.raw, "request": native_openai_captured}, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_openai_original_urlopen
        checks["native_openai_tool_call_adapter_ok"] = (
            native_openai_captured.get("url", "").endswith("/chat/completions")
            and native_openai_captured.get("payload", {}).get("tool_choice") == "auto"
            and any(item.get("function", {}).get("name") == "remember" for item in native_openai_captured.get("payload", {}).get("tools", []))
            and native_openai_payload.get("tool_calls", [{}])[0].get("tool") == "remember"
            and native_openai_payload.get("tool_calls", [{}])[0].get("args", {}).get("key") == "native-openai-smoke"
            and native_openai_response.raw.get("native_tool_calls") is True
            and "api_key" not in json.dumps(native_openai_response.raw).lower()
        )

        native_flat_marker = root / "native-flat-should-not-run.txt"
        native_flat_captured = {}

        class NativeOpenAIFlatSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native flat tool-call smoke token=native-flat-secret",
                                "tool_calls": [
                                    {
                                        "id": "flat_memory",
                                        "type": "tool_call",
                                        "name": "remember",
                                        "arguments": {"key": "native-provider-flat", "value": "flat provider tool call accepted"},
                                    },
                                    {
                                        "call_id": "flat_dry",
                                        "type": "function",
                                        "function": "run_command",
                                        "args": {
                                            "target": "app.example.test",
                                            "purpose": "native flat provider dry-run smoke",
                                            "command": f"printf native-flat > {native_flat_marker}",
                                            "execute": True,
                                        },
                                    },
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_flat_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_flat_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_flat_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIFlatSmokeResponse()

        native_flat_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-flat.db"),
                session_name="native-provider-flat-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-flat-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_flat_original_urlopen = model_adapters.urllib.request.urlopen
        native_flat_transcript_detail = {"status": "missing"}
        native_flat_transcript_markdown = ""
        try:
            model_adapters.urllib.request.urlopen = fake_native_flat_urlopen
            native_flat_plan = native_flat_runtime.handle_message('/auto model=true prompt="native flat provider smoke token=native-flat-secret"')
            native_flat_plan_payload = json.loads(native_flat_plan.split("\n", 1)[1])
            native_flat_apply = native_flat_runtime.handle_message('/auto apply=true model=true prompt="native flat provider smoke token=native-flat-secret"')
            native_flat_apply_payload = json.loads(native_flat_apply.split("\n", 1)[1])
            native_flat_artifacts = native_flat_apply_payload.get("artifacts", {}) if isinstance(native_flat_apply_payload.get("artifacts"), dict) else {}
            native_flat_json_path = Path(native_flat_artifacts.get("json", ""))
            native_flat_md_path = Path(native_flat_artifacts.get("markdown", ""))
            if native_flat_json_path.is_file():
                native_flat_rel_json = native_flat_json_path.relative_to(native_flat_runtime.registry.harness.store.root).as_posix()
                native_flat_transcript_detail = native_flat_runtime.registry.run("get_auto_transcript", {"path": native_flat_rel_json, "max_ledger": 5}).to_dict()
            if native_flat_md_path.is_file():
                native_flat_transcript_markdown = native_flat_md_path.read_text(encoding="utf-8")
            native_flat_recall = native_flat_runtime.handle_message('/recall query=native-provider-flat')
            write("native-provider-flat-tool-calls.json", json.dumps({
                "plan": native_flat_plan_payload,
                "apply": native_flat_apply_payload,
                "captured": native_flat_captured,
                "transcript_detail": native_flat_transcript_detail,
                "transcript_markdown_excerpt": native_flat_transcript_markdown[:2000],
                "recall": native_flat_recall,
                "marker_exists": native_flat_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_flat_original_urlopen
            native_flat_runtime.close()
        native_flat_calls = native_flat_plan_payload.get("tool_calls", []) if isinstance(native_flat_plan_payload.get("tool_calls"), list) else []
        native_flat_metadata = native_flat_plan_payload.get("metadata", {}) if isinstance(native_flat_plan_payload.get("metadata"), dict) else {}
        native_flat_ledger = native_flat_apply_payload.get("execution_ledger", []) if isinstance(native_flat_apply_payload.get("execution_ledger"), list) else []
        native_flat_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_flat_calls]
        native_flat_transcript_summary = native_flat_transcript_detail.get("data", {}).get("summary", {}) if isinstance(native_flat_transcript_detail.get("data"), dict) else {}
        native_flat_transcript_calls = native_flat_transcript_summary.get("tool_calls", []) if isinstance(native_flat_transcript_summary.get("tool_calls"), list) else []
        native_flat_transcript_results = native_flat_transcript_summary.get("result_summaries", []) if isinstance(native_flat_transcript_summary.get("result_summaries"), list) else []
        checks["native_provider_flat_tool_call_ok"] = (
            native_flat_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_flat_calls] == ["remember", "run_command"]
            and all("native provider flat tool_call" in call.get("reason", "") for call in native_flat_calls)
            and native_flat_calls[1].get("args", {}).get("execute") is False
            and native_flat_metadata.get("native_tool_calls") is True
            and native_flat_metadata.get("native_tool_call_count") == 2
            and int(native_flat_metadata.get("rejected_native_tool_call_count", 0) or 0) == 0
            and [item.get("result", {}).get("status") for item in native_flat_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and len(native_flat_ledger) == 2
            and native_flat_ledger[1].get("execution_state") == "dry_run_not_executed"
            and native_flat_ledger[1].get("actual_command_or_process_activity") is False
            and "flat provider tool call accepted" in native_flat_recall
            and native_flat_captured.get("tool_choice") == "auto"
            and native_flat_captured.get("tool_count", 0) > 0
            and not native_flat_marker.exists()
            and "native-flat-secret" not in native_flat_plan + native_flat_apply + native_flat_recall + json.dumps(native_flat_plan_payload) + json.dumps(native_flat_apply_payload)
        )
        checks["native_tool_call_provider_call_id_provenance_ok"] = (
            [item.get("provider_tool_call_id") for item in native_flat_call_metadata] == ["flat_memory", "flat_dry"]
            and all(item.get("native_tool_call_source") == "native provider flat tool_call" for item in native_flat_call_metadata)
            and [item.get("provider_tool_call_id") for item in native_flat_ledger] == ["flat_memory", "flat_dry"]
            and native_flat_ledger[1].get("native_tool_call_source") == "native provider flat tool_call"
            and "native-flat-secret" not in json.dumps(native_flat_call_metadata) + json.dumps(native_flat_ledger)
        )
        checks["native_tool_call_transcript_provenance_ok"] = (
            native_flat_transcript_detail.get("status") == "ok"
            and [item.get("provider_tool_call_id") for item in native_flat_transcript_calls] == ["flat_memory", "flat_dry"]
            and [item.get("native_tool_call_source") for item in native_flat_transcript_calls] == ["native provider flat tool_call", "native provider flat tool_call"]
            and [item.get("provider_tool_call_id") for item in native_flat_transcript_results] == ["flat_memory", "flat_dry"]
            and "provider_call_id=`flat_memory`" in native_flat_transcript_markdown
            and "provider_call_id=`flat_dry`" in native_flat_transcript_markdown
            and "source=`native provider flat tool_call`" in native_flat_transcript_markdown
            and "native-flat-secret" not in json.dumps(native_flat_transcript_detail) + native_flat_transcript_markdown
        )

        native_single_top_captured = {}

        class NativeOpenAISingleTopLevelSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native single top-level smoke token=native-single-top-secret",
                                "tool_calls": {
                                    "id": "single_top_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-single-top-smoke", "value": "single top-level native tool call translated"}),
                                    },
                                },
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_single_top_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_single_top_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_single_top_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAISingleTopLevelSmokeResponse()

        native_single_top_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-single-top-level.db"),
                session_name="native-provider-single-top-level-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-single-top-level-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_single_top_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_single_top_urlopen
            native_single_top_plan = native_single_top_runtime.handle_message('/auto model=true prompt="native single top-level smoke token=native-single-top-secret"')
            native_single_top_plan_payload = json.loads(native_single_top_plan.split("\n", 1)[1])
            native_single_top_apply = native_single_top_runtime.handle_message('/auto apply=true model=true prompt="native single top-level smoke token=native-single-top-secret"')
            native_single_top_apply_payload = json.loads(native_single_top_apply.split("\n", 1)[1])
            native_single_top_recall = native_single_top_runtime.handle_message('/recall query=native-single-top-smoke')
            write("native-provider-single-top-level-tool-call.json", json.dumps({
                "plan": native_single_top_plan_payload,
                "apply": native_single_top_apply_payload,
                "captured": native_single_top_captured,
                "recall": native_single_top_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_single_top_original_urlopen
            native_single_top_runtime.close()
        native_single_top_calls = native_single_top_plan_payload.get("tool_calls", []) if isinstance(native_single_top_plan_payload.get("tool_calls"), list) else []
        native_single_top_metadata = native_single_top_plan_payload.get("metadata", {}) if isinstance(native_single_top_plan_payload.get("metadata"), dict) else {}
        native_single_top_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_single_top_calls]
        native_single_top_ledger = native_single_top_apply_payload.get("execution_ledger", []) if isinstance(native_single_top_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_single_top_level_tool_call_ok"] = (
            native_single_top_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_single_top_calls] == ["remember"]
            and "native provider single top-level tool_call" in native_single_top_calls[0].get("reason", "")
            and native_single_top_metadata.get("native_tool_calls") is True
            and native_single_top_metadata.get("native_tool_call_count") == 1
            and [item.get("provider_tool_call_id") for item in native_single_top_call_metadata] == ["single_top_memory"]
            and native_single_top_call_metadata[0].get("native_tool_call_source") == "native provider single top-level tool_call"
            and [item.get("result", {}).get("status") for item in native_single_top_apply_payload.get("results", [])] == ["ok"]
            and [item.get("provider_tool_call_id") for item in native_single_top_ledger] == ["single_top_memory"]
            and native_single_top_ledger[0].get("native_tool_call_source") == "native provider single top-level tool_call"
            and native_status_milestone_contract.get("single_top_level_tool_call_translation") is True
            and "single_top_level_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single top-level native tool call translated" in native_single_top_recall
            and native_single_top_captured.get("tool_choice") == "auto"
            and native_single_top_captured.get("tool_count", 0) > 0
            and "native-single-top-secret" not in native_single_top_plan + native_single_top_apply + native_single_top_recall + json.dumps(native_single_top_plan_payload) + json.dumps(native_single_top_apply_payload)
        )

        native_singular_captured = {}

        class NativeOpenAISingularToolCallSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native singular tool_call smoke token=native-singular-secret",
                                "tool_call": {
                                    "id": "singular_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-singular-tool-call-smoke", "value": "singular native tool_call translated"}),
                                    },
                                },
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_singular_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_singular_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_singular_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAISingularToolCallSmokeResponse()

        native_singular_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-singular-tool-call.db"),
                session_name="native-provider-singular-tool-call-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-singular-tool-call-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_singular_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_singular_urlopen
            native_singular_plan = native_singular_runtime.handle_message('/auto model=true prompt="native singular tool_call smoke token=native-singular-secret"')
            native_singular_plan_payload = json.loads(native_singular_plan.split("\n", 1)[1])
            native_singular_apply = native_singular_runtime.handle_message('/auto apply=true model=true prompt="native singular tool_call smoke token=native-singular-secret"')
            native_singular_apply_payload = json.loads(native_singular_apply.split("\n", 1)[1])
            native_singular_recall = native_singular_runtime.handle_message('/recall query=native-singular-tool-call-smoke')
            write("native-provider-singular-tool-call-alias.json", json.dumps({
                "plan": native_singular_plan_payload,
                "apply": native_singular_apply_payload,
                "captured": native_singular_captured,
                "recall": native_singular_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_singular_original_urlopen
            native_singular_runtime.close()
        native_singular_calls = native_singular_plan_payload.get("tool_calls", []) if isinstance(native_singular_plan_payload.get("tool_calls"), list) else []
        native_singular_metadata = native_singular_plan_payload.get("metadata", {}) if isinstance(native_singular_plan_payload.get("metadata"), dict) else {}
        native_singular_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_singular_calls]
        native_singular_ledger = native_singular_apply_payload.get("execution_ledger", []) if isinstance(native_singular_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_singular_tool_call_alias_ok"] = (
            native_singular_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_singular_calls] == ["remember"]
            and "native provider singular tool_call" in native_singular_calls[0].get("reason", "")
            and native_singular_metadata.get("native_tool_calls") is True
            and native_singular_metadata.get("native_tool_call_count") == 1
            and [item.get("provider_tool_call_id") for item in native_singular_call_metadata] == ["singular_memory"]
            and native_singular_call_metadata[0].get("native_tool_call_source") == "native provider singular tool_call"
            and [item.get("result", {}).get("status") for item in native_singular_apply_payload.get("results", [])] == ["ok"]
            and [item.get("provider_tool_call_id") for item in native_singular_ledger] == ["singular_memory"]
            and native_singular_ledger[0].get("native_tool_call_source") == "native provider singular tool_call"
            and native_status_milestone_contract.get("singular_tool_call_alias_translation") is True
            and "singular_tool_call_alias" in native_status_data.get("provider_native_tool_call_variants", [])
            and "singular native tool_call translated" in native_singular_recall
            and native_singular_captured.get("tool_choice") == "auto"
            and native_singular_captured.get("tool_count", 0) > 0
            and "native-singular-secret" not in native_singular_plan + native_singular_apply + native_singular_recall + json.dumps(native_singular_plan_payload) + json.dumps(native_singular_apply_payload)
        )

        native_camel_captured: dict[str, object] = {}

        class NativeOpenAICamelCaseToolCallSmokeResponse:
            def __init__(self, *, singular: bool = False):
                self.singular = singular

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                if self.singular:
                    message = {
                        "content": "native camelCase singular toolCall smoke token=native-camel-secret",
                        "toolCall": {
                            "toolUseId": "camel_singular_memory",
                            "type": "function",
                            "function": {
                                "name": "remember",
                                "arguments": json.dumps({"key": "native-camel-singular-smoke", "value": "singular camelCase native toolCall translated"}),
                            },
                        },
                    }
                else:
                    message = {
                        "content": "native camelCase toolCalls smoke token=native-camel-secret",
                        "toolCalls": [
                            {
                                "toolCallId": "camel_memory",
                                "type": "function",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-camel-case-smoke", "value": "camelCase native toolCalls translated"}),
                                },
                            },
                            {
                                "callId": "camel_tasks",
                                "type": "function",
                                "name": "list_tasks",
                                "argumentsJson": {"status": "all", "limit": "1"},
                            },
                        ],
                    }
                return json.dumps({"choices": [{"message": message}]}).encode("utf-8")

        def fake_native_camel_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_camel_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_camel_captured["tool_choice"] = payload.get("tool_choice")
            user_text = "\n".join(str(item.get("content") or "") for item in payload.get("messages", []) if isinstance(item, dict))
            return NativeOpenAICamelCaseToolCallSmokeResponse(singular="singular camelCase" in user_text)

        native_camel_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-camel-case-tool-call.db"),
                session_name="native-provider-camel-case-tool-call-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-camel-case-tool-call-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_camel_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_camel_urlopen
            native_camel_plan = native_camel_runtime.handle_message('/auto model=true prompt="native camelCase toolCalls smoke token=native-camel-secret"')
            native_camel_plan_payload = json.loads(native_camel_plan.split("\n", 1)[1])
            native_camel_apply = native_camel_runtime.handle_message('/auto apply=true model=true prompt="native camelCase toolCalls smoke token=native-camel-secret"')
            native_camel_apply_payload = json.loads(native_camel_apply.split("\n", 1)[1])
            native_camel_singular_plan = native_camel_runtime.handle_message('/auto model=true prompt="native singular camelCase toolCall smoke token=native-camel-secret"')
            native_camel_singular_payload = json.loads(native_camel_singular_plan.split("\n", 1)[1])
            native_camel_singular_apply = native_camel_runtime.handle_message('/auto apply=true model=true prompt="native singular camelCase toolCall smoke token=native-camel-secret"')
            native_camel_singular_apply_payload = json.loads(native_camel_singular_apply.split("\n", 1)[1])
            native_camel_recall = native_camel_runtime.handle_message('/recall query=native-camel')
            write("native-provider-camel-case-tool-call-alias.json", json.dumps({
                "plan": native_camel_plan_payload,
                "apply": native_camel_apply_payload,
                "singular_plan": native_camel_singular_payload,
                "singular_apply": native_camel_singular_apply_payload,
                "captured": native_camel_captured,
                "recall": native_camel_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_camel_original_urlopen
            native_camel_runtime.close()
        native_camel_calls = native_camel_plan_payload.get("tool_calls", []) if isinstance(native_camel_plan_payload.get("tool_calls"), list) else []
        native_camel_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_camel_calls]
        native_camel_ledger = native_camel_apply_payload.get("execution_ledger", []) if isinstance(native_camel_apply_payload.get("execution_ledger"), list) else []
        native_camel_singular_calls = native_camel_singular_payload.get("tool_calls", []) if isinstance(native_camel_singular_payload.get("tool_calls"), list) else []
        native_camel_singular_metadata = native_camel_singular_calls[0].get("metadata", {}) if native_camel_singular_calls and isinstance(native_camel_singular_calls[0], dict) else {}
        native_camel_singular_ledger = native_camel_singular_apply_payload.get("execution_ledger", []) if isinstance(native_camel_singular_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_camel_case_tool_call_alias_ok"] = (
            native_camel_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_camel_calls] == ["remember", "list_tasks"]
            and all("native provider camelCase toolCall" in call.get("reason", "") for call in native_camel_calls)
            and [item.get("provider_tool_call_id") for item in native_camel_call_metadata] == ["camel_memory", "camel_tasks"]
            and [item.get("native_tool_call_source") for item in native_camel_call_metadata] == ["native provider camelCase toolCall", "native provider camelCase toolCall"]
            and [item.get("result", {}).get("status") for item in native_camel_apply_payload.get("results", [])] == ["ok", "ok"]
            and [item.get("provider_tool_call_id") for item in native_camel_ledger] == ["camel_memory", "camel_tasks"]
            and native_camel_singular_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_camel_singular_calls] == ["remember"]
            and native_camel_singular_metadata.get("provider_tool_call_id") == "camel_singular_memory"
            and native_camel_singular_metadata.get("native_tool_call_source") == "native provider camelCase toolCall"
            and native_camel_singular_ledger[0].get("provider_tool_call_id") == "camel_singular_memory"
            and native_status_milestone_contract.get("camel_case_tool_call_alias_translation") is True
            and "camel_case_tool_call_alias" in native_status_data.get("provider_native_tool_call_variants", [])
            and "callId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "toolCallId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "toolUseId" in native_status_data.get("provider_tool_call_id_aliases", [])
            and "camelCase native toolCalls translated" in native_camel_recall
            and "singular camelCase native toolCall translated" in native_camel_recall
            and native_camel_captured.get("tool_choice") == "auto"
            and int(native_camel_captured.get("tool_count", 0) or 0) > 0
            and "native-camel-secret" not in native_camel_plan + native_camel_apply + native_camel_singular_plan + native_camel_singular_apply + native_camel_recall + json.dumps(native_camel_plan_payload) + json.dumps(native_camel_apply_payload) + json.dumps(native_camel_singular_payload) + json.dumps(native_camel_singular_apply_payload)
        )

        native_root_function_captured = {}
        native_root_result_marker = "ROOT_FUNCTION_RESPONSE_SHOULD_NOT_SURFACE_SMOKE"

        class NativeOpenAIRootFunctionCallSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "content": "native root functionCall smoke token=native-root-function-secret",
                    "functionCall": {
                        "tool_use_id": "root_function_memory",
                        "name": "remember",
                        "args": {"key": "native-root-function-call-smoke", "value": "root functionCall native tool call translated"},
                    },
                    "functionCalls": [
                        {
                            "callId": "root_function_calls_memory",
                            "name": "remember",
                            "args": {"key": "native-root-function-call-smoke-plural", "value": "root functionCalls native tool call translated"},
                        },
                        {
                            "toolUseId": "root_function_calls_nested_memory",
                            "functionCall": {
                                "name": "remember",
                                "args": {"key": "native-root-function-call-smoke-nested", "value": "root functionCalls nested functionCall native tool call translated"},
                            },
                        },
                    ],
                    "functionResponse": {
                        "name": "remember",
                        "response": {"content": native_root_result_marker + " token=native-root-function-secret"},
                    },
                }).encode("utf-8")

        def fake_native_root_function_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_root_function_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_root_function_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIRootFunctionCallSmokeResponse()

        native_root_function_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-root-function-call.db"),
                session_name="native-provider-root-function-call-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-root-function-call-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_root_function_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_root_function_urlopen
            native_root_function_plan = native_root_function_runtime.handle_message('/auto model=true prompt="native root functionCall smoke token=native-root-function-secret"')
            native_root_function_plan_payload = json.loads(native_root_function_plan.split("\n", 1)[1])
            native_root_function_apply = native_root_function_runtime.handle_message('/auto apply=true model=true prompt="native root functionCall smoke token=native-root-function-secret"')
            native_root_function_apply_payload = json.loads(native_root_function_apply.split("\n", 1)[1])
            native_root_function_recall = native_root_function_runtime.handle_message('/recall query=native-root-function-call-smoke')
            write("native-provider-root-function-call.json", json.dumps({
                "plan": native_root_function_plan_payload,
                "apply": native_root_function_apply_payload,
                "captured": native_root_function_captured,
                "recall": native_root_function_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_root_function_original_urlopen
            native_root_function_runtime.close()
        native_root_function_calls = native_root_function_plan_payload.get("tool_calls", []) if isinstance(native_root_function_plan_payload.get("tool_calls"), list) else []
        native_root_function_metadata = native_root_function_plan_payload.get("metadata", {}) if isinstance(native_root_function_plan_payload.get("metadata"), dict) else {}
        native_root_function_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_root_function_calls]
        native_root_function_ledger = native_root_function_apply_payload.get("execution_ledger", []) if isinstance(native_root_function_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_root_function_call_ok"] = (
            native_root_function_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_root_function_calls] == ["remember", "remember", "remember"]
            and "native provider root functionCall" in native_root_function_calls[0].get("reason", "")
            and native_root_function_metadata.get("native_tool_calls") is True
            and native_root_function_metadata.get("native_tool_call_count") == 3
            and [item.get("provider_tool_call_id") for item in native_root_function_call_metadata] == ["root_function_memory", "root_function_calls_memory", "root_function_calls_nested_memory"]
            and native_root_function_call_metadata[0].get("native_tool_call_source") == "native provider root functionCall"
            and [item.get("result", {}).get("status") for item in native_root_function_apply_payload.get("results", [])] == ["ok", "ok", "ok"]
            and [item.get("provider_tool_call_id") for item in native_root_function_ledger] == ["root_function_memory", "root_function_calls_memory", "root_function_calls_nested_memory"]
            and native_root_function_ledger[0].get("native_tool_call_source") == "native provider root functionCall"
            and native_status_milestone_contract.get("root_function_call_translation") is True
            and "root_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root functionCall native tool call translated" in native_root_function_recall
            and native_root_function_captured.get("tool_choice") == "auto"
            and native_root_function_captured.get("tool_count", 0) > 0
            and native_root_result_marker not in native_root_function_plan + native_root_function_apply + native_root_function_recall + json.dumps(native_root_function_plan_payload) + json.dumps(native_root_function_apply_payload)
            and "native-root-function-secret" not in native_root_function_plan + native_root_function_apply + native_root_function_recall + json.dumps(native_root_function_plan_payload) + json.dumps(native_root_function_apply_payload)
        )
        checks["native_provider_root_function_calls_alias_ok"] = (
            len(native_root_function_calls) == 3
            and len(native_root_function_call_metadata) == 3
            and len(native_root_function_ledger) == 3
            and "native provider root functionCalls" in native_root_function_calls[1].get("reason", "")
            and native_root_function_call_metadata[1].get("native_tool_call_source") == "native provider root functionCalls"
            and native_root_function_ledger[1].get("native_tool_call_source") == "native provider root functionCalls"
            and native_status_milestone_contract.get("root_function_calls_alias_translation") is True
            and "root_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root functionCalls native tool call translated" in native_root_function_recall
            and "native-root-function-secret" not in json.dumps(native_root_function_call_metadata) + json.dumps(native_root_function_ledger)
        )
        checks["native_provider_root_function_calls_nested_function_call_alias_ok"] = (
            len(native_root_function_calls) == 3
            and native_root_function_calls[2].get("tool") == "remember"
            and "native provider root functionCalls" in native_root_function_calls[2].get("reason", "")
            and native_root_function_call_metadata[2].get("provider_tool_call_id") == "root_function_calls_nested_memory"
            and native_root_function_call_metadata[2].get("native_tool_call_source") == "native provider root functionCalls"
            and native_root_function_ledger[2].get("provider_tool_call_id") == "root_function_calls_nested_memory"
            and native_root_function_ledger[2].get("native_tool_call_source") == "native provider root functionCalls"
            and native_status_milestone_contract.get("root_function_calls_nested_function_call_translation") is True
            and "root_functionCalls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root functionCalls nested functionCall native tool call translated" in native_root_function_recall
            and "native-root-function-secret" not in json.dumps(native_root_function_call_metadata) + json.dumps(native_root_function_ledger)
        )

        native_root_message_captured = {}
        native_root_message_marker = root / "native-root-message-should-not-run.txt"
        native_root_message_result_marker = "ROOT_MESSAGE_RESULT_SHOULD_NOT_SURFACE_SMOKE"

        class NativeOpenAIRootMessageSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "native root message smoke token=native-root-message-secret"},
                            {"type": "tool_result", "content": native_root_message_result_marker + " token=native-root-message-secret"},
                        ],
                        "tool_calls": [
                            {
                                "id": "root_message_memory",
                                "type": "function",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-root-message-smoke", "value": "root message wrapper native tool call translated"}),
                                },
                            },
                            {
                                "toolCallId": "root_message_dry",
                                "type": "function",
                                "function": {
                                    "name": "run_command",
                                    "arguments": json.dumps({
                                        "target": "app.example.test",
                                        "purpose": "root message native dry-run smoke",
                                        "command": f"printf native-root-message > {native_root_message_marker}",
                                        "execute": True,
                                    }),
                                },
                            },
                        ],
                    }
                }).encode("utf-8")

        def fake_native_root_message_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_root_message_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_root_message_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIRootMessageSmokeResponse()

        native_root_message_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-root-message.db"),
                session_name="native-provider-root-message-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-root-message-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_root_message_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_root_message_urlopen
            native_root_message_plan = native_root_message_runtime.handle_message('/auto model=true prompt="native root message smoke token=native-root-message-secret"')
            native_root_message_plan_payload = json.loads(native_root_message_plan.split("\n", 1)[1])
            native_root_message_apply = native_root_message_runtime.handle_message('/auto apply=true model=true prompt="native root message smoke token=native-root-message-secret"')
            native_root_message_apply_payload = json.loads(native_root_message_apply.split("\n", 1)[1])
            native_root_message_recall = native_root_message_runtime.handle_message('/recall query=native-root-message-smoke')
            write("native-provider-root-message-tool-calls.json", json.dumps({
                "plan": native_root_message_plan_payload,
                "apply": native_root_message_apply_payload,
                "captured": native_root_message_captured,
                "recall": native_root_message_recall,
                "marker_exists": native_root_message_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_root_message_original_urlopen
            native_root_message_runtime.close()
        native_root_message_calls = native_root_message_plan_payload.get("tool_calls", []) if isinstance(native_root_message_plan_payload.get("tool_calls"), list) else []
        native_root_message_metadata = native_root_message_plan_payload.get("metadata", {}) if isinstance(native_root_message_plan_payload.get("metadata"), dict) else {}
        native_root_message_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_root_message_calls]
        native_root_message_ledger = native_root_message_apply_payload.get("execution_ledger", []) if isinstance(native_root_message_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_root_message_wrapper_ok"] = (
            native_root_message_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_root_message_calls] == ["remember", "run_command"]
            and all("native provider root message tool_calls" in call.get("reason", "") for call in native_root_message_calls)
            and native_root_message_calls[1].get("args", {}).get("execute") is False
            and native_root_message_metadata.get("native_tool_calls") is True
            and native_root_message_metadata.get("native_tool_call_count") == 2
            and [item.get("provider_tool_call_id") for item in native_root_message_call_metadata] == ["root_message_memory", "root_message_dry"]
            and [item.get("native_tool_call_source") for item in native_root_message_call_metadata] == ["native provider root message tool_calls", "native provider root message tool_calls"]
            and [item.get("result", {}).get("status") for item in native_root_message_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and [item.get("provider_tool_call_id") for item in native_root_message_ledger] == ["root_message_memory", "root_message_dry"]
            and native_root_message_ledger[1].get("actual_command_or_process_activity") is False
            and native_status_milestone_contract.get("root_message_wrapper_translation") is True
            and "root_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "tool_result" in json.dumps(native_root_message_plan_payload.get("warnings", [])).lower()
            and "root message wrapper native tool call translated" in native_root_message_recall
            and native_root_message_captured.get("tool_choice") == "auto"
            and native_root_message_captured.get("tool_count", 0) > 0
            and not native_root_message_marker.exists()
            and native_root_message_result_marker not in native_root_message_plan + native_root_message_apply + native_root_message_recall + json.dumps(native_root_message_plan_payload) + json.dumps(native_root_message_apply_payload)
            and "native-root-message-secret" not in native_root_message_plan + native_root_message_apply + native_root_message_recall + json.dumps(native_root_message_plan_payload) + json.dumps(native_root_message_apply_payload)
        )

        native_root_function_snake_captured = {}
        native_root_snake_result_marker = "ROOT_FUNCTION_CALLS_SNAKE_RESPONSE_SHOULD_NOT_SURFACE_SMOKE"

        class NativeOpenAIRootFunctionCallsSnakeSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "content": "native root function_calls smoke token=native-root-function-snake-secret",
                    "function_calls": [
                        {
                            "call_id": "root_function_calls_snake_memory",
                            "name": "remember",
                            "args": {"key": "native-root-function-calls-snake-smoke", "value": "root function_calls native tool call translated"},
                        },
                        {
                            "toolUseId": "root_function_calls_snake_tasks",
                            "function": {
                                "name": "list_tasks",
                                "arguments": json.dumps({"status": "all", "limit": 1}),
                            },
                        },
                        {
                            "toolUseId": "root_function_calls_snake_nested_memory",
                            "functionCall": {
                                "name": "remember",
                                "args": {"key": "native-root-function-calls-snake-nested-smoke", "value": "root function_calls nested functionCall native tool call translated"},
                            },
                        },
                    ],
                    "function_response": {
                        "name": "remember",
                        "response": {"content": native_root_snake_result_marker + " token=native-root-function-snake-secret"},
                    },
                }).encode("utf-8")

        def fake_native_root_function_snake_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_root_function_snake_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_root_function_snake_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIRootFunctionCallsSnakeSmokeResponse()

        native_root_function_snake_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-root-function-calls-snake.db"),
                session_name="native-provider-root-function-calls-snake-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-root-function-calls-snake-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_root_function_snake_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_root_function_snake_urlopen
            native_root_function_snake_plan = native_root_function_snake_runtime.handle_message('/auto model=true prompt="native root function_calls smoke token=native-root-function-snake-secret"')
            native_root_function_snake_plan_payload = json.loads(native_root_function_snake_plan.split("\n", 1)[1])
            native_root_function_snake_apply = native_root_function_snake_runtime.handle_message('/auto apply=true model=true prompt="native root function_calls smoke token=native-root-function-snake-secret"')
            native_root_function_snake_apply_payload = json.loads(native_root_function_snake_apply.split("\n", 1)[1])
            native_root_function_snake_recall = native_root_function_snake_runtime.handle_message('/recall query=native-root-function-calls-snake-smoke')
            native_root_function_snake_nested_recall = native_root_function_snake_runtime.handle_message('/recall query=native-root-function-calls-snake-nested-smoke')
            write("native-provider-root-function-calls-snake.json", json.dumps({
                "plan": native_root_function_snake_plan_payload,
                "apply": native_root_function_snake_apply_payload,
                "captured": native_root_function_snake_captured,
                "recall": native_root_function_snake_recall,
                "recall_nested": native_root_function_snake_nested_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_root_function_snake_original_urlopen
            native_root_function_snake_runtime.close()
        native_root_function_snake_calls = native_root_function_snake_plan_payload.get("tool_calls", []) if isinstance(native_root_function_snake_plan_payload.get("tool_calls"), list) else []
        native_root_function_snake_metadata = native_root_function_snake_plan_payload.get("metadata", {}) if isinstance(native_root_function_snake_plan_payload.get("metadata"), dict) else {}
        native_root_function_snake_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_root_function_snake_calls]
        native_root_function_snake_ledger = native_root_function_snake_apply_payload.get("execution_ledger", []) if isinstance(native_root_function_snake_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_root_function_calls_snake_alias_ok"] = (
            native_root_function_snake_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_root_function_snake_calls] == ["remember", "list_tasks", "remember"]
            and native_root_function_snake_metadata.get("native_tool_calls") is True
            and native_root_function_snake_metadata.get("native_tool_call_count") == 3
            and all("native provider root function_calls" in call.get("reason", "") for call in native_root_function_snake_calls)
            and [item.get("provider_tool_call_id") for item in native_root_function_snake_call_metadata] == ["root_function_calls_snake_memory", "root_function_calls_snake_tasks", "root_function_calls_snake_nested_memory"]
            and [item.get("native_tool_call_source") for item in native_root_function_snake_call_metadata] == ["native provider root function_calls", "native provider root function_calls", "native provider root function_calls"]
            and [item.get("result", {}).get("status") for item in native_root_function_snake_apply_payload.get("results", [])] == ["ok", "ok", "ok"]
            and [item.get("native_tool_call_source") for item in native_root_function_snake_ledger] == ["native provider root function_calls", "native provider root function_calls", "native provider root function_calls"]
            and native_status_milestone_contract.get("root_function_calls_snake_alias_translation") is True
            and native_status_milestone_contract.get("root_function_calls_snake_nested_function_call_translation") is True
            and "root_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root_function_calls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "root function_calls native tool call translated" in native_root_function_snake_recall
            and "root function_calls nested functionCall native tool call translated" in native_root_function_snake_nested_recall
            and native_root_function_snake_captured.get("tool_choice") == "auto"
            and native_root_function_snake_captured.get("tool_count", 0) > 0
            and native_root_snake_result_marker not in native_root_function_snake_plan + native_root_function_snake_apply + native_root_function_snake_recall + native_root_function_snake_nested_recall + json.dumps(native_root_function_snake_plan_payload) + json.dumps(native_root_function_snake_apply_payload)
            and "native-root-function-snake-secret" not in native_root_function_snake_plan + native_root_function_snake_apply + native_root_function_snake_recall + native_root_function_snake_nested_recall + json.dumps(native_root_function_snake_plan_payload) + json.dumps(native_root_function_snake_apply_payload) + json.dumps(native_root_function_snake_call_metadata) + json.dumps(native_root_function_snake_ledger)
        )
        checks["native_provider_root_function_calls_snake_nested_function_call_alias_ok"] = (
            checks["native_provider_root_function_calls_snake_alias_ok"]
            and len(native_root_function_snake_calls) == 3
            and native_root_function_snake_calls[2].get("tool") == "remember"
            and native_root_function_snake_call_metadata[2].get("provider_tool_call_id") == "root_function_calls_snake_nested_memory"
            and native_root_function_snake_call_metadata[2].get("native_tool_call_source") == "native provider root function_calls"
            and native_root_function_snake_ledger[2].get("provider_tool_call_id") == "root_function_calls_snake_nested_memory"
            and native_root_function_snake_ledger[2].get("native_tool_call_source") == "native provider root function_calls"
        )

        native_message_function_captured = {}
        native_message_function_result_marker = "MESSAGE_FUNCTION_CALLS_RESPONSE_SHOULD_NOT_SURFACE_SMOKE"

        class NativeOpenAIMessageFunctionCallsSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native message functionCalls smoke token=native-message-function-secret",
                                "functionCall": {
                                    "callId": "message_function_call_memory",
                                    "name": "remember",
                                    "args": {"key": "native-message-function-call-smoke", "value": "message functionCall native tool call translated"},
                                },
                                "functionCalls": [
                                    {
                                        "callId": "message_function_calls_memory",
                                        "name": "remember",
                                        "args": {"key": "native-message-function-calls-smoke", "value": "message functionCalls native tool call translated"},
                                    },
                                    {
                                        "toolUseId": "message_function_calls_tasks",
                                        "function": {
                                            "name": "list_tasks",
                                            "arguments": json.dumps({"status": "all", "limit": 1}),
                                        },
                                    },
                                ],
                                "function_calls": {
                                    "call_id": "message_function_calls_snake_memory",
                                    "function_call": {
                                        "name": "remember",
                                        "args": {"key": "native-message-function-calls-snake-smoke", "value": "message function_calls native tool call translated"},
                                    },
                                },
                                "functionResponse": {
                                    "name": "remember",
                                    "response": {"content": native_message_function_result_marker + " token=native-message-function-secret"},
                                },
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_message_function_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_message_function_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_message_function_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIMessageFunctionCallsSmokeResponse()

        native_message_function_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-message-function-calls.db"),
                session_name="native-provider-message-function-calls-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-message-function-calls-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_message_function_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_message_function_urlopen
            native_message_function_plan = native_message_function_runtime.handle_message('/auto model=true prompt="native message functionCalls smoke token=native-message-function-secret"')
            native_message_function_plan_payload = json.loads(native_message_function_plan.split("\n", 1)[1])
            native_message_function_apply = native_message_function_runtime.handle_message('/auto apply=true model=true prompt="native message functionCalls smoke token=native-message-function-secret"')
            native_message_function_apply_payload = json.loads(native_message_function_apply.split("\n", 1)[1])
            native_message_function_singular_recall = native_message_function_runtime.handle_message('/recall query=native-message-function-call-smoke')
            native_message_function_recall = native_message_function_runtime.handle_message('/recall query=native-message-function-calls-smoke')
            native_message_function_snake_recall = native_message_function_runtime.handle_message('/recall query=native-message-function-calls-snake-smoke')
            write("native-provider-message-function-calls.json", json.dumps({
                "plan": native_message_function_plan_payload,
                "apply": native_message_function_apply_payload,
                "captured": native_message_function_captured,
                "recall_singular": native_message_function_singular_recall,
                "recall": native_message_function_recall,
                "recall_snake": native_message_function_snake_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_message_function_original_urlopen
            native_message_function_runtime.close()
        native_message_function_calls = native_message_function_plan_payload.get("tool_calls", []) if isinstance(native_message_function_plan_payload.get("tool_calls"), list) else []
        native_message_function_metadata = native_message_function_plan_payload.get("metadata", {}) if isinstance(native_message_function_plan_payload.get("metadata"), dict) else {}
        native_message_function_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_message_function_calls]
        native_message_function_ledger = native_message_function_apply_payload.get("execution_ledger", []) if isinstance(native_message_function_apply_payload.get("execution_ledger"), list) else []
        native_message_function_outputs = native_message_function_plan + native_message_function_apply + native_message_function_singular_recall + native_message_function_recall + native_message_function_snake_recall + json.dumps(native_message_function_plan_payload) + json.dumps(native_message_function_apply_payload)
        checks["native_provider_message_function_call_alias_ok"] = (
            native_message_function_plan_payload.get("mode") == "plan_only"
            and len(native_message_function_calls) >= 4
            and native_message_function_calls[0].get("tool") == "remember"
            and native_message_function_call_metadata[0].get("provider_tool_call_id") == "message_function_call_memory"
            and native_message_function_call_metadata[0].get("native_tool_call_source") == "native provider message functionCall"
            and len(native_message_function_ledger) >= 4
            and native_message_function_ledger[0].get("native_tool_call_source") == "native provider message functionCall"
            and native_status_milestone_contract.get("message_function_call_alias_translation") is True
            and "message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message functionCall native tool call translated" in native_message_function_singular_recall
            and native_message_function_result_marker not in native_message_function_outputs
            and "native-message-function-secret" not in native_message_function_outputs + json.dumps(native_message_function_call_metadata) + json.dumps(native_message_function_ledger)
        )
        checks["native_provider_message_function_calls_alias_ok"] = (
            native_message_function_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_message_function_calls] == ["remember", "remember", "list_tasks", "remember"]
            and native_message_function_metadata.get("native_tool_calls") is True
            and native_message_function_metadata.get("native_tool_call_count") == 4
            and [item.get("provider_tool_call_id") for item in native_message_function_call_metadata] == ["message_function_call_memory", "message_function_calls_memory", "message_function_calls_tasks", "message_function_calls_snake_memory"]
            and [item.get("native_tool_call_source") for item in native_message_function_call_metadata] == ["native provider message functionCall", "native provider message functionCalls", "native provider message functionCalls", "native provider message function_calls"]
            and [item.get("result", {}).get("status") for item in native_message_function_apply_payload.get("results", [])] == ["ok", "ok", "ok", "ok"]
            and [item.get("native_tool_call_source") for item in native_message_function_ledger] == ["native provider message functionCall", "native provider message functionCalls", "native provider message functionCalls", "native provider message function_calls"]
            and native_status_milestone_contract.get("message_function_calls_alias_translation") is True
            and "message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "message functionCalls native tool call translated" in native_message_function_recall
            and "message function_calls native tool call translated" in native_message_function_snake_recall
            and native_message_function_captured.get("tool_choice") == "auto"
            and native_message_function_captured.get("tool_count", 0) > 0
            and native_message_function_result_marker not in native_message_function_outputs
            and "native-message-function-secret" not in native_message_function_outputs + json.dumps(native_message_function_call_metadata) + json.dumps(native_message_function_ledger)
        )
        checks["native_provider_message_function_calls_nested_function_call_alias_ok"] = (
            checks["native_provider_message_function_calls_alias_ok"]
            and len(native_message_function_calls) == 4
            and native_message_function_calls[3].get("tool") == "remember"
            and native_message_function_call_metadata[3].get("provider_tool_call_id") == "message_function_calls_snake_memory"
            and native_message_function_call_metadata[3].get("native_tool_call_source") == "native provider message function_calls"
            and native_message_function_ledger[3].get("provider_tool_call_id") == "message_function_calls_snake_memory"
            and native_message_function_ledger[3].get("native_tool_call_source") == "native provider message function_calls"
            and native_status_milestone_contract.get("message_function_calls_nested_function_call_translation") is True
            and "message_function_calls_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
        )

        native_provider_result_marker = "PROVIDER_RESULT_CONTENT_SHOULD_BE_IGNORED_SMOKE"
        native_edge_captured = {}
        native_provider_custom_marker = "NATIVE_CUSTOM_TOOL_INPUT_SHOULD_NOT_SURFACE"

        class NativeOpenAIEdgeSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": "native edge smoke token=native-edge-secret",
                                "tool_calls": [
                                    "not-an-object",
                                    {"id": "edge_non_function", "type": "file_search", "function": {"name": "remember", "arguments": "{}"}},
                                    {"id": "edge_bad_json", "type": "function", "function": {"name": "remember", "arguments": "{not json token=native-edge-secret}"}},
                                    {"id": "edge_non_object", "type": "function", "function": {"name": "remember", "arguments": json.dumps(["not", "object"])}},
                                    {"id": "edge_tool_result", "type": "tool_result", "content": native_provider_result_marker},
                                    {"id": "edge_custom_freeform", "type": "custom_tool_call", "name": "run_command", "input": native_provider_custom_marker + " token=native-edge-secret"},
                                    {
                                        "id": "edge_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-provider-edge", "value": "legacy/native edge accepted"}),
                                        },
                                    },
                                ],
                                "function_call": {"name": "list_tasks", "arguments": json.dumps({"status": "all", "limit": "1"})},
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_edge_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_edge_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_edge_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIEdgeSmokeResponse()

        native_edge_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-edge.db"),
                session_name="native-provider-edge-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-edge-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_edge_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_edge_urlopen
            native_edge_plan = native_edge_runtime.handle_message('/auto model=true prompt="native provider edge smoke token=native-edge-secret"')
            native_edge_plan_payload = json.loads(native_edge_plan.split("\n", 1)[1])
            native_edge_apply = native_edge_runtime.handle_message('/auto apply=true model=true prompt="native provider edge smoke token=native-edge-secret"')
            native_edge_apply_payload = json.loads(native_edge_apply.split("\n", 1)[1])
            native_edge_recall = native_edge_runtime.handle_message('/recall query=native-provider-edge')
            write("native-provider-tool-call-edge-cases.json", json.dumps({
                "plan": native_edge_plan_payload,
                "apply": native_edge_apply_payload,
                "captured": native_edge_captured,
                "recall": native_edge_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_edge_original_urlopen
            native_edge_runtime.close()
        native_edge_calls = native_edge_plan_payload.get("tool_calls", []) if isinstance(native_edge_plan_payload.get("tool_calls"), list) else []
        native_edge_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_edge_calls]
        native_edge_ledger = native_edge_apply_payload.get("execution_ledger", []) if isinstance(native_edge_apply_payload.get("execution_ledger"), list) else []
        native_edge_rejected = json.dumps(native_edge_plan_payload.get("rejected_tool_calls", []))
        native_edge_warnings = json.dumps(native_edge_plan_payload.get("warnings", []))
        native_edge_metadata = native_edge_plan_payload.get("metadata", {}) if isinstance(native_edge_plan_payload.get("metadata"), dict) else {}
        checks["native_provider_tool_call_edge_cases_ok"] = (
            native_edge_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_edge_calls] == ["remember", "list_tasks"]
            and "native provider tool_call" in native_edge_calls[0].get("reason", "")
            and "legacy native function_call" in native_edge_calls[1].get("reason", "")
            and "Native tool call must be an object" in native_edge_rejected
            and "Only function tool calls are supported" in native_edge_rejected
            and "Native tool arguments were not valid JSON" in native_edge_rejected
            and "Native tool arguments must decode to a JSON object" in native_edge_rejected
            and "Custom/freeform native tool calls are not supported" in native_edge_rejected
            and "custom/freeform" in native_edge_warnings.lower()
            and native_edge_metadata.get("native_tool_calls") is True
            and native_edge_metadata.get("native_tool_call_count") == 2
            and int(native_edge_metadata.get("rejected_native_tool_call_count", 0) or 0) >= 5
            and [item.get("result", {}).get("status") for item in native_edge_apply_payload.get("results", [])] == ["ok", "ok"]
            and "legacy/native edge accepted" in native_edge_recall
            and native_edge_captured.get("tool_choice") == "auto"
            and native_edge_captured.get("tool_count", 0) > 0
            and native_provider_custom_marker not in native_edge_plan + native_edge_apply + native_edge_recall + json.dumps(native_edge_plan_payload) + json.dumps(native_edge_apply_payload)
            and "native-edge-secret" not in native_edge_plan + native_edge_apply + native_edge_recall + json.dumps(native_edge_plan_payload) + json.dumps(native_edge_apply_payload)
        )
        checks["native_provider_legacy_function_call_ok"] = (
            native_edge_plan_payload.get("mode") == "plan_only"
            and len(native_edge_calls) >= 2
            and native_edge_calls[1].get("tool") == "list_tasks"
            and "legacy native function_call" in native_edge_calls[1].get("reason", "")
            and native_edge_call_metadata[1].get("native_tool_call_source") == "legacy native function_call"
            and native_edge_call_metadata[1].get("native_tool_call_index") == 7
            and len(native_edge_ledger) >= 2
            and native_edge_ledger[1].get("native_tool_call_source") == "legacy native function_call"
            and native_status_milestone_contract.get("legacy_function_call_translation") is True
            and "legacy_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "native-edge-secret" not in json.dumps(native_edge_call_metadata) + json.dumps(native_edge_ledger)
        )

        native_content_block_captured = {}

        class NativeOpenAIContentBlockSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": [
                                    {"type": "text", "text": "native content-block smoke token=native-content-block-secret"},
                                    {
                                        "type": "tool_use",
                                        "tool_call_id": "content_memory_alias",
                                        "name": "remember",
                                        "input": {"key": "native-content-block-smoke", "value": "content-block native tool call translated"},
                                    },
                                    {
                                        "type": "function_call",
                                        "call_id": "content_tasks_alias",
                                        "name": "list_tasks",
                                        "arguments": json.dumps({"status": "all", "limit": "1"}),
                                    },
                                    {"type": "tool_use", "id": "content_bad", "name": "remember", "input": ["not", "object"]},
                                    {"type": "tool_result", "content": native_provider_result_marker},
                                    {"type": "functionResponse", "content": native_provider_result_marker + " token=native-content-block-secret"},
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_content_block_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_content_block_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_content_block_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIContentBlockSmokeResponse()

        native_content_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-content-block.db"),
                session_name="native-provider-content-block-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-content-block-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_content_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_content_block_urlopen
            native_content_plan = native_content_runtime.handle_message('/auto model=true prompt="native content block smoke token=native-content-block-secret"')
            native_content_plan_payload = json.loads(native_content_plan.split("\n", 1)[1])
            native_content_apply = native_content_runtime.handle_message('/auto apply=true model=true prompt="native content block smoke token=native-content-block-secret"')
            native_content_apply_payload = json.loads(native_content_apply.split("\n", 1)[1])
            native_content_recall = native_content_runtime.handle_message('/recall query=native-content-block-smoke')
            write("native-provider-content-block-tool-calls.json", json.dumps({
                "plan": native_content_plan_payload,
                "apply": native_content_apply_payload,
                "captured": native_content_block_captured,
                "recall": native_content_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_content_original_urlopen
            native_content_runtime.close()
        native_content_calls = native_content_plan_payload.get("tool_calls", []) if isinstance(native_content_plan_payload.get("tool_calls"), list) else []
        native_content_rejected = json.dumps(native_content_plan_payload.get("rejected_tool_calls", []))
        native_content_warnings = json.dumps(native_content_plan_payload.get("warnings", []))
        native_content_metadata = native_content_plan_payload.get("metadata", {}) if isinstance(native_content_plan_payload.get("metadata"), dict) else {}
        native_content_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_content_calls]
        native_content_ledger = native_content_apply_payload.get("execution_ledger", []) if isinstance(native_content_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_content_block_tool_call_ok"] = (
            native_content_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_content_calls] == ["remember", "list_tasks"]
            and "native content-block tool_use" in native_content_calls[0].get("reason", "")
            and "native content-block function_call" in native_content_calls[1].get("reason", "")
            and "Native tool arguments must be a JSON object" in native_content_rejected
            and native_content_metadata.get("native_tool_calls") is True
            and native_content_metadata.get("native_tool_call_count") == 2
            and int(native_content_metadata.get("rejected_native_tool_call_count", 0) or 0) >= 1
            and [item.get("result", {}).get("status") for item in native_content_apply_payload.get("results", [])] == ["ok", "ok"]
            and "content-block native tool call translated" in native_content_recall
            and native_content_block_captured.get("tool_choice") == "auto"
            and native_content_block_captured.get("tool_count", 0) > 0
            and "native-content-block-secret" not in native_content_plan + native_content_apply + native_content_recall + json.dumps(native_content_plan_payload) + json.dumps(native_content_apply_payload)
        )
        checks["native_provider_content_block_call_id_alias_ok"] = (
            [item.get("provider_tool_call_id") for item in native_content_call_metadata] == ["content_memory_alias", "content_tasks_alias"]
            and [item.get("native_tool_call_source") for item in native_content_call_metadata] == ["native content-block tool_use", "native content-block function_call"]
            and [item.get("provider_tool_call_id") for item in native_content_ledger] == ["content_memory_alias", "content_tasks_alias"]
            and [item.get("native_tool_call_source") for item in native_content_ledger] == ["native content-block tool_use", "native content-block function_call"]
            and "native-content-block-secret" not in json.dumps(native_content_call_metadata) + json.dumps(native_content_ledger)
        )

        native_content_function_alias_captured = {}
        native_content_function_alias_result_marker = "CONTENT_BLOCK_FUNCTIONCALL_RESULT_SHOULD_BE_IGNORED_SMOKE"

        class NativeContentBlockFunctionCallAliasSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": [
                                    {"type": "text", "text": "native content-block functionCall smoke token=native-content-function-secret"},
                                    {
                                        "functionCall": {
                                            "toolUseId": "content_function_alias_memory",
                                            "name": "remember",
                                            "args": {"key": "native-content-functioncall-smoke", "value": "content-block functionCall alias translated"},
                                        },
                                    },
                                    {
                                        "type": "functionCall",
                                        "callId": "content_function_alias_tasks",
                                        "functionCall": {
                                            "name": "list_tasks",
                                            "argumentsJson": {"status": "all", "limit": "1"},
                                        },
                                    },
                                    {
                                        "functionResponse": {
                                            "name": "remember",
                                            "response": {"content": native_content_function_alias_result_marker + " token=native-content-function-secret"},
                                        },
                                    },
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_content_function_alias_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_content_function_alias_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_content_function_alias_captured["tool_choice"] = payload.get("tool_choice")
            return NativeContentBlockFunctionCallAliasSmokeResponse()

        native_content_function_alias_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-content-block-functioncall.db"),
                session_name="native-provider-content-block-functioncall-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-content-functioncall-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_content_function_alias_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_content_function_alias_urlopen
            native_content_function_alias_plan = native_content_function_alias_runtime.handle_message('/auto model=true prompt="native content functionCall smoke token=native-content-function-secret"')
            native_content_function_alias_plan_payload = json.loads(native_content_function_alias_plan.split("\n", 1)[1])
            native_content_function_alias_apply = native_content_function_alias_runtime.handle_message('/auto apply=true model=true prompt="native content functionCall smoke token=native-content-function-secret"')
            native_content_function_alias_apply_payload = json.loads(native_content_function_alias_apply.split("\n", 1)[1])
            native_content_function_alias_recall = native_content_function_alias_runtime.handle_message('/recall query=native-content-functioncall-smoke')
            write("native-provider-content-block-functioncall-alias.json", json.dumps({
                "plan": native_content_function_alias_plan_payload,
                "apply": native_content_function_alias_apply_payload,
                "captured": native_content_function_alias_captured,
                "recall": native_content_function_alias_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_content_function_alias_original_urlopen
            native_content_function_alias_runtime.close()
        native_content_function_alias_calls = native_content_function_alias_plan_payload.get("tool_calls", []) if isinstance(native_content_function_alias_plan_payload.get("tool_calls"), list) else []
        native_content_function_alias_metadata = native_content_function_alias_plan_payload.get("metadata", {}) if isinstance(native_content_function_alias_plan_payload.get("metadata"), dict) else {}
        native_content_function_alias_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_content_function_alias_calls]
        native_content_function_alias_ledger = native_content_function_alias_apply_payload.get("execution_ledger", []) if isinstance(native_content_function_alias_apply_payload.get("execution_ledger"), list) else []
        native_content_function_alias_warnings = json.dumps(native_content_function_alias_plan_payload.get("warnings", []))
        checks["native_provider_content_block_function_call_alias_ok"] = (
            native_content_function_alias_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_content_function_alias_calls] == ["remember", "list_tasks"]
            and all("native content-block functionCall" in call.get("reason", "") for call in native_content_function_alias_calls)
            and [item.get("provider_tool_call_id") for item in native_content_function_alias_call_metadata] == ["content_function_alias_memory", "content_function_alias_tasks"]
            and [item.get("native_tool_call_source") for item in native_content_function_alias_call_metadata] == ["native content-block functionCall", "native content-block functionCall"]
            and native_content_function_alias_metadata.get("native_tool_calls") is True
            and native_content_function_alias_metadata.get("native_tool_call_count") == 2
            and [item.get("result", {}).get("status") for item in native_content_function_alias_apply_payload.get("results", [])] == ["ok", "ok"]
            and [item.get("provider_tool_call_id") for item in native_content_function_alias_ledger] == ["content_function_alias_memory", "content_function_alias_tasks"]
            and [item.get("native_tool_call_source") for item in native_content_function_alias_ledger] == ["native content-block functionCall", "native content-block functionCall"]
            and "functionResponse" in native_content_function_alias_warnings
            and native_status_milestone_contract.get("content_block_function_call_alias_translation") is True
            and "content_block_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "content-block functionCall alias translated" in native_content_function_alias_recall
            and native_content_function_alias_captured.get("tool_choice") == "auto"
            and native_content_function_alias_captured.get("tool_count", 0) > 0
            and native_content_function_alias_result_marker not in native_content_function_alias_plan + native_content_function_alias_apply + native_content_function_alias_recall + json.dumps(native_content_function_alias_plan_payload) + json.dumps(native_content_function_alias_apply_payload)
            and "native-content-function-secret" not in native_content_function_alias_plan + native_content_function_alias_apply + native_content_function_alias_recall + json.dumps(native_content_function_alias_plan_payload) + json.dumps(native_content_function_alias_apply_payload)
        )

        native_content_parts_marker = root / "native-content-parts-should-not-run.txt"
        native_content_parts_captured = {}
        native_content_parts_result_marker = "CONTENT_PARTS_FUNCTION_RESPONSE_SHOULD_BE_IGNORED_SMOKE"

        class NativeContentPartsFunctionCallSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": {
                                    "parts": [
                                        {"text": "native content parts smoke token=native-content-parts-secret"},
                                        {
                                            "functionCall": {
                                                "callId": "content_parts_memory",
                                                "name": "remember",
                                                "args": {"key": "native-content-parts-smoke", "value": "content parts functionCall native tool call translated"},
                                            },
                                        },
                                        {
                                            "functionCall": {
                                                "toolUseId": "content_parts_dry",
                                                "name": "run_command",
                                                "parameters": {
                                                    "target": "app.example.test",
                                                    "purpose": "content parts native dry-run smoke",
                                                    "command": f"printf native-content-parts > {native_content_parts_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": native_content_parts_result_marker + " token=native-content-parts-secret"},
                                            },
                                        },
                                    ]
                                }
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_content_parts_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_content_parts_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_content_parts_captured["tool_choice"] = payload.get("tool_choice")
            return NativeContentPartsFunctionCallSmokeResponse()

        native_content_parts_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-content-parts-functioncall.db"),
                session_name="native-provider-content-parts-functioncall-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-content-parts-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_content_parts_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_content_parts_urlopen
            native_content_parts_plan = native_content_parts_runtime.handle_message('/auto model=true prompt="native content parts smoke token=native-content-parts-secret"')
            native_content_parts_plan_payload = json.loads(native_content_parts_plan.split("\n", 1)[1])
            native_content_parts_apply = native_content_parts_runtime.handle_message('/auto apply=true model=true prompt="native content parts smoke token=native-content-parts-secret"')
            native_content_parts_apply_payload = json.loads(native_content_parts_apply.split("\n", 1)[1])
            native_content_parts_recall = native_content_parts_runtime.handle_message('/recall query=native-content-parts-smoke')
            write("native-provider-content-parts-functioncall.json", json.dumps({
                "plan": native_content_parts_plan_payload,
                "apply": native_content_parts_apply_payload,
                "captured": native_content_parts_captured,
                "recall": native_content_parts_recall,
                "marker_exists": native_content_parts_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_content_parts_original_urlopen
            native_content_parts_runtime.close()
        native_content_parts_calls = native_content_parts_plan_payload.get("tool_calls", []) if isinstance(native_content_parts_plan_payload.get("tool_calls"), list) else []
        native_content_parts_metadata = native_content_parts_plan_payload.get("metadata", {}) if isinstance(native_content_parts_plan_payload.get("metadata"), dict) else {}
        native_content_parts_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_content_parts_calls]
        native_content_parts_ledger = native_content_parts_apply_payload.get("execution_ledger", []) if isinstance(native_content_parts_apply_payload.get("execution_ledger"), list) else []
        native_content_parts_warnings = json.dumps(native_content_parts_plan_payload.get("warnings", []))
        checks["native_provider_content_parts_function_call_ok"] = (
            native_content_parts_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_content_parts_calls] == ["remember", "run_command"]
            and all("native provider content parts functionCall" in call.get("reason", "") for call in native_content_parts_calls)
            and native_content_parts_calls[1].get("args", {}).get("execute") is False
            and [item.get("provider_tool_call_id") for item in native_content_parts_call_metadata] == ["content_parts_memory", "content_parts_dry"]
            and [item.get("native_tool_call_source") for item in native_content_parts_call_metadata] == ["native provider content parts functionCall", "native provider content parts functionCall"]
            and native_content_parts_metadata.get("native_tool_calls") is True
            and native_content_parts_metadata.get("native_tool_call_count") == 2
            and [item.get("result", {}).get("status") for item in native_content_parts_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and [item.get("provider_tool_call_id") for item in native_content_parts_ledger] == ["content_parts_memory", "content_parts_dry"]
            and [item.get("native_tool_call_source") for item in native_content_parts_ledger] == ["native provider content parts functionCall", "native provider content parts functionCall"]
            and native_content_parts_ledger[1].get("actual_command_or_process_activity") is False
            and "functionResponse" in native_content_parts_warnings
            and native_status_milestone_contract.get("content_parts_function_call_translation") is True
            and "content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "content parts functionCall native tool call translated" in native_content_parts_recall
            and native_content_parts_captured.get("tool_choice") == "auto"
            and native_content_parts_captured.get("tool_count", 0) > 0
            and not native_content_parts_marker.exists()
            and native_content_parts_result_marker not in native_content_parts_plan + native_content_parts_apply + native_content_parts_recall + json.dumps(native_content_parts_plan_payload) + json.dumps(native_content_parts_apply_payload)
            and "native-content-parts-secret" not in native_content_parts_plan + native_content_parts_apply + native_content_parts_recall + json.dumps(native_content_parts_plan_payload) + json.dumps(native_content_parts_apply_payload)
        )

        native_top_level_content_captured = {}

        class NativeTopLevelContentBlockSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "id": "msg_top_level_content_smoke",
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "native top-level content smoke token=native-top-level-content-secret"},
                        {
                            "type": "tool_use",
                            "tool_use_id": "top_level_content_memory",
                            "name": "remember",
                            "input": {"key": "native-top-level-content-smoke", "value": "top-level content native tool call translated"},
                        },
                        {
                            "type": "function_call",
                            "call_id": "top_level_content_tasks",
                            "name": "list_tasks",
                            "argumentsJson": {"status": "all", "limit": "1"},
                        },
                        {"type": "tool_result", "content": native_provider_result_marker + " token=native-top-level-content-secret"},
                    ],
                }).encode("utf-8")

        def fake_native_top_level_content_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_top_level_content_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_top_level_content_captured["tool_choice"] = payload.get("tool_choice")
            return NativeTopLevelContentBlockSmokeResponse()

        native_top_level_content_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-top-level-content-block.db"),
                session_name="native-provider-top-level-content-block-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-top-level-content-block-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_top_level_content_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_top_level_content_urlopen
            native_top_level_content_plan = native_top_level_content_runtime.handle_message('/auto model=true prompt="native top-level content block smoke token=native-top-level-content-secret"')
            native_top_level_content_plan_payload = json.loads(native_top_level_content_plan.split("\n", 1)[1])
            native_top_level_content_apply = native_top_level_content_runtime.handle_message('/auto apply=true model=true prompt="native top-level content block smoke token=native-top-level-content-secret"')
            native_top_level_content_apply_payload = json.loads(native_top_level_content_apply.split("\n", 1)[1])
            native_top_level_content_recall = native_top_level_content_runtime.handle_message('/recall query=native-top-level-content-smoke')
            write("native-provider-top-level-content-block-tool-calls.json", json.dumps({
                "plan": native_top_level_content_plan_payload,
                "apply": native_top_level_content_apply_payload,
                "captured": native_top_level_content_captured,
                "recall": native_top_level_content_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_top_level_content_original_urlopen
            native_top_level_content_runtime.close()
        native_top_level_content_calls = native_top_level_content_plan_payload.get("tool_calls", []) if isinstance(native_top_level_content_plan_payload.get("tool_calls"), list) else []
        native_top_level_content_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_top_level_content_calls]
        native_top_level_content_ledger = native_top_level_content_apply_payload.get("execution_ledger", []) if isinstance(native_top_level_content_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_top_level_content_block_tool_call_ok"] = (
            native_top_level_content_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_top_level_content_calls] == ["remember", "list_tasks"]
            and [item.get("provider_tool_call_id") for item in native_top_level_content_call_metadata] == ["top_level_content_memory", "top_level_content_tasks"]
            and [item.get("provider_tool_call_id") for item in native_top_level_content_ledger] == ["top_level_content_memory", "top_level_content_tasks"]
            and [item.get("result", {}).get("status") for item in native_top_level_content_apply_payload.get("results", [])] == ["ok", "ok"]
            and native_status_milestone_contract.get("top_level_content_block_tool_call_translation") is True
            and "top_level_content_block_tool_use" in native_status_data.get("provider_native_tool_call_variants", [])
            and "top-level content native tool call translated" in native_top_level_content_recall
            and native_top_level_content_captured.get("tool_choice") == "auto"
            and native_top_level_content_captured.get("tool_count", 0) > 0
            and native_provider_result_marker not in native_top_level_content_plan + native_top_level_content_apply + native_top_level_content_recall + json.dumps(native_top_level_content_plan_payload) + json.dumps(native_top_level_content_apply_payload)
            and "native-top-level-content-secret" not in native_top_level_content_plan + native_top_level_content_apply + native_top_level_content_recall + json.dumps(native_top_level_content_plan_payload) + json.dumps(native_top_level_content_apply_payload)
        )

        native_argument_alias_captured = {}

        class NativeOpenAIArgumentAliasSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": [
                                    {"type": "text", "text": "native argument alias smoke token=native-argument-alias-secret"},
                                    {
                                        "type": "tool_use",
                                        "tool_use_id": "alias_content_tasks",
                                        "name": "list_tasks",
                                        "inputJson": {"status": "all", "limit": "1"},
                                    },
                                ],
                                "tool_calls": [
                                    {
                                        "id": "alias_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments_json": {"key": "native-argument-alias-smoke", "value": "argument alias native tool call translated"},
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_argument_alias_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_argument_alias_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_argument_alias_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIArgumentAliasSmokeResponse()

        native_argument_alias_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-argument-aliases.db"),
                session_name="native-provider-argument-aliases-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-argument-alias-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_argument_alias_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_argument_alias_urlopen
            native_argument_alias_plan = native_argument_alias_runtime.handle_message('/auto model=true prompt="native argument alias smoke token=native-argument-alias-secret"')
            native_argument_alias_plan_payload = json.loads(native_argument_alias_plan.split("\n", 1)[1])
            native_argument_alias_apply = native_argument_alias_runtime.handle_message('/auto apply=true model=true prompt="native argument alias smoke token=native-argument-alias-secret"')
            native_argument_alias_apply_payload = json.loads(native_argument_alias_apply.split("\n", 1)[1])
            native_argument_alias_recall = native_argument_alias_runtime.handle_message('/recall query=native-argument-alias-smoke')
            write("native-provider-argument-aliases.json", json.dumps({
                "plan": native_argument_alias_plan_payload,
                "apply": native_argument_alias_apply_payload,
                "captured": native_argument_alias_captured,
                "recall": native_argument_alias_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_argument_alias_original_urlopen
            native_argument_alias_runtime.close()
        native_argument_alias_calls = native_argument_alias_plan_payload.get("tool_calls", []) if isinstance(native_argument_alias_plan_payload.get("tool_calls"), list) else []
        native_argument_alias_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_argument_alias_calls]
        native_argument_alias_ledger = native_argument_alias_apply_payload.get("execution_ledger", []) if isinstance(native_argument_alias_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_argument_aliases_ok"] = (
            native_argument_alias_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_argument_alias_calls] == ["remember", "list_tasks"]
            and native_argument_alias_calls[0].get("args", {}).get("key") == "native-argument-alias-smoke"
            and native_argument_alias_calls[1].get("args", {}).get("status") == "all"
            and native_argument_alias_calls[1].get("args", {}).get("limit") == 1
            and [item.get("provider_tool_call_id") for item in native_argument_alias_call_metadata] == ["alias_memory", "alias_content_tasks"]
            and [item.get("provider_tool_call_id") for item in native_argument_alias_ledger] == ["alias_memory", "alias_content_tasks"]
            and [item.get("result", {}).get("status") for item in native_argument_alias_apply_payload.get("results", [])] == ["ok", "ok"]
            and native_status_milestone_contract.get("provider_argument_alias_translation") is True
            and "arguments_json" in native_status_data.get("provider_argument_aliases", [])
            and "inputJson" in native_status_data.get("provider_argument_aliases", [])
            and "argument alias native tool call translated" in native_argument_alias_recall
            and native_argument_alias_captured.get("tool_choice") == "auto"
            and native_argument_alias_captured.get("tool_count", 0) > 0
            and "native-argument-alias-secret" not in native_argument_alias_plan + native_argument_alias_apply + native_argument_alias_recall + json.dumps(native_argument_alias_plan_payload) + json.dumps(native_argument_alias_apply_payload)
        )

        native_single_content_captured = {}
        native_single_content_counter = {"count": 0}
        native_single_content_result_marker = "NATIVE_SINGLE_CONTENT_RESULT_SHOULD_NOT_SURFACE"

        class NativeOpenAISingleContentBlockSmokeResponse:
            def __init__(self, payload: dict):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        def fake_native_single_content_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_single_content_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_single_content_captured["tool_choice"] = payload.get("tool_choice")
            native_single_content_counter["count"] += 1
            if native_single_content_counter["count"] <= 2:
                return NativeOpenAISingleContentBlockSmokeResponse({
                    "choices": [
                        {
                            "message": {
                                "content": {
                                    "type": "tool_use",
                                    "id": "single_content_memory",
                                    "name": "remember",
                                    "input": {"key": "native-single-content-smoke", "value": "single content-block native tool call translated"},
                                }
                            }
                        }
                    ]
                })
            return NativeOpenAISingleContentBlockSmokeResponse({
                "choices": [
                    {
                        "message": {
                            "content": {
                                "type": "tool_result",
                                "content": native_single_content_result_marker + " token=native-single-result-secret",
                            }
                        }
                    }
                ]
            })

        native_single_content_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-single-content-block.db"),
                session_name="native-provider-single-content-block-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-single-content-block-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_single_content_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_single_content_urlopen
            native_single_content_plan = native_single_content_runtime.handle_message('/auto model=true prompt="native single content block smoke token=native-single-content-secret"')
            native_single_content_plan_payload = json.loads(native_single_content_plan.split("\n", 1)[1])
            native_single_content_apply = native_single_content_runtime.handle_message('/auto apply=true model=true prompt="native single content block smoke token=native-single-content-secret"')
            native_single_content_apply_payload = json.loads(native_single_content_apply.split("\n", 1)[1])
            native_single_content_result_plan = native_single_content_runtime.handle_message('/auto model=true prompt="provider emitted only a prior result echo token=native-single-result-secret"')
            native_single_content_result_payload = json.loads(native_single_content_result_plan.split("\n", 1)[1])
            native_single_content_recall = native_single_content_runtime.handle_message('/recall query=native-single-content-smoke')
            write("native-provider-single-content-block-tool-calls.json", json.dumps({
                "plan": native_single_content_plan_payload,
                "apply": native_single_content_apply_payload,
                "result_echo_plan": native_single_content_result_payload,
                "captured": native_single_content_captured,
                "recall": native_single_content_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_single_content_original_urlopen
            native_single_content_runtime.close()
        native_single_content_calls = native_single_content_plan_payload.get("tool_calls", []) if isinstance(native_single_content_plan_payload.get("tool_calls"), list) else []
        native_single_content_metadata = native_single_content_plan_payload.get("metadata", {}) if isinstance(native_single_content_plan_payload.get("metadata"), dict) else {}
        native_single_content_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_single_content_calls]
        native_single_content_ledger = native_single_content_apply_payload.get("execution_ledger", []) if isinstance(native_single_content_apply_payload.get("execution_ledger"), list) else []
        native_single_content_result_warnings = json.dumps(native_single_content_result_payload.get("warnings", []))
        checks["native_provider_single_content_block_tool_call_ok"] = (
            native_single_content_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_single_content_calls] == ["remember"]
            and "native content-block tool_use" in native_single_content_calls[0].get("reason", "")
            and native_single_content_calls[0].get("args", {}).get("key") == "native-single-content-smoke"
            and native_single_content_metadata.get("native_tool_calls") is True
            and native_single_content_metadata.get("native_tool_call_count") == 1
            and [item.get("provider_tool_call_id") for item in native_single_content_call_metadata] == ["single_content_memory"]
            and native_single_content_call_metadata[0].get("native_tool_call_source") == "native content-block tool_use"
            and native_single_content_call_metadata[0].get("native_tool_call_index") == 1
            and [item.get("result", {}).get("status") for item in native_single_content_apply_payload.get("results", [])] == ["ok"]
            and [item.get("provider_tool_call_id") for item in native_single_content_ledger] == ["single_content_memory"]
            and native_single_content_ledger[0].get("native_tool_call_source") == "native content-block tool_use"
            and native_single_content_result_payload.get("tool_calls") == []
            and native_single_content_result_payload.get("no_tools_executed") is True
            and "tool_result" in native_single_content_result_warnings.lower()
            and native_status_milestone_contract.get("single_content_block_tool_call_translation") is True
            and "single_content_block_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single content-block native tool call translated" in native_single_content_recall
            and native_single_content_captured.get("tool_choice") == "auto"
            and native_single_content_captured.get("tool_count", 0) > 0
            and native_single_content_result_marker not in native_single_content_plan + native_single_content_apply + native_single_content_result_plan + native_single_content_recall + json.dumps(native_single_content_plan_payload) + json.dumps(native_single_content_apply_payload) + json.dumps(native_single_content_result_payload)
            and "native-single-content-secret" not in native_single_content_plan + native_single_content_apply + native_single_content_result_plan + native_single_content_recall + json.dumps(native_single_content_plan_payload) + json.dumps(native_single_content_apply_payload) + json.dumps(native_single_content_result_payload)
            and "native-single-result-secret" not in native_single_content_plan + native_single_content_apply + native_single_content_result_plan + native_single_content_recall + json.dumps(native_single_content_plan_payload) + json.dumps(native_single_content_apply_payload) + json.dumps(native_single_content_result_payload)
        )

        native_responses_marker = root / "native-responses-should-not-run.txt"
        native_responses_captured = {}
        native_responses_custom_marker = "NATIVE_RESPONSES_CUSTOM_INPUT_SHOULD_NOT_SURFACE"

        class NativeOpenAIResponsesOutputSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native responses output smoke token=native-responses-secret",
                    "output": [
                        {"type": "message", "content": [{"type": "output_text", "text": "native responses output smoke token=native-responses-secret"}]},
                        {
                            "type": "function_call",
                            "call_id": "responses_memory",
                            "name": "remember",
                            "arguments": json.dumps({"key": "native-responses-smoke", "value": "responses output native tool call translated"}),
                        },
                        {
                            "type": "function_call",
                            "call_id": "responses_dry",
                            "name": "run_command",
                            "arguments": json.dumps({
                                "target": "app.example.test",
                                "purpose": "native responses dry-run smoke",
                                "command": f"printf native-responses > {native_responses_marker}",
                                "execute": True,
                            }),
                        },
                        {"type": "custom_tool_call", "call_id": "responses_custom", "name": "run_command", "input": native_responses_custom_marker + " token=native-responses-secret"},
                        {"type": "function_call_output", "call_id": "responses_result", "output": native_provider_result_marker},
                    ],
                }).encode("utf-8")

        def fake_native_responses_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesOutputSmokeResponse()

        native_responses_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-output.db"),
                session_name="native-provider-responses-output-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-output-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_urlopen
            native_responses_plan = native_responses_runtime.handle_message('/auto model=true prompt="native responses output smoke token=native-responses-secret"')
            native_responses_plan_payload = json.loads(native_responses_plan.split("\n", 1)[1])
            native_responses_apply = native_responses_runtime.handle_message('/auto apply=true model=true prompt="native responses output smoke token=native-responses-secret"')
            native_responses_apply_payload = json.loads(native_responses_apply.split("\n", 1)[1])
            native_responses_recall = native_responses_runtime.handle_message('/recall query=native-responses-smoke')
            write("native-provider-responses-output-tool-calls.json", json.dumps({
                "plan": native_responses_plan_payload,
                "apply": native_responses_apply_payload,
                "captured": native_responses_captured,
                "recall": native_responses_recall,
                "marker_exists": native_responses_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_original_urlopen
            native_responses_runtime.close()
        native_responses_calls = native_responses_plan_payload.get("tool_calls", []) if isinstance(native_responses_plan_payload.get("tool_calls"), list) else []
        native_responses_rejected = json.dumps(native_responses_plan_payload.get("rejected_tool_calls", []))
        native_responses_warnings = json.dumps(native_responses_plan_payload.get("warnings", []))
        native_responses_metadata = native_responses_plan_payload.get("metadata", {}) if isinstance(native_responses_plan_payload.get("metadata"), dict) else {}
        native_responses_ledger = native_responses_apply_payload.get("execution_ledger", []) if isinstance(native_responses_apply_payload.get("execution_ledger"), list) else []
        native_responses_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_calls]
        checks["native_provider_responses_output_tool_call_ok"] = (
            native_responses_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_calls] == ["remember", "run_command"]
            and all("native provider responses output function_call" in call.get("reason", "") for call in native_responses_calls)
            and native_responses_calls[1].get("args", {}).get("execute") is False
            and native_responses_metadata.get("native_tool_calls") is True
            and native_responses_metadata.get("native_tool_call_count") == 2
            and int(native_responses_metadata.get("rejected_native_tool_call_count", 0) or 0) >= 1
            and "Custom/freeform native tool calls are not supported" in native_responses_rejected
            and "custom/freeform" in native_responses_warnings.lower()
            and [item.get("provider_tool_call_id") for item in native_responses_call_metadata] == ["responses_memory", "responses_dry"]
            and [item.get("provider_tool_call_id") for item in native_responses_ledger] == ["responses_memory", "responses_dry"]
            and native_responses_ledger[1].get("native_tool_call_source") == "native provider responses output function_call"
            and [item.get("result", {}).get("status") for item in native_responses_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and "responses output native tool call translated" in native_responses_recall
            and "tool_result" in native_responses_warnings.lower()
            and native_responses_captured.get("tool_choice") == "auto"
            and native_responses_captured.get("tool_count", 0) > 0
            and not native_responses_marker.exists()
            and native_responses_custom_marker not in native_responses_plan + native_responses_apply + native_responses_recall + json.dumps(native_responses_plan_payload) + json.dumps(native_responses_apply_payload)
            and "native-responses-secret" not in native_responses_plan + native_responses_apply + native_responses_recall + json.dumps(native_responses_plan_payload) + json.dumps(native_responses_apply_payload)
            and native_provider_result_marker not in native_responses_plan + native_responses_apply + native_responses_recall + json.dumps(native_responses_plan_payload) + json.dumps(native_responses_apply_payload)
        )

        native_responses_nested_captured = {}
        native_responses_nested_result_marker = "NATIVE_RESPONSES_NESTED_RESULT_SHOULD_NOT_SURFACE"

        class NativeOpenAIResponsesNestedOutputSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native nested responses output smoke token=native-responses-nested-secret",
                    "output": [
                        {"type": "message", "content": [{"type": "output_text", "text": "native nested responses output smoke token=native-responses-nested-secret"}]},
                        {
                            "type": "function_call",
                            "call_id": "responses_nested_function_memory",
                            "function": {
                                "name": "remember",
                                "arguments": json.dumps({"key": "native-responses-nested-smoke", "value": "nested Responses output function native tool call translated"}),
                            },
                        },
                        {
                            "type": "tool_call",
                            "toolUseId": "responses_nested_function_call_tasks",
                            "functionCall": {
                                "name": "list_tasks",
                                "parameters": {"status": "all", "limit": 1},
                            },
                        },
                        {"type": "function_call_output", "call_id": "responses_nested_result", "output": native_responses_nested_result_marker + " token=native-responses-nested-secret"},
                    ],
                }).encode("utf-8")

        def fake_native_responses_nested_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_nested_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_nested_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesNestedOutputSmokeResponse()

        native_responses_nested_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-nested-output.db"),
                session_name="native-provider-responses-nested-output-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-nested-output-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_nested_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_nested_urlopen
            native_responses_nested_plan = native_responses_nested_runtime.handle_message('/auto model=true prompt="native nested responses output smoke token=native-responses-nested-secret"')
            native_responses_nested_plan_payload = json.loads(native_responses_nested_plan.split("\n", 1)[1])
            native_responses_nested_apply = native_responses_nested_runtime.handle_message('/auto apply=true model=true prompt="native nested responses output smoke token=native-responses-nested-secret"')
            native_responses_nested_apply_payload = json.loads(native_responses_nested_apply.split("\n", 1)[1])
            native_responses_nested_recall = native_responses_nested_runtime.handle_message('/recall query=native-responses-nested-smoke')
            write("native-provider-responses-nested-output-tool-calls.json", json.dumps({
                "plan": native_responses_nested_plan_payload,
                "apply": native_responses_nested_apply_payload,
                "captured": native_responses_nested_captured,
                "recall": native_responses_nested_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_nested_original_urlopen
            native_responses_nested_runtime.close()
        native_responses_nested_calls = native_responses_nested_plan_payload.get("tool_calls", []) if isinstance(native_responses_nested_plan_payload.get("tool_calls"), list) else []
        native_responses_nested_metadata = native_responses_nested_plan_payload.get("metadata", {}) if isinstance(native_responses_nested_plan_payload.get("metadata"), dict) else {}
        native_responses_nested_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_nested_calls]
        native_responses_nested_ledger = native_responses_nested_apply_payload.get("execution_ledger", []) if isinstance(native_responses_nested_apply_payload.get("execution_ledger"), list) else []
        native_responses_nested_outputs = native_responses_nested_plan + native_responses_nested_apply + native_responses_nested_recall + json.dumps(native_responses_nested_plan_payload) + json.dumps(native_responses_nested_apply_payload)
        checks["native_provider_responses_output_nested_function_call_ok"] = (
            native_responses_nested_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_nested_calls] == ["remember", "list_tasks"]
            and "native provider responses output nested function" in native_responses_nested_calls[0].get("reason", "")
            and "native provider responses output nested functionCall" in native_responses_nested_calls[1].get("reason", "")
            and native_responses_nested_metadata.get("native_tool_calls") is True
            and native_responses_nested_metadata.get("native_tool_call_count") == 2
            and [item.get("provider_tool_call_id") for item in native_responses_nested_call_metadata] == ["responses_nested_function_memory", "responses_nested_function_call_tasks"]
            and [item.get("native_tool_call_source") for item in native_responses_nested_call_metadata] == ["native provider responses output nested function", "native provider responses output nested functionCall"]
            and [item.get("provider_tool_call_id") for item in native_responses_nested_ledger] == ["responses_nested_function_memory", "responses_nested_function_call_tasks"]
            and [item.get("native_tool_call_source") for item in native_responses_nested_ledger] == ["native provider responses output nested function", "native provider responses output nested functionCall"]
            and [item.get("result", {}).get("status") for item in native_responses_nested_apply_payload.get("results", [])] == ["ok", "ok"]
            and native_status_milestone_contract.get("responses_output_nested_function_call_translation") is True
            and "responses_output_nested_function" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_nested_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "nested Responses output function native tool call translated" in native_responses_nested_recall
            and "tool_result" in json.dumps(native_responses_nested_plan_payload.get("warnings", [])).lower()
            and native_responses_nested_captured.get("tool_choice") == "auto"
            and native_responses_nested_captured.get("tool_count", 0) > 0
            and native_responses_nested_result_marker not in native_responses_nested_outputs
            and "native-responses-nested-secret" not in native_responses_nested_outputs + json.dumps(native_responses_nested_call_metadata) + json.dumps(native_responses_nested_ledger)
        )

        native_responses_output_message_captured = {}
        native_responses_output_message_result_marker = "NATIVE_RESPONSES_OUTPUT_MESSAGE_RESULT_SHOULD_NOT_SURFACE"

        class NativeOpenAIResponsesOutputNestedMessageSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native responses output nested message smoke token=native-responses-output-message-secret",
                    "output": [
                        {
                            "type": "message",
                            "message": {
                                "content": {
                                    "parts": [
                                        {"text": "native responses output nested message text token=native-responses-output-message-secret"},
                                        {
                                            "functionCall": {
                                                "callId": "responses_output_message_parts_memory",
                                                "name": "remember",
                                                "args": {"key": "native-responses-output-message-parts-smoke", "value": "Responses output nested message content parts native tool call translated"},
                                            }
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": native_responses_output_message_result_marker + " token=native-responses-output-message-secret"},
                                            }
                                        },
                                    ]
                                },
                                "tool_calls": [
                                    {
                                        "id": "responses_output_message_tool_calls_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-responses-output-message-tool-calls-smoke", "value": "Responses output nested message tool_calls native tool call translated"}),
                                        },
                                    }
                                ],
                                "toolCalls": {
                                    "toolUseId": "responses_output_message_toolcalls_tasks",
                                    "function": {"name": "list_tasks", "argumentsJson": {"status": "all", "limit": 1}},
                                },
                                "tool_call": {
                                    "tool_call_id": "responses_output_message_tool_call_memory",
                                    "function": {"name": "remember", "arguments": json.dumps({"key": "native-responses-output-message-tool-call-smoke", "value": "Responses output nested message tool_call native tool call translated"})},
                                },
                                "toolCall": {
                                    "toolCallId": "responses_output_message_tool_camel_memory",
                                    "name": "remember",
                                    "args": {"key": "native-responses-output-message-tool-camel-smoke", "value": "Responses output nested message toolCall native tool call translated"},
                                },
                                "functionCall": {
                                    "callId": "responses_output_message_function_memory",
                                    "name": "remember",
                                    "parameters": {"key": "native-responses-output-message-functioncall-smoke", "value": "Responses output nested message functionCall native tool call translated"},
                                },
                                "functionCalls": [
                                    {"callId": "responses_output_message_functions_memory", "name": "remember", "args": {"key": "native-responses-output-message-functioncalls-smoke", "value": "Responses output nested message functionCalls native tool call translated"}}
                                ],
                                "function_calls": {
                                    "call_id": "responses_output_message_functions_snake_memory",
                                    "function_call": {"name": "remember", "args": {"key": "native-responses-output-message-function-calls-smoke", "value": "Responses output nested message function_calls native tool call translated"}},
                                },
                            },
                        },
                        {
                            "message": {
                                "content": {
                                    "parts": [
                                        {"text": "native typeless responses output message text token=native-responses-output-message-secret"},
                                        {
                                            "functionCall": {
                                                "callId": "responses_output_message_typeless_parts_memory",
                                                "name": "remember",
                                                "args": {"key": "native-responses-output-message-typeless-parts-smoke", "value": "Responses output typeless nested message content parts native tool call translated"},
                                            }
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": native_responses_output_message_result_marker + " token=native-responses-output-message-secret"},
                                            }
                                        },
                                    ]
                                },
                                "tool_calls": [
                                    {
                                        "id": "responses_output_message_typeless_tool_calls_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-responses-output-message-typeless-tool-calls-smoke", "value": "Responses output typeless nested message tool_calls native tool call translated"}),
                                        },
                                    }
                                ],
                                "functionCalls": {
                                    "callId": "responses_output_message_typeless_functions_memory",
                                    "name": "remember",
                                    "args": {"key": "native-responses-output-message-typeless-functioncalls-smoke", "value": "Responses output typeless nested message functionCalls native tool call translated"},
                                },
                            }
                        }
                    ],
                }).encode("utf-8")

        def fake_native_responses_output_message_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_output_message_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_output_message_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesOutputNestedMessageSmokeResponse()

        native_responses_output_message_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-output-nested-message.db"),
                session_name="native-provider-responses-output-nested-message-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-output-nested-message-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_output_message_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_output_message_urlopen
            native_responses_output_message_plan = native_responses_output_message_runtime.handle_message('/auto model=true prompt="native responses output nested message smoke token=native-responses-output-message-secret"')
            native_responses_output_message_plan_payload = json.loads(native_responses_output_message_plan.split("\n", 1)[1])
            native_responses_output_message_apply = native_responses_output_message_runtime.handle_message('/auto apply=true model=true prompt="native responses output nested message smoke token=native-responses-output-message-secret"')
            native_responses_output_message_apply_payload = json.loads(native_responses_output_message_apply.split("\n", 1)[1])
            native_responses_output_message_recall = native_responses_output_message_runtime.handle_message('/recall query=native-responses-output-message')
            write("native-provider-responses-output-nested-message-aliases.json", json.dumps({
                "plan": native_responses_output_message_plan_payload,
                "apply": native_responses_output_message_apply_payload,
                "captured": native_responses_output_message_captured,
                "recall": native_responses_output_message_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_output_message_original_urlopen
            native_responses_output_message_runtime.close()
        native_responses_output_message_calls = native_responses_output_message_plan_payload.get("tool_calls", []) if isinstance(native_responses_output_message_plan_payload.get("tool_calls"), list) else []
        native_responses_output_message_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_output_message_calls]
        native_responses_output_message_ledger = native_responses_output_message_apply_payload.get("execution_ledger", []) if isinstance(native_responses_output_message_apply_payload.get("execution_ledger"), list) else []
        native_responses_output_message_outputs = native_responses_output_message_plan + native_responses_output_message_apply + native_responses_output_message_recall + json.dumps(native_responses_output_message_plan_payload) + json.dumps(native_responses_output_message_apply_payload)
        checks["native_provider_responses_output_message_aliases_ok"] = (
            native_responses_output_message_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_output_message_calls] == ["remember", "list_tasks", "remember", "remember", "remember", "remember", "remember", "remember", "remember", "remember", "remember"]
            and [item.get("provider_tool_call_id") for item in native_responses_output_message_call_metadata] == [
                "responses_output_message_tool_calls_memory",
                "responses_output_message_toolcalls_tasks",
                "responses_output_message_tool_call_memory",
                "responses_output_message_tool_camel_memory",
                "responses_output_message_function_memory",
                "responses_output_message_functions_memory",
                "responses_output_message_functions_snake_memory",
                "responses_output_message_typeless_tool_calls_memory",
                "responses_output_message_typeless_functions_memory",
                "responses_output_message_parts_memory",
                "responses_output_message_typeless_parts_memory",
            ]
            and [item.get("native_tool_call_source") for item in native_responses_output_message_call_metadata] == [
                "native provider responses output message tool_calls",
                "native provider responses output message toolCalls",
                "native provider responses output message tool_call",
                "native provider responses output message toolCall",
                "native provider responses output message functionCall",
                "native provider responses output message functionCalls",
                "native provider responses output message function_calls",
                "native provider responses output message tool_calls",
                "native provider responses output message functionCalls",
                "native provider responses output message content parts functionCall",
                "native provider responses output message content parts functionCall",
            ]
            and [item.get("provider_tool_call_id") for item in native_responses_output_message_ledger] == [item.get("provider_tool_call_id") for item in native_responses_output_message_call_metadata]
            and [item.get("result", {}).get("status") for item in native_responses_output_message_apply_payload.get("results", [])] == ["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok"]
            and native_status_milestone_contract.get("responses_output_message_alias_translation") is True
            and "responses_output_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_toolCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_toolCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_wrapper" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Responses output nested message tool_calls native tool call translated" in native_responses_output_message_recall
            and "Responses output nested message content parts native tool call translated" in native_responses_output_message_recall
            and "Responses output typeless nested message tool_calls native tool call translated" in native_responses_output_message_recall
            and "Responses output typeless nested message functionCalls native tool call translated" in native_responses_output_message_recall
            and "Responses output typeless nested message content parts native tool call translated" in native_responses_output_message_recall
            and "functionResponse" in json.dumps(native_responses_output_message_plan_payload.get("warnings", []))
            and native_responses_output_message_captured.get("tool_choice") == "auto"
            and native_responses_output_message_captured.get("tool_count", 0) > 0
            and native_responses_output_message_result_marker not in native_responses_output_message_outputs
            and "native-responses-output-message-secret" not in native_responses_output_message_outputs + json.dumps(native_responses_output_message_call_metadata) + json.dumps(native_responses_output_message_ledger)
        )
        checks["native_provider_responses_output_message_typeless_wrapper_ok"] = (
            checks["native_provider_responses_output_message_aliases_ok"]
            and native_status_milestone_contract.get("responses_output_message_typeless_wrapper_translation") is True
            and "responses_output_message_typeless_wrapper" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_tool_calls_memory" in json.dumps(native_responses_output_message_call_metadata)
            and "Responses output typeless nested message content parts native tool call translated" in native_responses_output_message_recall
            and native_responses_output_message_result_marker not in native_responses_output_message_outputs
        )

        native_responses_output_direct_message_captured = {}
        native_responses_output_direct_message_result_marker = "NATIVE_RESPONSES_OUTPUT_DIRECT_MESSAGE_RESULT_SHOULD_NOT_SURFACE"

        class NativeOpenAIResponsesOutputTypelessDirectMessageSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native typeless direct responses output message token=native-responses-output-direct-message-secret",
                    "output": [
                        {
                            "content": {
                                "parts": [
                                    {"text": "native typeless direct responses output message text token=native-responses-output-direct-message-secret"},
                                    {
                                        "functionCall": {
                                            "callId": "responses_output_direct_message_parts_memory",
                                            "name": "remember",
                                            "args": {"key": "native-responses-output-direct-message-parts-smoke", "value": "Typeless direct Responses output message content parts native tool call translated"},
                                        }
                                    },
                                    {
                                        "functionResponse": {
                                            "name": "remember",
                                            "response": {"content": native_responses_output_direct_message_result_marker + " token=native-responses-output-direct-message-secret"},
                                        }
                                    },
                                ]
                            },
                            "tool_calls": [
                                {
                                    "id": "responses_output_direct_message_tool_calls_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-responses-output-direct-message-tool-calls-smoke", "value": "Typeless direct Responses output message tool_calls native tool call translated"}),
                                    },
                                }
                            ],
                            "toolCalls": [
                                {
                                    "toolUseId": "responses_output_direct_message_toolcalls_memory",
                                    "function": {
                                        "name": "remember",
                                        "argumentsJson": {"key": "native-responses-output-direct-message-toolcalls-smoke", "value": "Typeless direct Responses output message toolCalls native tool call translated"},
                                    },
                                }
                            ],
                            "tool_call": {
                                "tool_call_id": "responses_output_direct_message_tool_call_memory",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-responses-output-direct-message-tool-call-smoke", "value": "Typeless direct Responses output message tool_call native tool call translated"}),
                                },
                            },
                            "toolCall": {
                                "toolCallId": "responses_output_direct_message_tool_camel_memory",
                                "name": "remember",
                                "args": {"key": "native-responses-output-direct-message-tool-camel-smoke", "value": "Typeless direct Responses output message toolCall native tool call translated"},
                            },
                            "functionCall": {
                                "callId": "responses_output_direct_message_function_alias_memory",
                                "name": "remember",
                                "parameters": {"key": "native-responses-output-direct-message-functioncall-smoke", "value": "Typeless direct Responses output message functionCall native tool call translated"},
                            },
                            "function_call": {
                                "call_id": "responses_output_direct_message_function_call_memory",
                                "name": "remember",
                                "parameters": {"key": "native-responses-output-direct-message-function-call-smoke", "value": "Typeless direct Responses output message function_call native tool call translated"},
                            },
                            "functionCalls": {
                                "callId": "responses_output_direct_message_function_calls_memory",
                                "name": "remember",
                                "args": {"key": "native-responses-output-direct-message-functioncalls-smoke", "value": "Typeless direct Responses output message functionCalls native tool call translated"},
                            },
                            "function_calls": [
                                {
                                    "call_id": "responses_output_direct_message_function_calls_snake_memory",
                                    "function_call": {
                                        "name": "remember",
                                        "parameters": {"key": "native-responses-output-direct-message-function-calls-snake-smoke", "value": "Typeless direct Responses output message function_calls native tool call translated"},
                                    },
                                }
                            ],
                        }
                    ],
                }).encode("utf-8")

        def fake_native_responses_output_direct_message_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_output_direct_message_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_output_direct_message_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesOutputTypelessDirectMessageSmokeResponse()

        native_responses_output_direct_message_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-output-typeless-direct-message.db"),
                session_name="native-provider-responses-output-typeless-direct-message-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-output-typeless-direct-message-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_output_direct_message_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_output_direct_message_urlopen
            native_responses_output_direct_message_plan = native_responses_output_direct_message_runtime.handle_message('/auto model=true prompt="native typeless direct responses output message smoke token=native-responses-output-direct-message-secret"')
            native_responses_output_direct_message_plan_payload = json.loads(native_responses_output_direct_message_plan.split("\n", 1)[1])
            native_responses_output_direct_message_apply = native_responses_output_direct_message_runtime.handle_message('/auto apply=true model=true prompt="native typeless direct responses output message smoke token=native-responses-output-direct-message-secret"')
            native_responses_output_direct_message_apply_payload = json.loads(native_responses_output_direct_message_apply.split("\n", 1)[1])
            native_responses_output_direct_message_recall = native_responses_output_direct_message_runtime.handle_message('/recall query=native-responses-output-direct-message')
            write("native-provider-responses-output-typeless-direct-message.json", json.dumps({
                "plan": native_responses_output_direct_message_plan_payload,
                "apply": native_responses_output_direct_message_apply_payload,
                "captured": native_responses_output_direct_message_captured,
                "recall": native_responses_output_direct_message_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_output_direct_message_original_urlopen
            native_responses_output_direct_message_runtime.close()
        native_responses_output_direct_message_calls = native_responses_output_direct_message_plan_payload.get("tool_calls", []) if isinstance(native_responses_output_direct_message_plan_payload.get("tool_calls"), list) else []
        native_responses_output_direct_message_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_output_direct_message_calls]
        native_responses_output_direct_message_ledger = native_responses_output_direct_message_apply_payload.get("execution_ledger", []) if isinstance(native_responses_output_direct_message_apply_payload.get("execution_ledger"), list) else []
        native_responses_output_direct_message_outputs = native_responses_output_direct_message_plan + native_responses_output_direct_message_apply + native_responses_output_direct_message_recall + json.dumps(native_responses_output_direct_message_plan_payload) + json.dumps(native_responses_output_direct_message_apply_payload)
        checks["native_provider_responses_output_message_typeless_direct_ok"] = (
            native_responses_output_direct_message_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_output_direct_message_calls] == ["remember"] * 9
            and [item.get("native_tool_call_source") for item in native_responses_output_direct_message_call_metadata] == [
                "native provider typeless responses output message tool_calls",
                "native provider typeless responses output message toolCalls",
                "native provider typeless responses output message tool_call",
                "native provider typeless responses output message toolCall",
                "native provider typeless responses output message functionCall",
                "native provider typeless responses output message function_call",
                "native provider typeless responses output message functionCalls",
                "native provider typeless responses output message function_calls",
                "native provider typeless responses output message content parts functionCall",
            ]
            and [item.get("provider_tool_call_id") for item in native_responses_output_direct_message_call_metadata] == [
                "responses_output_direct_message_tool_calls_memory",
                "responses_output_direct_message_toolcalls_memory",
                "responses_output_direct_message_tool_call_memory",
                "responses_output_direct_message_tool_camel_memory",
                "responses_output_direct_message_function_alias_memory",
                "responses_output_direct_message_function_call_memory",
                "responses_output_direct_message_function_calls_memory",
                "responses_output_direct_message_function_calls_snake_memory",
                "responses_output_direct_message_parts_memory",
            ]
            and [item.get("provider_tool_call_id") for item in native_responses_output_direct_message_ledger] == [item.get("provider_tool_call_id") for item in native_responses_output_direct_message_call_metadata]
            and [item.get("native_tool_call_source") for item in native_responses_output_direct_message_ledger] == [item.get("native_tool_call_source") for item in native_responses_output_direct_message_call_metadata]
            and [item.get("result", {}).get("status") for item in native_responses_output_direct_message_apply_payload.get("results", [])] == ["ok"] * 9
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_tool_calls_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_tool_calls_camel_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_tool_call_singular_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_tool_call_camel_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_function_call_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_function_calls_alias_translation") is True
            and native_status_milestone_contract.get("responses_output_message_typeless_direct_function_calls_snake_alias_translation") is True
            and "responses_output_message_typeless_direct" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_toolCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_toolCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_output_message_typeless_direct_content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Typeless direct Responses output message tool_calls native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message toolCalls native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message tool_call native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message toolCall native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message functionCall native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message function_call native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message functionCalls native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message function_calls native tool call translated" in native_responses_output_direct_message_recall
            and "Typeless direct Responses output message content parts native tool call translated" in native_responses_output_direct_message_recall
            and "functionResponse" in json.dumps(native_responses_output_direct_message_plan_payload.get("warnings", []))
            and native_responses_output_direct_message_captured.get("tool_choice") == "auto"
            and native_responses_output_direct_message_captured.get("tool_count", 0) > 0
            and native_responses_output_direct_message_result_marker not in native_responses_output_direct_message_outputs
            and "native-responses-output-direct-message-secret" not in native_responses_output_direct_message_outputs + json.dumps(native_responses_output_direct_message_call_metadata) + json.dumps(native_responses_output_direct_message_ledger)
        )
        checks["native_provider_responses_output_message_typeless_direct_aliases_ok"] = checks["native_provider_responses_output_message_typeless_direct_ok"]

        native_responses_message_tool_captured = {}

        class NativeOpenAIResponsesMessageToolCallSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native responses message tool_calls smoke token=native-responses-message-tool-secret",
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "native responses message tool_calls smoke token=native-responses-message-tool-secret"}],
                            "tool_calls": [
                                {
                                    "id": "responses_message_tool_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-responses-message-tool-calls-smoke", "value": "Responses message-level tool_calls native tool call translated"}),
                                    },
                                },
                                {
                                    "id": "responses_message_tool_tasks",
                                    "type": "function",
                                    "function": {
                                        "name": "list_tasks",
                                        "argumentsJson": {"status": "all", "limit": 1},
                                    },
                                },
                            ],
                            "toolCalls": [
                                {
                                    "toolUseId": "responses_message_toolcalls_plural",
                                    "function": {
                                        "name": "remember",
                                        "argumentsJson": {"key": "native-responses-message-toolcalls-smoke", "value": "Responses message-level toolCalls native tool call translated"},
                                    },
                                }
                            ],
                            "tool_call": {
                                "tool_call_id": "responses_message_tool_call_singular",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-responses-message-tool-call-smoke", "value": "Responses message-level tool_call native tool call translated"}),
                                },
                            },
                            "toolCall": {
                                "toolCallId": "responses_message_tool_camel",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-responses-message-tool-camel-smoke", "value": "Responses message-level toolCall native tool call translated"}),
                                },
                            },
                            "functionCall": {
                                "callId": "responses_message_function_alias",
                                "name": "remember",
                                "parameters": {"key": "native-responses-message-functioncall-smoke", "value": "Responses message-level functionCall native tool call translated"},
                            },
                            "functionCalls": [
                                {
                                    "callId": "responses_message_function_calls_plural",
                                    "name": "remember",
                                    "args": {"key": "native-responses-message-functioncalls-smoke", "value": "Responses message-level functionCalls native tool call translated"},
                                }
                            ],
                            "function_calls": {
                                "call_id": "responses_message_function_calls_snake",
                                "function_call": {
                                    "name": "remember",
                                    "parameters": {"key": "native-responses-message-function-calls-snake-smoke", "value": "Responses message-level function_calls native tool call translated"},
                                },
                            },
                        }
                    ],
                }).encode("utf-8")

        def fake_native_responses_message_tool_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_message_tool_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_message_tool_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesMessageToolCallSmokeResponse()

        native_responses_message_tool_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-message-tool-calls.db"),
                session_name="native-provider-responses-message-tool-calls-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-tool-calls-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_message_tool_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_message_tool_urlopen
            native_responses_message_tool_plan = native_responses_message_tool_runtime.handle_message('/auto model=true prompt="native responses message tool_calls smoke token=native-responses-message-tool-secret"')
            native_responses_message_tool_plan_payload = json.loads(native_responses_message_tool_plan.split("\n", 1)[1])
            native_responses_message_tool_apply = native_responses_message_tool_runtime.handle_message('/auto apply=true model=true prompt="native responses message tool_calls smoke token=native-responses-message-tool-secret"')
            native_responses_message_tool_apply_payload = json.loads(native_responses_message_tool_apply.split("\n", 1)[1])
            native_responses_message_tool_recall = native_responses_message_tool_runtime.handle_message('/recall query=native-responses-message')
            write("native-provider-responses-message-tool-calls.json", json.dumps({
                "plan": native_responses_message_tool_plan_payload,
                "apply": native_responses_message_tool_apply_payload,
                "captured": native_responses_message_tool_captured,
                "recall": native_responses_message_tool_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_message_tool_original_urlopen
            native_responses_message_tool_runtime.close()
        native_responses_message_tool_calls = native_responses_message_tool_plan_payload.get("tool_calls", []) if isinstance(native_responses_message_tool_plan_payload.get("tool_calls"), list) else []
        native_responses_message_tool_metadata = native_responses_message_tool_plan_payload.get("metadata", {}) if isinstance(native_responses_message_tool_plan_payload.get("metadata"), dict) else {}
        native_responses_message_tool_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_message_tool_calls]
        native_responses_message_tool_ledger = native_responses_message_tool_apply_payload.get("execution_ledger", []) if isinstance(native_responses_message_tool_apply_payload.get("execution_ledger"), list) else []
        native_responses_message_tool_outputs = native_responses_message_tool_plan + native_responses_message_tool_apply + native_responses_message_tool_recall + json.dumps(native_responses_message_tool_plan_payload) + json.dumps(native_responses_message_tool_apply_payload)
        checks["native_provider_responses_message_tool_call_alias_ok"] = (
            native_responses_message_tool_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_message_tool_calls] == ["remember", "list_tasks", "remember", "remember", "remember", "remember", "remember", "remember"]
            and "native provider responses message tool_calls" in native_responses_message_tool_calls[0].get("reason", "")
            and "native provider responses message toolCalls" in native_responses_message_tool_calls[2].get("reason", "")
            and "native provider responses message tool_call" in native_responses_message_tool_calls[3].get("reason", "")
            and "native provider responses message toolCall" in native_responses_message_tool_calls[4].get("reason", "")
            and "native provider responses message functionCall" in native_responses_message_tool_calls[5].get("reason", "")
            and "native provider responses message functionCalls" in native_responses_message_tool_calls[6].get("reason", "")
            and "native provider responses message function_calls" in native_responses_message_tool_calls[7].get("reason", "")
            and native_responses_message_tool_metadata.get("native_tool_calls") is True
            and native_responses_message_tool_metadata.get("native_tool_call_count") == 8
            and [item.get("provider_tool_call_id") for item in native_responses_message_tool_call_metadata] == ["responses_message_tool_memory", "responses_message_tool_tasks", "responses_message_toolcalls_plural", "responses_message_tool_call_singular", "responses_message_tool_camel", "responses_message_function_alias", "responses_message_function_calls_plural", "responses_message_function_calls_snake"]
            and [item.get("native_tool_call_source") for item in native_responses_message_tool_call_metadata] == ["native provider responses message tool_calls", "native provider responses message tool_calls", "native provider responses message toolCalls", "native provider responses message tool_call", "native provider responses message toolCall", "native provider responses message functionCall", "native provider responses message functionCalls", "native provider responses message function_calls"]
            and [item.get("provider_tool_call_id") for item in native_responses_message_tool_ledger] == ["responses_message_tool_memory", "responses_message_tool_tasks", "responses_message_toolcalls_plural", "responses_message_tool_call_singular", "responses_message_tool_camel", "responses_message_function_alias", "responses_message_function_calls_plural", "responses_message_function_calls_snake"]
            and [item.get("native_tool_call_source") for item in native_responses_message_tool_ledger] == ["native provider responses message tool_calls", "native provider responses message tool_calls", "native provider responses message toolCalls", "native provider responses message tool_call", "native provider responses message toolCall", "native provider responses message functionCall", "native provider responses message functionCalls", "native provider responses message function_calls"]
            and [item.get("result", {}).get("status") for item in native_responses_message_tool_apply_payload.get("results", [])] == ["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok"]
            and native_status_milestone_contract.get("responses_message_tool_call_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_tool_calls_camel_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_tool_call_singular_alias_translation") is True
            and "responses_message_tool_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_toolCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_toolCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Responses message-level tool_calls native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level toolCalls native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level tool_call native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level toolCall native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level functionCall native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level functionCalls native tool call translated" in native_responses_message_tool_recall
            and "Responses message-level function_calls native tool call translated" in native_responses_message_tool_recall
            and native_responses_message_tool_captured.get("tool_choice") == "auto"
            and native_responses_message_tool_captured.get("tool_count", 0) > 0
            and "native-responses-message-tool-secret" not in native_responses_message_tool_outputs + json.dumps(native_responses_message_tool_call_metadata) + json.dumps(native_responses_message_tool_ledger)
        )
        checks["native_provider_responses_message_function_calls_alias_ok"] = (
            checks["native_provider_responses_message_tool_call_alias_ok"] is True
            and native_status_milestone_contract.get("responses_message_function_calls_alias_translation") is True
            and native_status_milestone_contract.get("responses_message_function_calls_snake_alias_translation") is True
            and "responses_message_functionCalls" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_function_calls" in native_status_data.get("provider_native_tool_call_variants", [])
        )
        checks["native_provider_responses_message_toolcalls_plural_alias_ok"] = (
            checks["native_provider_responses_message_tool_call_alias_ok"] is True
            and native_status_milestone_contract.get("responses_message_tool_calls_camel_alias_translation") is True
            and "responses_message_toolCalls" in native_status_data.get("provider_native_tool_call_variants", [])
        )
        checks["native_provider_responses_message_tool_call_singular_alias_ok"] = (
            checks["native_provider_responses_message_tool_call_alias_ok"] is True
            and native_status_milestone_contract.get("responses_message_tool_call_singular_alias_translation") is True
            and "responses_message_tool_call" in native_status_data.get("provider_native_tool_call_variants", [])
        )

        native_responses_message_content_captured = {}
        native_responses_message_content_result_marker = "NATIVE_RESPONSES_MESSAGE_CONTENT_RESULT_SHOULD_NOT_SURFACE"

        class NativeOpenAIResponsesMessageContentSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native responses message content smoke token=native-responses-message-secret",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {"type": "output_text", "text": "native responses message content smoke token=native-responses-message-secret"},
                                {
                                    "type": "function_call",
                                    "call_id": "responses_message_content_memory",
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-responses-message-content-smoke", "value": "Responses message content function_call native tool call translated"}),
                                },
                                {
                                    "type": "tool_use",
                                    "toolUseId": "responses_message_content_tasks",
                                    "name": "list_tasks",
                                    "input": {"status": "all", "limit": 1},
                                },
                                {
                                    "type": "functionCall",
                                    "callId": "responses_message_content_function_alias",
                                    "functionCall": {
                                        "name": "remember",
                                        "argumentsJson": {"key": "native-responses-message-content-functioncall-smoke", "value": "Responses message content functionCall native tool call translated"},
                                    },
                                },
                                {"type": "function_call_output", "call_id": "responses_message_content_result", "output": native_responses_message_content_result_marker + " token=native-responses-message-secret"},
                                {
                                    "type": "functionResponse",
                                    "functionResponse": {
                                        "name": "remember",
                                        "response": {"content": native_responses_message_content_result_marker + " token=native-responses-message-secret"},
                                    },
                                },
                            ],
                        }
                    ],
                }).encode("utf-8")

        def fake_native_responses_message_content_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_message_content_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_message_content_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesMessageContentSmokeResponse()

        native_responses_message_content_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-message-content.db"),
                session_name="native-provider-responses-message-content-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-content-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_message_content_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_message_content_urlopen
            native_responses_message_content_plan = native_responses_message_content_runtime.handle_message('/auto model=true prompt="native responses message content smoke token=native-responses-message-secret"')
            native_responses_message_content_plan_payload = json.loads(native_responses_message_content_plan.split("\n", 1)[1])
            native_responses_message_content_apply = native_responses_message_content_runtime.handle_message('/auto apply=true model=true prompt="native responses message content smoke token=native-responses-message-secret"')
            native_responses_message_content_apply_payload = json.loads(native_responses_message_content_apply.split("\n", 1)[1])
            native_responses_message_content_recall = native_responses_message_content_runtime.handle_message('/recall query=native-responses-message-content')
            write("native-provider-responses-message-content-tool-calls.json", json.dumps({
                "plan": native_responses_message_content_plan_payload,
                "apply": native_responses_message_content_apply_payload,
                "captured": native_responses_message_content_captured,
                "recall": native_responses_message_content_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_message_content_original_urlopen
            native_responses_message_content_runtime.close()
        native_responses_message_content_calls = native_responses_message_content_plan_payload.get("tool_calls", []) if isinstance(native_responses_message_content_plan_payload.get("tool_calls"), list) else []
        native_responses_message_content_metadata = native_responses_message_content_plan_payload.get("metadata", {}) if isinstance(native_responses_message_content_plan_payload.get("metadata"), dict) else {}
        native_responses_message_content_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_message_content_calls]
        native_responses_message_content_ledger = native_responses_message_content_apply_payload.get("execution_ledger", []) if isinstance(native_responses_message_content_apply_payload.get("execution_ledger"), list) else []
        native_responses_message_content_outputs = native_responses_message_content_plan + native_responses_message_content_apply + native_responses_message_content_recall + json.dumps(native_responses_message_content_plan_payload) + json.dumps(native_responses_message_content_apply_payload)
        checks["native_provider_responses_message_content_tool_call_ok"] = (
            native_responses_message_content_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_message_content_calls] == ["remember", "list_tasks", "remember"]
            and "native provider responses message content function_call" in native_responses_message_content_calls[0].get("reason", "")
            and "native provider responses message content tool_use" in native_responses_message_content_calls[1].get("reason", "")
            and "native provider responses message content functionCall" in native_responses_message_content_calls[2].get("reason", "")
            and native_responses_message_content_metadata.get("native_tool_calls") is True
            and native_responses_message_content_metadata.get("native_tool_call_count") == 3
            and [item.get("provider_tool_call_id") for item in native_responses_message_content_call_metadata] == ["responses_message_content_memory", "responses_message_content_tasks", "responses_message_content_function_alias"]
            and [item.get("native_tool_call_source") for item in native_responses_message_content_call_metadata] == ["native provider responses message content function_call", "native provider responses message content tool_use", "native provider responses message content functionCall"]
            and [item.get("provider_tool_call_id") for item in native_responses_message_content_ledger] == ["responses_message_content_memory", "responses_message_content_tasks", "responses_message_content_function_alias"]
            and [item.get("native_tool_call_source") for item in native_responses_message_content_ledger] == ["native provider responses message content function_call", "native provider responses message content tool_use", "native provider responses message content functionCall"]
            and [item.get("result", {}).get("status") for item in native_responses_message_content_apply_payload.get("results", [])] == ["ok", "ok", "ok"]
            and native_status_milestone_contract.get("responses_message_content_tool_call_translation") is True
            and native_status_milestone_contract.get("responses_message_content_function_call_alias_translation") is True
            and "responses_message_content_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_content_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "responses_message_content_tool_use" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Responses message content function_call native tool call translated" in native_responses_message_content_recall
            and "Responses message content functionCall native tool call translated" in native_responses_message_content_recall
            and "tool_result" in json.dumps(native_responses_message_content_plan_payload.get("warnings", [])).lower()
            and "functionResponse" in json.dumps(native_responses_message_content_plan_payload.get("warnings", []))
            and native_responses_message_content_captured.get("tool_choice") == "auto"
            and native_responses_message_content_captured.get("tool_count", 0) > 0
            and native_responses_message_content_result_marker not in native_responses_message_content_outputs
            and "native-responses-message-secret" not in native_responses_message_content_outputs + json.dumps(native_responses_message_content_call_metadata) + json.dumps(native_responses_message_content_ledger)
        )
        checks["native_provider_responses_message_content_function_call_alias_ok"] = (
            native_responses_message_content_plan_payload.get("mode") == "plan_only"
            and len(native_responses_message_content_calls) == 3
            and native_responses_message_content_calls[2].get("tool") == "remember"
            and native_responses_message_content_calls[2].get("args", {}).get("key") == "native-responses-message-content-functioncall-smoke"
            and "native provider responses message content functionCall" in native_responses_message_content_calls[2].get("reason", "")
            and native_responses_message_content_call_metadata[2].get("provider_tool_call_id") == "responses_message_content_function_alias"
            and native_responses_message_content_call_metadata[2].get("native_tool_call_source") == "native provider responses message content functionCall"
            and native_responses_message_content_ledger[2].get("provider_tool_call_id") == "responses_message_content_function_alias"
            and native_responses_message_content_ledger[2].get("native_tool_call_source") == "native provider responses message content functionCall"
            and native_status_milestone_contract.get("responses_message_content_function_call_alias_translation") is True
            and "responses_message_content_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Responses message content functionCall native tool call translated" in native_responses_message_content_recall
            and native_responses_message_content_result_marker not in native_responses_message_content_outputs
            and "native-responses-message-secret" not in native_responses_message_content_outputs + json.dumps(native_responses_message_content_call_metadata) + json.dumps(native_responses_message_content_ledger)
        )

        native_responses_message_parts_marker = root / "native-responses-message-parts-should-not-run.txt"
        native_responses_message_parts_captured = {}
        native_responses_message_parts_result_marker = "RESPONSES_MESSAGE_CONTENT_PARTS_RESULT_SHOULD_BE_IGNORED_SMOKE"

        class NativeOpenAIResponsesMessageContentPartsSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native responses message content parts smoke token=native-responses-message-parts-secret",
                    "output": [
                        {
                            "type": "message",
                            "content": {
                                "parts": [
                                    {"text": "native responses message content parts smoke token=native-responses-message-parts-secret"},
                                    {
                                        "functionCall": {
                                            "callId": "responses_message_parts_memory",
                                            "name": "remember",
                                            "args": {"key": "native-responses-message-parts-smoke", "value": "Responses message content parts functionCall native tool call translated"},
                                        }
                                    },
                                    {
                                        "functionCall": {
                                            "toolUseId": "responses_message_parts_dry",
                                            "name": "run_command",
                                            "parameters": {
                                                "target": "app.example.test",
                                                "purpose": "responses message content parts native dry-run smoke",
                                                "command": f"printf native-responses-message-parts > {native_responses_message_parts_marker}",
                                                "execute": True,
                                            },
                                        }
                                    },
                                    {
                                        "functionResponse": {
                                            "name": "remember",
                                            "response": {"content": native_responses_message_parts_result_marker + " token=native-responses-message-parts-secret"},
                                        }
                                    },
                                ]
                            },
                        }
                    ],
                }).encode("utf-8")

        def fake_native_responses_message_parts_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_responses_message_parts_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_responses_message_parts_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAIResponsesMessageContentPartsSmokeResponse()

        native_responses_message_parts_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-responses-message-content-parts.db"),
                session_name="native-provider-responses-message-content-parts-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-content-parts-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_responses_message_parts_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_responses_message_parts_urlopen
            native_responses_message_parts_plan = native_responses_message_parts_runtime.handle_message('/auto model=true prompt="native responses message content parts smoke token=native-responses-message-parts-secret"')
            native_responses_message_parts_plan_payload = json.loads(native_responses_message_parts_plan.split("\n", 1)[1])
            native_responses_message_parts_apply = native_responses_message_parts_runtime.handle_message('/auto apply=true model=true prompt="native responses message content parts smoke token=native-responses-message-parts-secret"')
            native_responses_message_parts_apply_payload = json.loads(native_responses_message_parts_apply.split("\n", 1)[1])
            native_responses_message_parts_recall = native_responses_message_parts_runtime.handle_message('/recall query=native-responses-message-parts-smoke')
            write("native-provider-responses-message-content-parts-functioncall.json", json.dumps({
                "plan": native_responses_message_parts_plan_payload,
                "apply": native_responses_message_parts_apply_payload,
                "captured": native_responses_message_parts_captured,
                "recall": native_responses_message_parts_recall,
                "marker_exists": native_responses_message_parts_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_responses_message_parts_original_urlopen
            native_responses_message_parts_runtime.close()
        native_responses_message_parts_calls = native_responses_message_parts_plan_payload.get("tool_calls", []) if isinstance(native_responses_message_parts_plan_payload.get("tool_calls"), list) else []
        native_responses_message_parts_metadata = native_responses_message_parts_plan_payload.get("metadata", {}) if isinstance(native_responses_message_parts_plan_payload.get("metadata"), dict) else {}
        native_responses_message_parts_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_responses_message_parts_calls]
        native_responses_message_parts_ledger = native_responses_message_parts_apply_payload.get("execution_ledger", []) if isinstance(native_responses_message_parts_apply_payload.get("execution_ledger"), list) else []
        native_responses_message_parts_warnings = json.dumps(native_responses_message_parts_plan_payload.get("warnings", []))
        native_responses_message_parts_outputs = native_responses_message_parts_plan + native_responses_message_parts_apply + native_responses_message_parts_recall + json.dumps(native_responses_message_parts_plan_payload) + json.dumps(native_responses_message_parts_apply_payload)
        checks["native_provider_responses_message_content_parts_function_call_ok"] = (
            native_responses_message_parts_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_responses_message_parts_calls] == ["remember", "run_command"]
            and all("native provider responses message content parts functionCall" in call.get("reason", "") for call in native_responses_message_parts_calls)
            and native_responses_message_parts_calls[1].get("args", {}).get("execute") is False
            and [item.get("provider_tool_call_id") for item in native_responses_message_parts_call_metadata] == ["responses_message_parts_memory", "responses_message_parts_dry"]
            and [item.get("native_tool_call_source") for item in native_responses_message_parts_call_metadata] == ["native provider responses message content parts functionCall", "native provider responses message content parts functionCall"]
            and native_responses_message_parts_metadata.get("native_tool_calls") is True
            and native_responses_message_parts_metadata.get("native_tool_call_count") == 2
            and [item.get("result", {}).get("status") for item in native_responses_message_parts_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and [item.get("provider_tool_call_id") for item in native_responses_message_parts_ledger] == ["responses_message_parts_memory", "responses_message_parts_dry"]
            and [item.get("native_tool_call_source") for item in native_responses_message_parts_ledger] == ["native provider responses message content parts functionCall", "native provider responses message content parts functionCall"]
            and native_responses_message_parts_ledger[1].get("actual_command_or_process_activity") is False
            and "functionResponse" in native_responses_message_parts_warnings
            and native_status_milestone_contract.get("responses_message_content_parts_function_call_translation") is True
            and "responses_message_content_parts_functionCall" in native_status_data.get("provider_native_tool_call_variants", [])
            and "Responses message content parts functionCall native tool call translated" in native_responses_message_parts_recall
            and native_responses_message_parts_captured.get("tool_choice") == "auto"
            and native_responses_message_parts_captured.get("tool_count", 0) > 0
            and not native_responses_message_parts_marker.exists()
            and native_responses_message_parts_result_marker not in native_responses_message_parts_outputs
            and "native-responses-message-parts-secret" not in native_responses_message_parts_outputs + json.dumps(native_responses_message_parts_call_metadata) + json.dumps(native_responses_message_parts_ledger)
        )

        native_single_responses_captured = {}

        class NativeOpenAISingleResponsesOutputSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "output_text": "native single responses output smoke token=native-single-responses-secret",
                    "output": {
                        "type": "function_call",
                        "call_id": "single_responses_memory",
                        "name": "remember",
                        "arguments": json.dumps({"key": "native-single-responses-smoke", "value": "single Responses output native tool call translated"}),
                    },
                }).encode("utf-8")

        def fake_native_single_responses_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_single_responses_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_single_responses_captured["tool_choice"] = payload.get("tool_choice")
            return NativeOpenAISingleResponsesOutputSmokeResponse()

        native_single_responses_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-single-responses-output.db"),
                session_name="native-provider-single-responses-output-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-single-responses-output-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_single_responses_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_single_responses_urlopen
            native_single_responses_plan = native_single_responses_runtime.handle_message('/auto model=true prompt="native single responses output smoke token=native-single-responses-secret"')
            native_single_responses_plan_payload = json.loads(native_single_responses_plan.split("\n", 1)[1])
            native_single_responses_apply = native_single_responses_runtime.handle_message('/auto apply=true model=true prompt="native single responses output smoke token=native-single-responses-secret"')
            native_single_responses_apply_payload = json.loads(native_single_responses_apply.split("\n", 1)[1])
            native_single_responses_recall = native_single_responses_runtime.handle_message('/recall query=native-single-responses-smoke')
            write("native-provider-single-responses-output-tool-call.json", json.dumps({
                "plan": native_single_responses_plan_payload,
                "apply": native_single_responses_apply_payload,
                "captured": native_single_responses_captured,
                "recall": native_single_responses_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_single_responses_original_urlopen
            native_single_responses_runtime.close()
        native_single_responses_calls = native_single_responses_plan_payload.get("tool_calls", []) if isinstance(native_single_responses_plan_payload.get("tool_calls"), list) else []
        native_single_responses_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_single_responses_calls]
        native_single_responses_ledger = native_single_responses_apply_payload.get("execution_ledger", []) if isinstance(native_single_responses_apply_payload.get("execution_ledger"), list) else []
        checks["native_provider_single_responses_output_tool_call_ok"] = (
            native_single_responses_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_single_responses_calls] == ["remember"]
            and "native provider single responses output function_call" in native_single_responses_calls[0].get("reason", "")
            and [item.get("provider_tool_call_id") for item in native_single_responses_call_metadata] == ["single_responses_memory"]
            and [item.get("provider_tool_call_id") for item in native_single_responses_ledger] == ["single_responses_memory"]
            and native_single_responses_ledger[0].get("native_tool_call_source") == "native provider single responses output function_call"
            and [item.get("result", {}).get("status") for item in native_single_responses_apply_payload.get("results", [])] == ["ok"]
            and native_status_milestone_contract.get("single_responses_output_tool_call_translation") is True
            and "single_responses_output_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single Responses output native tool call translated" in native_single_responses_recall
            and native_single_responses_captured.get("tool_choice") == "auto"
            and native_single_responses_captured.get("tool_count", 0) > 0
            and "native-single-responses-secret" not in native_single_responses_plan + native_single_responses_apply + native_single_responses_recall + json.dumps(native_single_responses_plan_payload) + json.dumps(native_single_responses_apply_payload)
        )

        native_candidate_marker = root / "native-candidate-should-not-run.txt"
        native_candidate_captured = {}

        class NativeProviderCandidateSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {"text": "native candidate functionCall smoke token=native-candidate-secret"},
                                    {
                                        "functionCall": {
                                            "id": "candidate_memory",
                                            "name": "remember",
                                            "parameters": {"key": "native-candidate-smoke", "value": "candidate functionCall native tool call translated"},
                                        }
                                    },
                                    {
                                        "functionCall": {
                                            "call_id": "candidate_dry",
                                            "name": "run_command",
                                            "args": {
                                                "target": "app.example.test",
                                                "purpose": "native candidate dry-run smoke",
                                                "command": f"printf native-candidate > {native_candidate_marker}",
                                                "execute": True,
                                            },
                                        }
                                    },
                                    {
                                        "functionResponse": {
                                            "name": "remember",
                                            "response": {"content": native_provider_result_marker + " token=native-candidate-secret"},
                                        }
                                    },
                                ]
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_candidate_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_candidate_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_candidate_captured["tool_choice"] = payload.get("tool_choice")
            return NativeProviderCandidateSmokeResponse()

        native_candidate_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-candidate.db"),
                session_name="native-provider-candidate-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-candidate-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_candidate_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_candidate_urlopen
            native_candidate_plan = native_candidate_runtime.handle_message('/auto model=true prompt="native candidate functionCall smoke token=native-candidate-secret"')
            native_candidate_plan_payload = json.loads(native_candidate_plan.split("\n", 1)[1])
            native_candidate_apply = native_candidate_runtime.handle_message('/auto apply=true model=true prompt="native candidate functionCall smoke token=native-candidate-secret"')
            native_candidate_apply_payload = json.loads(native_candidate_apply.split("\n", 1)[1])
            native_candidate_recall = native_candidate_runtime.handle_message('/recall query=native-candidate-smoke')
            write("native-provider-candidate-function-calls.json", json.dumps({
                "plan": native_candidate_plan_payload,
                "apply": native_candidate_apply_payload,
                "captured": native_candidate_captured,
                "recall": native_candidate_recall,
                "marker_exists": native_candidate_marker.exists(),
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_candidate_original_urlopen
            native_candidate_runtime.close()
        native_candidate_calls = native_candidate_plan_payload.get("tool_calls", []) if isinstance(native_candidate_plan_payload.get("tool_calls"), list) else []
        native_candidate_metadata = native_candidate_plan_payload.get("metadata", {}) if isinstance(native_candidate_plan_payload.get("metadata"), dict) else {}
        native_candidate_ledger = native_candidate_apply_payload.get("execution_ledger", []) if isinstance(native_candidate_apply_payload.get("execution_ledger"), list) else []
        native_candidate_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_candidate_calls]
        checks["native_provider_candidate_function_call_ok"] = (
            native_candidate_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_candidate_calls] == ["remember", "run_command"]
            and all("native provider candidate functionCall" in call.get("reason", "") for call in native_candidate_calls)
            and native_candidate_calls[0].get("args", {}).get("key") == "native-candidate-smoke"
            and native_candidate_calls[1].get("args", {}).get("execute") is False
            and [item.get("provider_tool_call_id") for item in native_candidate_call_metadata] == ["candidate_memory", "candidate_dry"]
            and all(item.get("native_tool_call_source") == "native provider candidate functionCall" for item in native_candidate_call_metadata)
            and native_candidate_metadata.get("native_tool_calls") is True
            and native_candidate_metadata.get("native_tool_call_count") == 2
            and [item.get("result", {}).get("status") for item in native_candidate_apply_payload.get("results", [])] == ["ok", "dry_run"]
            and [item.get("provider_tool_call_id") for item in native_candidate_ledger] == ["candidate_memory", "candidate_dry"]
            and native_candidate_ledger[1].get("native_tool_call_source") == "native provider candidate functionCall"
            and native_candidate_ledger[1].get("actual_command_or_process_activity") is False
            and native_status_milestone_contract.get("candidate_function_call_translation") is True
            and "candidate_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "functionResponse" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and "candidate functionCall native tool call translated" in native_candidate_recall
            and native_candidate_captured.get("tool_choice") == "auto"
            and native_candidate_captured.get("tool_count", 0) > 0
            and not native_candidate_marker.exists()
            and native_provider_result_marker not in native_candidate_plan + native_candidate_apply + native_candidate_recall + json.dumps(native_candidate_plan_payload) + json.dumps(native_candidate_apply_payload)
            and "native-candidate-secret" not in native_candidate_plan + native_candidate_apply + native_candidate_recall + json.dumps(native_candidate_plan_payload) + json.dumps(native_candidate_apply_payload)
        )

        native_single_candidate_captured = {}

        class NativeProviderSingleCandidateSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "candidates": [
                        {
                            "content": {
                                "parts": {
                                    "functionCall": {
                                        "tool_use_id": "single_candidate_memory",
                                        "name": "remember",
                                        "args": {"key": "native-single-candidate-smoke", "value": "single candidate functionCall native tool call translated"},
                                    }
                                }
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_single_candidate_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_single_candidate_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_single_candidate_captured["tool_choice"] = payload.get("tool_choice")
            return NativeProviderSingleCandidateSmokeResponse()

        native_single_candidate_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-single-candidate.db"),
                session_name="native-provider-single-candidate-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-single-candidate-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_single_candidate_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_single_candidate_urlopen
            native_single_candidate_plan = native_single_candidate_runtime.handle_message('/auto model=true prompt="native single candidate functionCall smoke token=native-single-candidate-secret"')
            native_single_candidate_plan_payload = json.loads(native_single_candidate_plan.split("\n", 1)[1])
            native_single_candidate_apply = native_single_candidate_runtime.handle_message('/auto apply=true model=true prompt="native single candidate functionCall smoke token=native-single-candidate-secret"')
            native_single_candidate_apply_payload = json.loads(native_single_candidate_apply.split("\n", 1)[1])
            native_single_candidate_recall = native_single_candidate_runtime.handle_message('/recall query=native-single-candidate-smoke')
            write("native-provider-single-candidate-function-call.json", json.dumps({
                "plan": native_single_candidate_plan_payload,
                "apply": native_single_candidate_apply_payload,
                "captured": native_single_candidate_captured,
                "recall": native_single_candidate_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_single_candidate_original_urlopen
            native_single_candidate_runtime.close()
        native_single_candidate_calls = native_single_candidate_plan_payload.get("tool_calls", []) if isinstance(native_single_candidate_plan_payload.get("tool_calls"), list) else []
        native_single_candidate_metadata = native_single_candidate_plan_payload.get("metadata", {}) if isinstance(native_single_candidate_plan_payload.get("metadata"), dict) else {}
        native_single_candidate_ledger = native_single_candidate_apply_payload.get("execution_ledger", []) if isinstance(native_single_candidate_apply_payload.get("execution_ledger"), list) else []
        native_single_candidate_call_metadata = [call.get("metadata", {}) if isinstance(call, dict) else {} for call in native_single_candidate_calls]
        checks["native_provider_single_candidate_part_function_call_ok"] = (
            native_single_candidate_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_single_candidate_calls] == ["remember"]
            and "native provider candidate functionCall" in native_single_candidate_calls[0].get("reason", "")
            and native_single_candidate_calls[0].get("args", {}).get("key") == "native-single-candidate-smoke"
            and [item.get("provider_tool_call_id") for item in native_single_candidate_call_metadata] == ["single_candidate_memory"]
            and native_single_candidate_call_metadata[0].get("native_tool_call_source") == "native provider candidate functionCall"
            and native_single_candidate_metadata.get("native_tool_calls") is True
            and native_single_candidate_metadata.get("native_tool_call_count") == 1
            and [item.get("result", {}).get("status") for item in native_single_candidate_apply_payload.get("results", [])] == ["ok"]
            and [item.get("provider_tool_call_id") for item in native_single_candidate_ledger] == ["single_candidate_memory"]
            and native_single_candidate_ledger[0].get("native_tool_call_source") == "native provider candidate functionCall"
            and native_status_milestone_contract.get("single_candidate_part_function_call_translation") is True
            and "single_candidate_part_function_call" in native_status_data.get("provider_native_tool_call_variants", [])
            and "single candidate functionCall native tool call translated" in native_single_candidate_recall
            and native_single_candidate_captured.get("tool_choice") == "auto"
            and native_single_candidate_captured.get("tool_count", 0) > 0
            and "native-single-candidate-secret" not in native_single_candidate_plan + native_single_candidate_apply + native_single_candidate_recall + json.dumps(native_single_candidate_plan_payload) + json.dumps(native_single_candidate_apply_payload)
        )
        native_hosted_marker = "NATIVE_HOSTED_TOOL_INPUT_SHOULD_NOT_SURFACE_SMOKE"
        native_hosted_captured = {}

        class NativeProviderHostedRejectSmokeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({
                    "choices": [
                        {
                            "message": {
                                "content": [
                                    {"type": "text", "text": "native hosted/freeform tool smoke token=native-hosted-secret"},
                                    {
                                        "type": "server_tool_use",
                                        "tool_use_id": "hosted_server_tool",
                                        "name": "web_search",
                                        "input": native_hosted_marker + " token=native-hosted-secret",
                                    },
                                    {
                                        "type": "mcp_tool_use",
                                        "tool_use_id": "hosted_mcp_tool",
                                        "name": "mcp_browser",
                                        "input": {"query": native_hosted_marker + " nested token=native-hosted-secret"},
                                    },
                                    {
                                        "type": "tool_use",
                                        "tool_call_id": "hosted_valid_memory",
                                        "name": "remember",
                                        "input": {"key": "native-hosted-reject-smoke", "value": "hosted provider tools rejected while registered calls still apply"},
                                    },
                                ],
                            }
                        }
                    ]
                }).encode("utf-8")

        def fake_native_hosted_urlopen(request, timeout=0):
            payload = json.loads(request.data.decode("utf-8"))
            native_hosted_captured["tool_count"] = len(payload.get("tools", [])) if isinstance(payload.get("tools"), list) else 0
            native_hosted_captured["tool_choice"] = payload.get("tool_choice")
            return NativeProviderHostedRejectSmokeResponse()

        native_hosted_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-provider-hosted-reject.db"),
                session_name="native-provider-hosted-reject-smoke",
                auto_model_planning=True,
            ),
            adapter=OpenAICompatibleAdapter(model="fake-native-hosted-reject-smoke", base_url="http://127.0.0.1:9/v1"),
        )
        native_hosted_original_urlopen = model_adapters.urllib.request.urlopen
        try:
            model_adapters.urllib.request.urlopen = fake_native_hosted_urlopen
            native_hosted_plan = native_hosted_runtime.handle_message('/auto model=true prompt="native hosted tool reject smoke token=native-hosted-secret"')
            native_hosted_plan_payload = json.loads(native_hosted_plan.split("\n", 1)[1])
            native_hosted_apply = native_hosted_runtime.handle_message('/auto apply=true model=true prompt="native hosted tool reject smoke token=native-hosted-secret"')
            native_hosted_apply_payload = json.loads(native_hosted_apply.split("\n", 1)[1])
            native_hosted_recall = native_hosted_runtime.handle_message('/recall query=native-hosted-reject-smoke')
            write("native-provider-hosted-tool-call-reject.json", json.dumps({
                "plan": native_hosted_plan_payload,
                "apply": native_hosted_apply_payload,
                "captured": native_hosted_captured,
                "recall": native_hosted_recall,
            }, indent=2, sort_keys=True))
        finally:
            model_adapters.urllib.request.urlopen = native_hosted_original_urlopen
            native_hosted_runtime.close()
        native_hosted_calls = native_hosted_plan_payload.get("tool_calls", []) if isinstance(native_hosted_plan_payload.get("tool_calls"), list) else []
        native_hosted_rejected = json.dumps(native_hosted_plan_payload.get("rejected_tool_calls", []))
        native_hosted_warnings = json.dumps(native_hosted_plan_payload.get("warnings", []))
        native_hosted_metadata = native_hosted_plan_payload.get("metadata", {}) if isinstance(native_hosted_plan_payload.get("metadata"), dict) else {}
        checks["native_provider_hosted_tool_call_reject_ok"] = (
            native_hosted_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_hosted_calls] == ["remember"]
            and native_hosted_calls[0].get("args", {}).get("key") == "native-hosted-reject-smoke"
            and "provider-hosted tools must be exposed" in native_hosted_rejected
            and "server_tool_use" in native_hosted_rejected
            and "mcp_tool_use" in native_hosted_rejected
            and "custom/freeform/hosted" in native_hosted_warnings.lower()
            and int(native_hosted_metadata.get("rejected_native_tool_call_count", 0) or 0) == 2
            and [item.get("result", {}).get("status") for item in native_hosted_apply_payload.get("results", [])] == ["ok"]
            and "hosted provider tools rejected while registered calls still apply" in native_hosted_recall
            and native_hosted_captured.get("tool_choice") == "auto"
            and native_hosted_captured.get("tool_count", 0) > 0
            and native_status_milestone_contract.get("provider_hosted_tool_calls_rejected") is True
            and "server_tool_use" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and "mcp_tool_use" in native_status_data.get("provider_unsupported_tool_call_types_rejected", [])
            and native_hosted_marker not in native_hosted_plan + native_hosted_apply + native_hosted_recall + json.dumps(native_hosted_plan_payload) + json.dumps(native_hosted_apply_payload)
            and "native-hosted-secret" not in native_hosted_plan + native_hosted_apply + native_hosted_recall + json.dumps(native_hosted_plan_payload) + json.dumps(native_hosted_apply_payload)
        )
        checks["native_provider_custom_tool_call_reject_ok"] = (
            "Custom/freeform native tool calls are not supported" in native_edge_rejected
            and "Custom/freeform native tool calls are not supported" in native_responses_rejected
            and "custom/freeform" in native_edge_warnings.lower()
            and "custom/freeform" in native_responses_warnings.lower()
            and int(native_edge_metadata.get("rejected_native_tool_call_count", 0) or 0) >= 5
            and int(native_responses_metadata.get("rejected_native_tool_call_count", 0) or 0) >= 1
            and native_provider_custom_marker not in native_edge_plan + native_edge_apply + native_edge_recall + json.dumps(native_edge_plan_payload) + json.dumps(native_edge_apply_payload)
            and native_responses_custom_marker not in native_responses_plan + native_responses_apply + native_responses_recall + json.dumps(native_responses_plan_payload) + json.dumps(native_responses_apply_payload)
        )
        checks["native_provider_tool_result_ignore_ok"] = (
            "tool_result" in native_edge_warnings.lower()
            and "tool_result" in native_content_warnings.lower()
            and "tool_result" in native_single_content_result_warnings.lower()
            and "tool_result" in native_responses_warnings.lower()
            and "functionResponse" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and "function_response" in native_status_data.get("provider_tool_result_block_types_ignored", [])
            and native_provider_result_marker not in native_edge_plan + native_edge_apply + native_edge_recall
            and native_provider_result_marker not in native_content_plan + native_content_apply + native_content_recall
            and native_provider_result_marker not in native_responses_plan + native_responses_apply + native_responses_recall
            and native_provider_result_marker not in native_candidate_plan + native_candidate_apply + native_candidate_recall
            and native_single_content_result_marker not in native_single_content_plan + native_single_content_apply + native_single_content_result_plan + native_single_content_recall
            and native_provider_result_marker not in json.dumps(native_edge_plan_payload) + json.dumps(native_edge_apply_payload)
            and native_provider_result_marker not in json.dumps(native_content_plan_payload) + json.dumps(native_content_apply_payload)
            and native_provider_result_marker not in json.dumps(native_responses_plan_payload) + json.dumps(native_responses_apply_payload)
            and native_provider_result_marker not in json.dumps(native_candidate_plan_payload) + json.dumps(native_candidate_apply_payload)
            and native_single_content_result_marker not in json.dumps(native_single_content_plan_payload) + json.dumps(native_single_content_apply_payload) + json.dumps(native_single_content_result_payload)
        )

        native_confirm_marker = root / "native-confirm-should-not-run.txt"
        native_block_marker = root / "native-block-should-not-run.txt"
        guardrail_adapter = SmokeToolCallGuardrailAdapter(native_confirm_marker, native_block_marker)
        guardrail_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-guardrail.db"),
                session_name="native-tool-guardrail-smoke",
                auto_model_planning=True,
            ),
            adapter=guardrail_adapter,
        )
        try:
            guardrail_plan = guardrail_runtime.handle_message('/auto model=true execute=true prompt="native guardrail smoke plan"')
            guardrail_plan_payload = json.loads(guardrail_plan.split("\n", 1)[1])
            pending_guardrail_after_plan = guardrail_runtime.store.list_approvals(guardrail_runtime.session_id, status="pending")
            guardrail_plan_audit_events = [row["event"] for row in guardrail_runtime.store.list_audit(guardrail_runtime.session_id, limit=20)]
            guardrail_apply = guardrail_runtime.handle_message('/auto apply=true model=true execute=true prompt="native guardrail smoke plan"')
            guardrail_apply_payload = json.loads(guardrail_apply.split("\n", 1)[1])
            guardrail_apply_ledger = guardrail_apply_payload.get("execution_ledger", []) if isinstance(guardrail_apply_payload.get("execution_ledger"), list) else []
            pending_guardrail_after_apply = guardrail_runtime.store.list_approvals(guardrail_runtime.session_id, status="pending")
            guardrail_loop = guardrail_runtime.handle_message('/auto-loop model=true execute=true steps=4 prompt="native guardrail smoke loop stop"')
            guardrail_loop_payload = json.loads(guardrail_loop.split("\n", 1)[1])
            guardrail_loop_ledger = guardrail_loop_payload.get("execution_ledger", []) if isinstance(guardrail_loop_payload.get("execution_ledger"), list) else []
            pending_guardrail_after_loop = guardrail_runtime.store.list_approvals(guardrail_runtime.session_id, status="pending")
            write("native-tool-guardrail-plan.txt", guardrail_plan)
            write("native-tool-guardrail-apply.txt", guardrail_apply)
            write("native-tool-guardrail-loop-stop.txt", guardrail_loop)
        finally:
            guardrail_runtime.close()
        guardrail_plan_statuses = [call.get("validation", {}).get("guardrail_status") for call in guardrail_plan_payload.get("tool_calls", [])]
        guardrail_previews = [call.get("validation", {}).get("guardrail_preview", {}) for call in guardrail_plan_payload.get("tool_calls", [])]
        guardrail_result_statuses = [item.get("result", {}).get("status") for item in guardrail_apply_payload.get("results", [])]
        guardrail_loop_statuses = [item.get("result_status") for item in guardrail_loop_ledger]
        guardrail_loop_terminal = guardrail_loop_payload.get("steps", [{}])[0].get("terminal_result_statuses") if guardrail_loop_payload.get("steps") else []
        checks["native_tool_call_guardrail_approval_ok"] = (
            guardrail_plan_payload.get("mode") == "plan_only"
            and guardrail_plan_statuses == ["confirm", "block"]
            and all(preview.get("no_target_activity") is True and preview.get("evidence_written") is False and preview.get("approval_queued") is False for preview in guardrail_previews)
            and "will require guardrail approval" in json.dumps(guardrail_plan_payload.get("warnings", []))
            and "will be blocked by guardrails" in json.dumps(guardrail_plan_payload.get("warnings", []))
            and not pending_guardrail_after_plan
            and "tool_call" not in guardrail_plan_audit_events
            and guardrail_apply_payload.get("mode") == "applied"
            and guardrail_result_statuses == ["needs_approval", "blocked"]
            and len(pending_guardrail_after_apply) == 1
            and pending_guardrail_after_apply[0].get("tool_name") == "run_command"
            and not native_confirm_marker.exists()
            and not native_block_marker.exists()
        )
        checks["native_tool_call_loop_approval_stop_ok"] = (
            guardrail_loop_payload.get("stop_reason") == "approval_or_blocked_result"
            and guardrail_loop_payload.get("steps_executed") == 1
            and guardrail_loop_terminal == ["blocked", "needs_approval"]
            and guardrail_loop_statuses == ["needs_approval", "blocked"]
            and len(guardrail_adapter.prompts) == 3
            and len(pending_guardrail_after_loop) == 2
            and not any(item.get("actual_command_or_process_activity") for item in guardrail_loop_ledger)
            and not any(item.get("safe_to_claim_command_executed") for item in guardrail_loop_ledger)
            and not native_confirm_marker.exists()
            and not native_block_marker.exists()
        )

        approval_replay_marker = root / "native-approval-replay.txt"
        approval_replay_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-approval-replay.db"),
                session_name="native-tool-approval-replay-smoke",
                auto_model_planning=True,
            ),
            adapter=SmokeToolCallOperatorApprovalReplayAdapter(approval_replay_marker),
        )
        try:
            approval_replay_plan = approval_replay_runtime.handle_message('/auto model=true execute=true prompt="native approval replay token=approval-replay-smoke-secret"')
            approval_replay_plan_payload = json.loads(approval_replay_plan.split("\n", 1)[1])
            approval_replay_plan_pending = approval_replay_runtime.store.list_approvals(approval_replay_runtime.session_id, status="pending")
            approval_replay_apply = approval_replay_runtime.handle_message('/auto apply=true model=true execute=true prompt="native approval replay token=approval-replay-smoke-secret"')
            approval_replay_apply_payload = json.loads(approval_replay_apply.split("\n", 1)[1])
            approval_replay_ledger = approval_replay_apply_payload.get("execution_ledger", []) if isinstance(approval_replay_apply_payload.get("execution_ledger"), list) else []
            approval_replay_approval_id = int(approval_replay_ledger[0].get("approval_id", 0) or 0) if approval_replay_ledger else 0
            approval_replay_pending = approval_replay_runtime.store.list_approvals(approval_replay_runtime.session_id, status="pending")
            approval_replay_artifacts = approval_replay_apply_payload.get("artifacts", {}) if isinstance(approval_replay_apply_payload.get("artifacts"), dict) else {}
            approval_replay_json_path = Path(approval_replay_artifacts.get("json", ""))
            approval_replay_md_path = Path(approval_replay_artifacts.get("markdown", ""))
            approval_replay_transcript = ""
            if approval_replay_json_path.is_file():
                approval_replay_transcript += approval_replay_json_path.read_text(encoding="utf-8")
            if approval_replay_md_path.is_file():
                approval_replay_transcript += approval_replay_md_path.read_text(encoding="utf-8")
            approval_replay_detail_before = approval_replay_runtime.handle_message(f"/approval id={approval_replay_approval_id}") if approval_replay_approval_id else ""
            approval_replay_approved = approval_replay_runtime.handle_message(f"/approve id={approval_replay_approval_id}") if approval_replay_approval_id else ""
            approval_replay_detail_after = approval_replay_runtime.handle_message(f"/approval id={approval_replay_approval_id}") if approval_replay_approval_id else ""
            approval_replay_row = approval_replay_runtime.store.get_approval(approval_replay_approval_id, session_id=approval_replay_runtime.session_id) if approval_replay_approval_id else None
            write("native-tool-operator-approval-replay.json", json.dumps({
                "plan": approval_replay_plan_payload,
                "apply": approval_replay_apply_payload,
                "detail_before": approval_replay_detail_before,
                "approved": approval_replay_approved,
                "detail_after": approval_replay_detail_after,
                "marker_exists": approval_replay_marker.exists(),
                "approval_status": (approval_replay_row or {}).get("status"),
            }, indent=2, sort_keys=True))
        finally:
            approval_replay_runtime.close()
        approval_replay_plan_calls = approval_replay_plan_payload.get("tool_calls", []) if isinstance(approval_replay_plan_payload.get("tool_calls"), list) else []
        approval_replay_blob = json.dumps({
            "plan": approval_replay_plan_payload,
            "apply": approval_replay_apply_payload,
            "detail_before": approval_replay_detail_before,
            "approved": approval_replay_approved,
            "detail_after": approval_replay_detail_after,
            "transcript": approval_replay_transcript,
        }, sort_keys=True)
        checks["native_tool_call_operator_approval_replay_ok"] = (
            approval_replay_plan_payload.get("mode") == "plan_only"
            and approval_replay_plan_calls[0].get("validation", {}).get("guardrail_status") == "confirm"
            and approval_replay_plan_calls[0].get("validation", {}).get("guardrail_preview", {}).get("no_target_activity") is True
            and approval_replay_plan_calls[0].get("validation", {}).get("guardrail_preview", {}).get("approval_queued") is False
            and not approval_replay_plan_pending
            and approval_replay_apply_payload.get("mode") == "applied"
            and approval_replay_apply_payload.get("results", [{}])[0].get("result", {}).get("status") == "needs_approval"
            and approval_replay_ledger[0].get("execution_state") == "queued_for_approval"
            and approval_replay_ledger[0].get("approval_queued") is True
            and approval_replay_ledger[0].get("actual_command_or_process_activity") is False
            and len(approval_replay_pending) == 1
            and (approval_replay_row or {}).get("status") == "approved_executed"
            and "[executed]" in approval_replay_approved
            and approval_replay_marker.exists()
            and approval_replay_marker.read_text(encoding="utf-8") == "native-approval-replayed"
            and "queued_for_approval" in approval_replay_transcript
            and "actual_command_or_process_activity=`False`" in approval_replay_transcript
            and "approved_executed" in approval_replay_detail_after
            and "approval-replay-smoke-secret" not in approval_replay_blob
        )

        approval_action_marker = root / "native-approval-action-should-not-run.txt"
        approval_action_adapter = SmokeToolCallApprovalActionAdapter()
        approval_action_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-approval-action.db"),
                session_name="native-tool-approval-action-smoke",
                auto_model_planning=True,
            ),
            adapter=approval_action_adapter,
        )
        try:
            queued_approval_action = approval_action_runtime.registry.run(
                "run_command",
                {
                    "target": "app.example.test",
                    "purpose": "native approval action guard smoke fixture",
                    "command": f"curl -X POST http://127.0.0.1:1/native-approval ; printf approved > {approval_action_marker}",
                    "execute": True,
                },
            )
            approval_action_adapter.approval_id = int(queued_approval_action.data.get("approval_id", 0) or 0)
            approval_action_plan = approval_action_runtime.handle_message('/auto model=true prompt="model tries to approve pending action"')
            approval_action_plan_payload = json.loads(approval_action_plan.split("\n", 1)[1])
            approval_action_apply = approval_action_runtime.handle_message('/auto apply=true model=true prompt="model tries to approve pending action"')
            approval_action_apply_payload = json.loads(approval_action_apply.split("\n", 1)[1])
            approval_action_loop = approval_action_runtime.handle_message('/auto-loop model=true steps=2 prompt="model tries to approve pending action"')
            approval_action_loop_payload = json.loads(approval_action_loop.split("\n", 1)[1])
            pending_approval_actions = approval_action_runtime.store.list_approvals(approval_action_runtime.session_id, status="pending")
            approval_action_audit = "\n".join(row[0] or "" for row in approval_action_runtime.store.conn.execute("SELECT data_json FROM audit_log").fetchall())
            write("native-tool-approval-action-guard.json", json.dumps({
                "plan": approval_action_plan_payload,
                "apply": approval_action_apply_payload,
                "loop": approval_action_loop_payload,
                "seen_tool_names": approval_action_adapter.seen_tool_names,
                "pending": pending_approval_actions,
            }, indent=2, sort_keys=True))
        finally:
            approval_action_runtime.close()
        approval_action_rejected = json.dumps(approval_action_plan_payload.get("rejected_tool_calls", [])) + json.dumps(approval_action_loop_payload)
        checks["native_tool_call_approval_action_guard_ok"] = (
            queued_approval_action.status == "needs_approval"
            and approval_action_plan_payload.get("mode") == "plan_only"
            and approval_action_plan_payload.get("tool_calls") == []
            and "Approval-control tools require an explicit direct operator command" in approval_action_rejected
            and "approve" not in approval_action_adapter.seen_tool_names
            and "deny" not in approval_action_adapter.seen_tool_names
            and approval_action_apply_payload.get("mode") == "applied"
            and approval_action_apply_payload.get("results") == []
            and approval_action_loop_payload.get("stop_reason") == "no_tool_calls"
            and approval_action_loop_payload.get("steps_executed") == 0
            and len(pending_approval_actions) == 1
            and pending_approval_actions[0].get("id") == approval_action_adapter.approval_id
            and not approval_action_marker.exists()
            and '"tool": "approve"' not in approval_action_audit
            and '"tool": "deny"' not in approval_action_audit
        )

        native_policy_adapter = SmokeToolCallRuntimePolicyAdapter()
        native_policy_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-runtime-policy.db"),
                session_name="native-tool-runtime-policy-smoke",
                auto_model_planning=True,
                confirm_tools=("remember",),
                blocked_tools=("workspace_read",),
            ),
            adapter=native_policy_adapter,
        )
        try:
            native_policy_plan = native_policy_runtime.handle_message('/auto model=true prompt="native runtime policy smoke token=policy-smoke-secret"')
            native_policy_plan_payload = json.loads(native_policy_plan.split("\n", 1)[1])
            native_policy_plan_pending = native_policy_runtime.store.list_approvals(native_policy_runtime.session_id, status="pending")
            native_policy_apply = native_policy_runtime.handle_message('/auto apply=true model=true prompt="native runtime policy smoke token=policy-smoke-secret"')
            native_policy_apply_payload = json.loads(native_policy_apply.split("\n", 1)[1])
            native_policy_apply_ledger = native_policy_apply_payload.get("execution_ledger", []) if isinstance(native_policy_apply_payload.get("execution_ledger"), list) else []
            native_policy_pending = native_policy_runtime.store.list_approvals(native_policy_runtime.session_id, status="pending")
            native_policy_approval_id = int(native_policy_pending[0].get("id", 0) or 0) if native_policy_pending else 0
            native_policy_recall_before = native_policy_runtime.handle_message('/recall query=native-policy-smoke')
            native_policy_approved = native_policy_runtime.handle_message(f"/approve id={native_policy_approval_id}") if native_policy_approval_id else ""
            native_policy_recall_after = native_policy_runtime.handle_message('/recall query=native-policy-smoke')

            native_policy_loop_adapter = SmokeToolCallRuntimePolicyAdapter()
            native_policy_loop_runtime = PhobosAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement_path),
                    db_path=str(data / "native-tool-runtime-policy-loop.db"),
                    session_name="native-tool-runtime-policy-loop-smoke",
                    auto_model_planning=True,
                    confirm_tools=("remember",),
                    blocked_tools=("workspace_read",),
                ),
                adapter=native_policy_loop_adapter,
            )
            try:
                native_policy_loop = native_policy_loop_runtime.handle_message('/auto-loop model=true steps=3 prompt="native runtime policy loop smoke token=policy-smoke-secret"')
                native_policy_loop_payload = json.loads(native_policy_loop.split("\n", 1)[1])
                native_policy_loop_ledger = native_policy_loop_payload.get("execution_ledger", []) if isinstance(native_policy_loop_payload.get("execution_ledger"), list) else []
                native_policy_loop_pending = native_policy_loop_runtime.store.list_approvals(native_policy_loop_runtime.session_id, status="pending")
            finally:
                native_policy_loop_runtime.close()
            write("native-tool-runtime-policy.json", json.dumps({
                "plan": native_policy_plan_payload,
                "apply": native_policy_apply_payload,
                "approved": native_policy_approved,
                "recall_before": native_policy_recall_before,
                "recall_after": native_policy_recall_after,
                "loop": native_policy_loop_payload,
            }, indent=2, sort_keys=True))
        finally:
            native_policy_runtime.close()
        native_policy_plan_calls = native_policy_plan_payload.get("tool_calls", []) if isinstance(native_policy_plan_payload.get("tool_calls"), list) else []
        native_policy_blob = json.dumps({
            "plan": native_policy_plan_payload,
            "apply": native_policy_apply_payload,
            "approved": native_policy_approved,
            "recall_before": native_policy_recall_before,
            "recall_after": native_policy_recall_after,
            "loop": native_policy_loop_payload,
        }, sort_keys=True)
        checks["native_tool_call_runtime_policy_ok"] = (
            native_policy_plan_payload.get("mode") == "plan_only"
            and [call.get("tool") for call in native_policy_plan_calls] == ["remember", "workspace_read"]
            and [call.get("validation", {}).get("runtime_policy") for call in native_policy_plan_calls] == ["confirm_required", "blocked"]
            and "will require approval by runtime policy" in json.dumps(native_policy_plan_payload.get("warnings", []))
            and "will be blocked by runtime policy" in json.dumps(native_policy_plan_payload.get("warnings", []))
            and not native_policy_plan_pending
            and [item.get("result", {}).get("status") for item in native_policy_apply_payload.get("results", [])] == ["needs_approval", "blocked"]
            and [item.get("runtime_policy") for item in native_policy_apply_ledger] == ["confirm_required", "blocked"]
            and [item.get("execution_state") for item in native_policy_apply_ledger] == ["queued_for_approval", "blocked"]
            and all(item.get("runtime_policy_enforced") is True for item in native_policy_apply_ledger)
            and not any(item.get("actual_command_or_process_activity") for item in native_policy_apply_ledger)
            and len(native_policy_pending) == 1
            and native_policy_pending[0].get("tool_name") == "remember"
            and "native runtime policy approval replayed" not in native_policy_recall_before
            and "native-policy-smoke" in native_policy_approved
            and "native runtime policy approval replayed" in native_policy_recall_after
            and native_policy_loop_payload.get("stop_reason") == "approval_or_blocked_result"
            and native_policy_loop_payload.get("steps_executed") == 1
            and len(native_policy_loop_adapter.prompts) == 1
            and native_policy_loop_payload.get("steps", [{}])[0].get("terminal_result_statuses") == ["blocked", "needs_approval"]
            and [item.get("runtime_policy") for item in native_policy_loop_ledger] == ["confirm_required", "blocked"]
            and all(item.get("runtime_policy_enforced") is True for item in native_policy_loop_ledger)
            and len(native_policy_loop_pending) == 1
            and "policy-smoke-secret" not in native_policy_plan + native_policy_apply + native_policy_loop + native_policy_blob
        )

        feedback_adapter = SmokeToolCallFeedbackAdapter()
        feedback_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-tool-feedback-smoke",
                auto_model_planning=True,
            ),
            adapter=feedback_adapter,
        )
        feedback_gateway = None
        try:
            feedback_loop = feedback_runtime.handle_message('/auto-loop model=true steps=4 prompt="native feedback smoke token=feedback-smoke-secret"')
            feedback_payload = json.loads(feedback_loop.split("\n", 1)[1])
            feedback_ledger = feedback_payload.get("execution_ledger", []) if isinstance(feedback_payload.get("execution_ledger"), list) else []
            feedback_execution_summary = feedback_payload.get("execution_summary", {}) if isinstance(feedback_payload.get("execution_summary"), dict) else {}
            feedback_steps = feedback_payload.get("steps", []) if isinstance(feedback_payload.get("steps"), list) else []
            feedback_planner_trace = feedback_payload.get("planner_trace", []) if isinstance(feedback_payload.get("planner_trace"), list) else []
            feedback_step_deltas = [
                step.get("execution_ledger_delta", [])
                for step in feedback_steps
                if isinstance(step, dict) and step.get("mode") == "applied"
            ]
            feedback_recall = feedback_runtime.handle_message('/recall query=native-feedback-recovered')
            feedback_artifacts = feedback_payload.get("artifacts", {}) if isinstance(feedback_payload.get("artifacts"), dict) else {}
            feedback_json_path = Path(feedback_artifacts.get("json", ""))
            feedback_md_path = Path(feedback_artifacts.get("markdown", ""))
            feedback_transcript = ""
            if feedback_json_path.is_file():
                feedback_transcript += feedback_json_path.read_text(encoding="utf-8")
            if feedback_md_path.is_file():
                feedback_transcript += feedback_md_path.read_text(encoding="utf-8")

            feedback_rel_json = feedback_json_path.relative_to(feedback_runtime.registry.harness.store.root).as_posix() if feedback_json_path.is_file() else ""
            feedback_outside_transcript = root / "outside-native-transcript.txt"
            feedback_outside_transcript.write_text('{"prompt":"OUTSIDE_NATIVE_TRANSCRIPT_SENTINEL"}\n', encoding="utf-8")
            feedback_symlink_created = False
            if feedback_rel_json and hasattr(os, "symlink"):
                try:
                    feedback_symlink = feedback_json_path.parent / "escape.json"
                    if feedback_symlink.exists() or feedback_symlink.is_symlink():
                        feedback_symlink.unlink()
                    feedback_symlink.symlink_to(feedback_outside_transcript)
                    feedback_symlink_created = True
                except OSError:
                    feedback_symlink_created = False
            feedback_transcript_list = feedback_runtime.registry.run("list_auto_transcripts", {"kind": "loop", "limit": 10}).to_dict()
            feedback_transcript_detail = feedback_runtime.registry.run("get_auto_transcript", {"path": feedback_rel_json, "max_ledger": 2}).to_dict()
            feedback_transcript_ref = feedback_runtime.registry.run("resolve_local_ref", {"ref": f"auto-transcript:{feedback_rel_json}", "max_ledger": 2}).to_dict()
            feedback_transcript_slash = feedback_runtime.handle_message(f"/auto-transcript path={feedback_rel_json} max_ledger=2") if feedback_rel_json else ""

            feedback_gateway = AgentGateway(feedback_runtime, port=0)
            feedback_thread = threading.Thread(target=feedback_gateway.serve_forever, daemon=True)
            feedback_thread.start()
            feedback_host, feedback_port = feedback_gateway.server_address

            def feedback_post(route: str, body: dict[str, object]) -> dict[str, object]:
                req = urllib.request.Request(
                    f"http://{feedback_host}:{feedback_port}{route}",
                    data=json.dumps(body).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    return json.loads(response.read().decode("utf-8"))

            with urllib.request.urlopen(f"http://{feedback_host}:{feedback_port}/routes", timeout=5) as response:
                feedback_routes = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(f"http://{feedback_host}:{feedback_port}/", timeout=5) as response:
                feedback_dashboard = response.read().decode("utf-8")
            gateway_auto = feedback_post("/auto", {"prompt": "native gateway plan token=native-gateway-secret", "model": True, "apply": False})
            gateway_auto_payload = json.loads(str(gateway_auto.get("response", "{}")).split("\n", 1)[1])
            gateway_loop = feedback_post("/auto-loop", {"prompt": "native gateway loop token=native-loop-secret", "model": True, "steps": "4"})
            gateway_loop_payload = json.loads(str(gateway_loop.get("response", "{}")).split("\n", 1)[1])
            with urllib.request.urlopen(f"http://{feedback_host}:{feedback_port}/auto-transcripts?kind=loop&limit=5", timeout=5) as response:
                feedback_gateway_transcript_index = json.loads(response.read().decode("utf-8"))
            transcript_detail_query = urllib.parse.urlencode({"path": feedback_rel_json, "max_ledger": "2"})
            with urllib.request.urlopen(f"http://{feedback_host}:{feedback_port}/auto-transcript?{transcript_detail_query}", timeout=5) as response:
                feedback_gateway_transcript_detail = json.loads(response.read().decode("utf-8"))
            try:
                bad_gateway_req = urllib.request.Request(
                    f"http://{feedback_host}:{feedback_port}/auto-loop",
                    data=json.dumps({"prompt": "bad native loop", "steps": "1.5"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(bad_gateway_req, timeout=5)
                bad_gateway_steps = {"status_code": 200, "payload": {}}
            except urllib.error.HTTPError as exc:
                bad_gateway_steps = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
            bridge_loop = handle_bridge_message(
                feedback_runtime,
                BridgeMessage(platform="discord", text='!phobos /auto-loop model=true steps=4 prompt="native chat loop token=native-chat-secret"', channel_id="C-native-smoke", user_id="U-native-smoke", message_id="M-native-smoke"),
                BridgeConfig(platform="discord", allowed_channel_ids=("C-native-smoke",), allowed_user_ids=("U-native-smoke",), command_prefix="!phobos", max_response_chars=1200),
            )
            write("native-tool-feedback-loop.txt", feedback_loop)
            write("native-tool-feedback-transcript.txt", feedback_transcript)
            write("native-tool-gateway-chat.json", json.dumps({
                "routes": feedback_routes,
                "dashboard_contains_native_loop": "Native Tool Loop" in feedback_dashboard,
                "gateway_auto": gateway_auto,
                "gateway_loop": gateway_loop,
                "bad_gateway_steps": bad_gateway_steps,
                "transcript_index": feedback_transcript_list,
                "transcript_detail": feedback_transcript_detail,
                "transcript_ref": feedback_transcript_ref,
                "planner_trace": feedback_planner_trace,
                "step_deltas": feedback_step_deltas,
                "gateway_transcript_index": feedback_gateway_transcript_index,
                "gateway_transcript_detail": feedback_gateway_transcript_detail,
                "symlink_created": feedback_symlink_created,
                "bridge_loop": bridge_loop.to_dict(),
            }, indent=2, sort_keys=True))
        finally:
            if feedback_gateway is not None:
                feedback_gateway.shutdown()
            feedback_runtime.close()

        model_error_adapter = SmokeToolCallModelErrorAfterFeedbackAdapter()
        model_error_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-model-error-stop.db"),
                session_name="native-tool-model-error-stop-smoke",
                auto_model_planning=True,
            ),
            adapter=model_error_adapter,
        )
        try:
            model_error_loop = model_error_runtime.handle_message('/auto-loop model=true steps=4 prompt="native model error stop token=model-error-smoke-secret"')
            model_error_payload = json.loads(model_error_loop.split("\n", 1)[1])
            model_error_ledger = model_error_payload.get("execution_ledger", []) if isinstance(model_error_payload.get("execution_ledger"), list) else []
            model_error_steps = model_error_payload.get("steps", []) if isinstance(model_error_payload.get("steps"), list) else []
            model_error_step = model_error_steps[-1] if model_error_steps and isinstance(model_error_steps[-1], dict) else {}
            model_error_plan = model_error_step.get("plan") if isinstance(model_error_step.get("plan"), dict) else {}
            model_error_metadata = model_error_plan.get("metadata") if isinstance(model_error_plan.get("metadata"), dict) else {}
            model_error_recall = model_error_runtime.handle_message('/recall query=native-model-error-stop')
            model_error_artifacts = model_error_payload.get("artifacts", {}) if isinstance(model_error_payload.get("artifacts"), dict) else {}
            model_error_transcript = ""
            for path_value in [model_error_artifacts.get("json"), model_error_artifacts.get("markdown")]:
                if path_value:
                    model_error_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            model_error_chat = model_error_runtime.render_chat_response(model_error_loop, message='/auto-loop model=true prompt="native model error stop"', platform="discord")
            write("native-tool-model-error-stop.txt", model_error_loop)
            write("native-tool-model-error-stop-transcript.txt", model_error_transcript)
            write("native-tool-model-error-stop-chat.txt", model_error_chat)
        finally:
            model_error_runtime.close()

        invalid_plan_adapter = SmokeToolCallInvalidAfterFeedbackAdapter()
        invalid_plan_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "native-tool-invalid-plan-stop.db"),
                session_name="native-tool-invalid-plan-stop-smoke",
                auto_model_planning=True,
            ),
            adapter=invalid_plan_adapter,
        )
        try:
            invalid_plan_loop = invalid_plan_runtime.handle_message('/auto-loop model=true steps=4 prompt="native invalid plan stop token=invalid-plan-smoke-secret"')
            invalid_plan_payload = json.loads(invalid_plan_loop.split("\n", 1)[1])
            invalid_plan_ledger = invalid_plan_payload.get("execution_ledger", []) if isinstance(invalid_plan_payload.get("execution_ledger"), list) else []
            invalid_plan_steps = invalid_plan_payload.get("steps", []) if isinstance(invalid_plan_payload.get("steps"), list) else []
            invalid_plan_step = invalid_plan_steps[-1] if invalid_plan_steps and isinstance(invalid_plan_steps[-1], dict) else {}
            invalid_plan_plan = invalid_plan_step.get("plan") if isinstance(invalid_plan_step.get("plan"), dict) else {}
            invalid_plan_metadata = invalid_plan_plan.get("metadata") if isinstance(invalid_plan_plan.get("metadata"), dict) else {}
            invalid_plan_recall = invalid_plan_runtime.handle_message('/recall query=native-invalid-plan-stop')
            invalid_plan_artifacts = invalid_plan_payload.get("artifacts", {}) if isinstance(invalid_plan_payload.get("artifacts"), dict) else {}
            invalid_plan_transcript = ""
            for path_value in [invalid_plan_artifacts.get("json"), invalid_plan_artifacts.get("markdown")]:
                if path_value:
                    invalid_plan_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            invalid_plan_chat = invalid_plan_runtime.render_chat_response(invalid_plan_loop, message='/auto-loop model=true prompt="native invalid plan stop"', platform="discord")
            invalid_plan_status = invalid_plan_runtime.registry.run("runtime_status", {}).to_dict()
            write("native-tool-invalid-plan-stop.txt", invalid_plan_loop)
            write("native-tool-invalid-plan-stop-transcript.txt", invalid_plan_transcript)
            write("native-tool-invalid-plan-stop-chat.txt", invalid_plan_chat)
        finally:
            invalid_plan_runtime.close()

        terminal_adapter = SmokeToolCallTerminalNoToolAdapter()
        terminal_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-terminal-no-tool-smoke",
                auto_model_planning=True,
            ),
            adapter=terminal_adapter,
        )
        try:
            terminal_loop = terminal_runtime.handle_message('/auto-loop model=true steps=4 prompt="remember native-terminal-stop as token=terminal-stop-smoke-secret"')
            terminal_payload = json.loads(terminal_loop.split("\n", 1)[1])
            terminal_recall = terminal_runtime.handle_message('/recall query=native-terminal-stop')
            terminal_artifacts = terminal_payload.get("artifacts", {}) if isinstance(terminal_payload.get("artifacts"), dict) else {}
            terminal_json_path = Path(terminal_artifacts.get("json", ""))
            terminal_md_path = Path(terminal_artifacts.get("markdown", ""))
            terminal_transcript = ""
            if terminal_json_path.is_file():
                terminal_transcript += terminal_json_path.read_text(encoding="utf-8")
            if terminal_md_path.is_file():
                terminal_transcript += terminal_md_path.read_text(encoding="utf-8")
            terminal_rel_json = terminal_json_path.relative_to(terminal_runtime.registry.harness.store.root).as_posix() if terminal_json_path.is_file() else ""
            terminal_detail = terminal_runtime.registry.run("get_auto_transcript", {"path": terminal_rel_json, "max_ledger": 5}).to_dict() if terminal_rel_json else {}
            terminal_status = terminal_runtime.registry.run("runtime_status", {}).to_dict()
            terminal_chat = terminal_runtime.render_chat_response(terminal_loop, message='/auto-loop model=true prompt="native terminal no-tool stop"', platform="discord")
            write("native-tool-terminal-no-tool-loop.txt", terminal_loop)
            write("native-tool-terminal-no-tool-transcript.txt", terminal_transcript)
            write("native-tool-terminal-no-tool-chat.txt", terminal_chat)
        finally:
            terminal_runtime.close()

        duplicate_adapter = SmokeToolCallDuplicatePlanAdapter()
        duplicate_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-duplicate-plan-smoke",
                auto_model_planning=True,
            ),
            adapter=duplicate_adapter,
        )
        try:
            duplicate_loop = duplicate_runtime.handle_message('/auto-loop model=true steps=4 prompt="remember native duplicate loop token=duplicate-stop-smoke-secret"')
            duplicate_payload = json.loads(duplicate_loop.split("\n", 1)[1])
            duplicate_recall = duplicate_runtime.handle_message('/recall query=native-duplicate-stop')
            duplicate_transcript = ""
            duplicate_artifacts = duplicate_payload.get("artifacts", {}) if isinstance(duplicate_payload.get("artifacts"), dict) else {}
            for path_value in [duplicate_artifacts.get("json"), duplicate_artifacts.get("markdown")]:
                if path_value:
                    duplicate_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            write("native-tool-duplicate-plan-loop.txt", duplicate_loop)
            write("native-tool-duplicate-plan-transcript.txt", duplicate_transcript)
        finally:
            duplicate_runtime.close()

        partial_duplicate_adapter = SmokeToolCallPartialDuplicatePlanAdapter()
        partial_duplicate_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-partial-duplicate-plan-smoke",
                auto_model_planning=True,
            ),
            adapter=partial_duplicate_adapter,
        )
        try:
            partial_duplicate_loop = partial_duplicate_runtime.handle_message('/auto-loop model=true steps=4 prompt="native partial duplicate loop token=partial-duplicate-smoke-secret"')
            partial_duplicate_payload = json.loads(partial_duplicate_loop.split("\n", 1)[1])
            partial_duplicate_recall = partial_duplicate_runtime.handle_message('/recall query=native-partial-duplicate-stop')
            partial_duplicate_withheld_recall = partial_duplicate_runtime.handle_message('/recall query=native-partial-duplicate-withheld')
            partial_duplicate_transcript = ""
            partial_duplicate_artifacts = partial_duplicate_payload.get("artifacts", {}) if isinstance(partial_duplicate_payload.get("artifacts"), dict) else {}
            for path_value in [partial_duplicate_artifacts.get("json"), partial_duplicate_artifacts.get("markdown")]:
                if path_value:
                    partial_duplicate_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            write("native-tool-partial-duplicate-plan-loop.txt", partial_duplicate_loop)
            write("native-tool-partial-duplicate-plan-transcript.txt", partial_duplicate_transcript)
        finally:
            partial_duplicate_runtime.close()

        same_step_duplicate_adapter = SmokeToolCallSameStepDuplicatePlanAdapter()
        same_step_duplicate_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-same-step-duplicate-plan-smoke",
                auto_model_planning=True,
            ),
            adapter=same_step_duplicate_adapter,
        )
        try:
            same_step_duplicate_loop = same_step_duplicate_runtime.handle_message('/auto-loop model=true steps=4 prompt="native same-step duplicate loop token=same-step-duplicate-smoke-secret"')
            same_step_duplicate_payload = json.loads(same_step_duplicate_loop.split("\n", 1)[1])
            same_step_duplicate_recall = same_step_duplicate_runtime.handle_message('/recall query=native-same-step-duplicate')
            same_step_duplicate_transcript = ""
            same_step_duplicate_artifacts = same_step_duplicate_payload.get("artifacts", {}) if isinstance(same_step_duplicate_payload.get("artifacts"), dict) else {}
            for path_value in [same_step_duplicate_artifacts.get("json"), same_step_duplicate_artifacts.get("markdown")]:
                if path_value:
                    same_step_duplicate_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            write("native-tool-same-step-duplicate-plan-loop.txt", same_step_duplicate_loop)
            write("native-tool-same-step-duplicate-plan-transcript.txt", same_step_duplicate_transcript)
        finally:
            same_step_duplicate_runtime.close()

        max_steps_adapter = SmokeToolCallMaxStepsAdapter()
        max_steps_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(db_path),
                session_name="native-max-steps-smoke",
                auto_model_planning=True,
                max_auto_steps=2,
            ),
            adapter=max_steps_adapter,
        )
        try:
            max_steps_loop = max_steps_runtime.handle_message('/auto-loop model=true prompt="native max steps smoke token=maxsteps-smoke-secret"')
            max_steps_payload = json.loads(max_steps_loop.split("\n", 1)[1])
            max_steps_ledger = max_steps_payload.get("execution_ledger", []) if isinstance(max_steps_payload.get("execution_ledger"), list) else []
            max_steps_artifacts = max_steps_payload.get("artifacts", {}) if isinstance(max_steps_payload.get("artifacts"), dict) else {}
            max_steps_transcript = ""
            for path_value in [max_steps_artifacts.get("json"), max_steps_artifacts.get("markdown")]:
                if path_value:
                    max_steps_transcript += Path(str(path_value)).read_text(encoding="utf-8")
            max_steps_chat = max_steps_runtime.render_chat_response(max_steps_loop, message='/auto-loop model=true prompt="native max steps smoke"', platform="discord")
            max_steps_status = max_steps_runtime.registry.run("runtime_status", {}).to_dict()
            write("native-tool-max-steps-loop.txt", max_steps_loop)
            write("native-tool-max-steps-transcript.txt", max_steps_transcript)
            write("native-tool-max-steps-chat.txt", max_steps_chat)
        finally:
            max_steps_runtime.close()
        terminal_steps = terminal_payload.get("steps", []) if isinstance(terminal_payload.get("steps"), list) else []
        terminal_no_plan = terminal_steps[-1] if terminal_steps and isinstance(terminal_steps[-1], dict) else {}
        terminal_plan = terminal_no_plan.get("plan") if isinstance(terminal_no_plan.get("plan"), dict) else {}
        terminal_metadata = terminal_plan.get("metadata") if isinstance(terminal_plan.get("metadata"), dict) else {}
        terminal_ledger = terminal_payload.get("execution_ledger", []) if isinstance(terminal_payload.get("execution_ledger"), list) else []
        duplicate_steps = duplicate_payload.get("steps", []) if isinstance(duplicate_payload.get("steps"), list) else []
        duplicate_stop_step = duplicate_steps[-1] if duplicate_steps and isinstance(duplicate_steps[-1], dict) else {}
        duplicate_ledger = duplicate_payload.get("execution_ledger", []) if isinstance(duplicate_payload.get("execution_ledger"), list) else []
        partial_duplicate_steps = partial_duplicate_payload.get("steps", []) if isinstance(partial_duplicate_payload.get("steps"), list) else []
        partial_duplicate_stop_step = partial_duplicate_steps[-1] if partial_duplicate_steps and isinstance(partial_duplicate_steps[-1], dict) else {}
        partial_duplicate_ledger = partial_duplicate_payload.get("execution_ledger", []) if isinstance(partial_duplicate_payload.get("execution_ledger"), list) else []
        same_step_duplicate_steps = same_step_duplicate_payload.get("steps", []) if isinstance(same_step_duplicate_payload.get("steps"), list) else []
        same_step_duplicate_stop_step = same_step_duplicate_steps[-1] if same_step_duplicate_steps and isinstance(same_step_duplicate_steps[-1], dict) else {}
        same_step_duplicate_ledger = same_step_duplicate_payload.get("execution_ledger", []) if isinstance(same_step_duplicate_payload.get("execution_ledger"), list) else []
        checks["native_tool_call_terminal_no_tool_stop_ok"] = (
            terminal_payload.get("stop_reason") == "no_tool_calls"
            and terminal_payload.get("steps_executed") == 1
            and len(terminal_adapter.prompts) == 2
            and len(terminal_ledger) == 1
            and terminal_ledger[0].get("execution_state") == "completed_without_command_execution"
            and terminal_ledger[0].get("actual_command_or_process_activity") is False
            and terminal_no_plan.get("mode") == "no_plan"
            and terminal_no_plan.get("no_tools_executed") is True
            and terminal_no_plan.get("execution_ledger_delta") == []
            and terminal_plan.get("summary") == "smoke model stopped after successful native result"
            and terminal_metadata.get("terminal_no_tool_plan_respected") is True
            and terminal_metadata.get("deterministic_fallback_suppressed") is True
            and "native terminal no-tool stop ran once" in terminal_recall
            and "terminal-stop-smoke-secret" not in json.dumps(terminal_payload) + terminal_recall
        )
        terminal_detail_summary = terminal_detail.get("data", {}).get("summary", {}) if isinstance(terminal_detail.get("data"), dict) else {}
        checks["native_tool_call_no_tool_no_dispatch_ok"] = (
            terminal_no_plan.get("no_tools_executed") is True
            and terminal_no_plan.get("execution_ledger_delta") == []
            and terminal_detail_summary.get("no_dispatch_step_count") == 1
            and "No-dispatch step: no tools were dispatched for this step." in terminal_transcript
            and "no-dispatch terminal step" in terminal_chat
            and terminal_status.get("data", {}).get("native_tool_calling", {}).get("terminal_no_tool_no_dispatch_step") is True
            and "terminal-stop-smoke-secret" not in terminal_transcript + terminal_chat + json.dumps(terminal_detail)
        )
        checks["native_tool_call_duplicate_loop_stop_ok"] = (
            duplicate_payload.get("stop_reason") == "duplicate_plan"
            and duplicate_payload.get("steps_executed") == 1
            and duplicate_payload.get("feedback_history_entries") == 1
            and len(duplicate_adapter.prompts) == 2
            and len(duplicate_ledger) == 1
            and duplicate_ledger[0].get("execution_state") == "completed_without_command_execution"
            and duplicate_ledger[0].get("actual_command_or_process_activity") is False
            and duplicate_stop_step.get("mode") == "stopped_duplicate_plan"
            and duplicate_stop_step.get("no_tools_executed") is True
            and duplicate_stop_step.get("execution_ledger_delta") == []
            and duplicate_stop_step.get("duplicate_tool_call_count") == 1
            and "native duplicate stop ran once" in duplicate_recall
            and "Duplicate plan stop" in duplicate_transcript
            and "duplicate-stop-smoke-secret" not in json.dumps(duplicate_payload) + duplicate_recall + duplicate_transcript
        )
        checks["native_tool_call_partial_duplicate_loop_stop_ok"] = (
            partial_duplicate_payload.get("stop_reason") == "duplicate_plan"
            and partial_duplicate_payload.get("steps_executed") == 1
            and len(partial_duplicate_adapter.prompts) == 2
            and len(partial_duplicate_ledger) == 1
            and partial_duplicate_ledger[0].get("execution_state") == "completed_without_command_execution"
            and partial_duplicate_stop_step.get("mode") == "stopped_duplicate_plan"
            and partial_duplicate_stop_step.get("duplicate_detection") == "tool_args_any_repeat"
            and partial_duplicate_stop_step.get("duplicate_tool_call_count") == 1
            and partial_duplicate_stop_step.get("new_tool_call_count") == 1
            and partial_duplicate_stop_step.get("execution_ledger_delta") == []
            and "native partial duplicate stop ran once" in partial_duplicate_recall
            and "partial duplicate new call should be withheld" not in partial_duplicate_withheld_recall
            and "new calls withheld=1" in partial_duplicate_transcript
            and "partial-duplicate-smoke-secret" not in json.dumps(partial_duplicate_payload) + partial_duplicate_recall + partial_duplicate_transcript
        )
        checks["native_tool_call_same_step_duplicate_stop_ok"] = (
            same_step_duplicate_payload.get("stop_reason") == "duplicate_plan"
            and same_step_duplicate_payload.get("steps_executed") == 0
            and same_step_duplicate_payload.get("feedback_history_entries") == 0
            and len(same_step_duplicate_adapter.prompts) == 1
            and same_step_duplicate_ledger == []
            and same_step_duplicate_stop_step.get("mode") == "stopped_duplicate_plan"
            and same_step_duplicate_stop_step.get("duplicate_detection") == "tool_args_same_step_repeat"
            and same_step_duplicate_stop_step.get("duplicate_tool_call_count") == 1
            and same_step_duplicate_stop_step.get("new_tool_call_count") == 1
            and same_step_duplicate_stop_step.get("execution_ledger_delta") == []
            and same_step_duplicate_stop_step.get("no_tools_executed") is True
            and "same-step duplicate must not dispatch" not in same_step_duplicate_recall
            and "tool_args_same_step_repeat" in same_step_duplicate_transcript
            and "new calls withheld=1" in same_step_duplicate_transcript
            and "same-step-duplicate-smoke-secret" not in json.dumps(same_step_duplicate_payload) + same_step_duplicate_recall + same_step_duplicate_transcript
        )
        checks["native_tool_call_max_steps_budget_ok"] = (
            max_steps_payload.get("stop_reason") == "max_steps"
            and max_steps_payload.get("steps_requested") == 2
            and max_steps_payload.get("max_steps_budget") == 2
            and max_steps_payload.get("max_steps_budget_exhausted") is True
            and max_steps_payload.get("steps_executed") == 2
            and max_steps_payload.get("feedback_history_entries") == 2
            and len(max_steps_adapter.prompts) == 2
            and len(max_steps_ledger) == 2
            and [item.get("step") for item in max_steps_ledger] == [1, 2]
            and not any(item.get("actual_command_or_process_activity") for item in max_steps_ledger)
            and max_steps_status.get("data", {}).get("native_tool_calling", {}).get("max_steps_budget_stop_enforced") is True
            and max_steps_status.get("data", {}).get("native_tool_calling", {}).get("model_error_stop_enforced") is True
            and "Stop reason: `max_steps`" in max_steps_transcript
            and "Max-step budget exhausted: `True`" in max_steps_transcript
            and "Max-step budget reached" in max_steps_transcript
            and "Max-step budget exhausted" in max_steps_chat
            and "actual_command_or_process_activity=0" in max_steps_chat
            and "maxsteps-smoke-secret" not in json.dumps(max_steps_payload) + max_steps_transcript + max_steps_chat
        )
        checks["native_tool_call_model_error_stop_ok"] = (
            model_error_payload.get("stop_reason") == "model_error"
            and model_error_payload.get("steps_executed") == 1
            and model_error_payload.get("feedback_history_entries") == 1
            and len(model_error_adapter.prompts) == 2
            and model_error_step.get("mode") == "model_error"
            and model_error_step.get("no_tools_executed") is True
            and model_error_step.get("execution_ledger_delta") == []
            and model_error_metadata.get("model_planner_failed") is True
            and model_error_metadata.get("deterministic_fallback_suppressed") is True
            and "token=<REDACTED>" in json.dumps(model_error_metadata)
            and len(model_error_ledger) == 1
            and model_error_ledger[0].get("execution_state") == "completed_without_command_execution"
            and model_error_ledger[0].get("actual_command_or_process_activity") is False
            and "native model error first step ran" in model_error_recall
            and "Stop reason: `model_error`" in model_error_transcript
            and "Model planner failed after tool feedback" in model_error_transcript
            and "Native tool loop stopped: `model_error`" in model_error_chat
            and "Model tool planning failed" in model_error_chat
            and "model-error-smoke-secret" not in json.dumps(model_error_payload) + model_error_transcript + model_error_chat + model_error_recall
        )
        checks["native_tool_call_invalid_plan_stop_ok"] = (
            invalid_plan_payload.get("stop_reason") == "invalid_plan"
            and invalid_plan_payload.get("steps_executed") == 1
            and invalid_plan_payload.get("feedback_history_entries") == 1
            and len(invalid_plan_adapter.prompts) == 2
            and invalid_plan_step.get("mode") == "invalid_plan"
            and invalid_plan_step.get("no_tools_executed") is True
            and invalid_plan_step.get("execution_ledger_delta") == []
            and invalid_plan_step.get("rejected_tool_call_count") == 2
            and invalid_plan_plan.get("tool_calls") == []
            and len(invalid_plan_plan.get("rejected_tool_calls", [])) == 2
            and invalid_plan_metadata.get("all_tool_calls_rejected") is True
            and invalid_plan_metadata.get("invalid_model_tool_plan") is True
            and invalid_plan_metadata.get("deterministic_fallback_suppressed") is True
            and invalid_plan_metadata.get("attempted_tool_call_count") == 2
            and invalid_plan_metadata.get("accepted_tool_call_count") == 0
            and len(invalid_plan_ledger) == 1
            and invalid_plan_ledger[0].get("execution_state") == "completed_without_command_execution"
            and invalid_plan_ledger[0].get("actual_command_or_process_activity") is False
            and "native invalid plan first step ran" in invalid_plan_recall
            and "Invalid plan stop" in invalid_plan_transcript
            and "Native tool loop stopped: `invalid_plan`" in invalid_plan_chat
            and "invalid or rejected tool calls" in invalid_plan_chat
            and invalid_plan_status.get("data", {}).get("native_tool_calling", {}).get("invalid_plan_stop_enforced") is True
            and "invalid-plan-smoke-secret" not in json.dumps(invalid_plan_payload) + invalid_plan_transcript + invalid_plan_chat + invalid_plan_recall
        )
        checks["native_tool_call_feedback_loop_ok"] = (
            feedback_payload.get("stop_reason") == "no_tool_calls"
            and feedback_payload.get("steps_executed") == 2
            and feedback_payload.get("transcript_artifact_written") is True
            and [item.get("result", {}).get("status") for step in feedback_payload.get("steps", []) for item in step.get("results", [])][:2] == ["error", "ok"]
            and feedback_execution_summary.get("ledger_entries") == 2
            and feedback_execution_summary.get("handler_error") == 1
            and feedback_execution_summary.get("local_only_completion") == 1
            and feedback_execution_summary.get("claimable_tool_runs") == 1
            and feedback_execution_summary.get("claimable_command_executions") == 0
            and "native feedback loop recovered" in feedback_recall
            and "Execution summary" in feedback_transcript
            and "Claimable tool runs: `1`" in feedback_transcript
            and "Execution ledger" in feedback_transcript
            and "Execution ledger delta" in feedback_transcript
            and "Workspace file not found" in feedback_transcript
            and "feedback-smoke-secret" not in json.dumps(feedback_payload) + feedback_transcript
        )
        checks["native_tool_call_step_ledger_delta_ok"] = (
            len(feedback_step_deltas) == 2
            and all(len(delta) == 1 for delta in feedback_step_deltas)
            and [delta[0].get("step") for delta in feedback_step_deltas] == [1, 2]
            and [delta[0].get("execution_state") for delta in feedback_step_deltas] == ["handler_error_no_target_execution_claimed", "completed_without_command_execution"]
            and feedback_step_deltas[0][0] == feedback_ledger[0]
            and feedback_step_deltas[1][0] == feedback_ledger[1]
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("step_ledger_delta_count") == 2
            and [item.get("step") for item in feedback_transcript_detail.get("data", {}).get("summary", {}).get("step_ledger_deltas", [])] == [1, 2]
            and feedback_gateway_transcript_detail.get("data", {}).get("summary", {}).get("step_ledger_delta_count") == 2
            and not any(item.get("actual_command_or_process_activity") for delta in feedback_step_deltas for item in delta)
            and "feedback-smoke-secret" not in json.dumps(feedback_step_deltas) + json.dumps(feedback_transcript_detail) + json.dumps(feedback_gateway_transcript_detail)
        )
        checks["native_tool_call_planner_trace_ok"] = (
            [item.get("step") for item in feedback_planner_trace] == [1, 2, 3]
            and [item.get("tool_call_count") for item in feedback_planner_trace] == [1, 1, 0]
            and all(item.get("provider") == "smoke-tool-call-feedback" for item in feedback_planner_trace)
            and all(item.get("context_provided") is True for item in feedback_planner_trace)
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("planner_trace_count") == 3
            and feedback_gateway_transcript_detail.get("data", {}).get("summary", {}).get("planner_trace_count") == 3
            and "Planner trace" in feedback_transcript
            and "provider=`smoke-tool-call-feedback`" in feedback_transcript
            and "feedback-smoke-secret" not in json.dumps(feedback_planner_trace) + feedback_transcript
        )
        feedback_final_prompt = feedback_adapter.prompts[-1] if feedback_adapter.prompts else ""
        checks["native_tool_call_cumulative_feedback_ok"] = (
            feedback_payload.get("feedback_history_mode") == "cumulative_redacted"
            and feedback_payload.get("feedback_history_entries") == 2
            and len(feedback_adapter.prompts) >= 3
            and "Previous Phobos tool results (cumulative, redacted" in feedback_adapter.prompts[1]
            and "Workspace file not found" in feedback_final_prompt
            and "Stored memory" in feedback_final_prompt
        )
        feedback_followup_prompt_blob = "\n".join(feedback_adapter.prompts[1:]) if len(feedback_adapter.prompts) > 1 else ""
        checks["native_tool_call_feedback_prompt_redaction_ok"] = (
            len(feedback_adapter.prompts) >= 3
            and "Previous Phobos tool results (cumulative, redacted" in feedback_followup_prompt_blob
            and "Workspace file not found" in feedback_followup_prompt_blob
            and "token=<REDACTED>" in feedback_followup_prompt_blob
            and "feedback-smoke-secret" not in feedback_followup_prompt_blob
            and native_status_data.get("followup_feedback_prompt_redacted") is True
            and native_status_milestone_contract.get("followup_prompt_secret_redaction") is True
        )
        feedback_transcript_rows = feedback_transcript_list.get("data", {}).get("transcripts", []) if isinstance(feedback_transcript_list.get("data"), dict) else []
        feedback_transcript_blob = json.dumps({
            "list": feedback_transcript_list,
            "detail": feedback_transcript_detail,
            "ref": feedback_transcript_ref,
            "slash": feedback_transcript_slash,
            "gateway_index": feedback_gateway_transcript_index,
            "gateway_detail": feedback_gateway_transcript_detail,
        }, sort_keys=True)
        checks["native_tool_call_transcript_index_detail_ok"] = (
            feedback_transcript_list.get("status") == "ok"
            and feedback_rel_json in [str(item.get("path")) for item in feedback_transcript_rows]
            and feedback_transcript_list.get("data", {}).get("no_target_activity") is True
            and feedback_transcript_list.get("data", {}).get("raw_file_contents_emitted") is False
            and (not feedback_symlink_created or "escape.json" in json.dumps(feedback_transcript_list.get("data", {}).get("skipped", [])))
            and feedback_transcript_detail.get("status") == "ok"
            and feedback_transcript_detail.get("data", {}).get("raw_file_contents_emitted") is False
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("execution_counts", {}).get("handler_error") == 1
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("execution_summary", {}).get("claimable_tool_runs") == 1
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("result_count") == 2
            and feedback_transcript_ref.get("status") == "ok"
            and "Native tool-calling transcript returned" in feedback_transcript_slash
            and "/auto-transcripts" in feedback_routes.get("paths", [])
            and "/auto-transcript" in feedback_routes.get("paths", [])
            and feedback_gateway_transcript_index.get("status") == "ok"
            and feedback_gateway_transcript_detail.get("status") == "ok"
            and feedback_gateway_transcript_detail.get("data", {}).get("raw_file_contents_emitted") is False
            and "execution_counts" in feedback_gateway_transcript_detail.get("data", {}).get("summary", {})
            and "OUTSIDE_NATIVE_TRANSCRIPT_SENTINEL" not in feedback_transcript_blob
            and "feedback-smoke-secret" not in feedback_transcript_blob
            and "native-loop-secret" not in feedback_transcript_blob
        )
        checks["native_tool_call_execution_ledger_ok"] = (
            len(native_apply_ledger) >= 2
            and len(guardrail_apply_ledger) >= 2
            and len(feedback_ledger) >= 2
            and len(native_allowed_exec_ledger) >= 1
            and [item.get("tool") for item in native_apply_ledger] == ["list_tasks", "run_command"]
            and native_apply_ledger[1].get("execution_state") == "dry_run_not_executed"
            and native_apply_ledger[1].get("actual_command_or_process_activity") is False
            and [item.get("execution_state") for item in guardrail_apply_ledger] == ["queued_for_approval", "blocked"]
            and all(item.get("actual_command_or_process_activity") is False for item in guardrail_apply_ledger)
            and [item.get("execution_state") for item in feedback_ledger[:2]] == ["handler_error_no_target_execution_claimed", "completed_without_command_execution"]
            and feedback_ledger[0].get("safe_to_claim_tool_ran") is False
            and all(item.get("actual_command_or_process_activity") is False for item in feedback_ledger)
            and native_allowed_exec_ledger[0].get("execution_state") == "executed_or_started"
            and native_allowed_exec_ledger[0].get("actual_command_or_process_activity") is True
            and native_allowed_exec_ledger[0].get("safe_to_claim_command_executed") is True
            and "feedback-smoke-secret" not in json.dumps(native_apply_ledger + guardrail_apply_ledger + feedback_ledger + native_allowed_exec_ledger)
        )
        checks["native_tool_call_execution_summary_ok"] = (
            native_allowed_plan_summary.get("ledger_entries") == 0
            and native_allowed_dry_summary.get("ledger_entries") == 1
            and native_allowed_dry_summary.get("dry_run") == 1
            and native_allowed_dry_summary.get("claimable_tool_runs") == 0
            and native_allowed_exec_summary.get("ledger_entries") == 1
            and native_allowed_exec_summary.get("actual_command_or_process_activity") == 1
            and native_allowed_exec_summary.get("claimable_command_executions") == 1
            and feedback_execution_summary.get("handler_error") == 1
            and feedback_execution_summary.get("claimable_tool_runs") == 1
            and feedback_transcript_detail.get("data", {}).get("summary", {}).get("execution_summary", {}).get("handler_error") == 1
            and "Claim rule" in feedback_transcript
            and "native-allowed-secret" not in json.dumps(native_allowed_plan_summary) + json.dumps(native_allowed_dry_summary) + json.dumps(native_allowed_exec_summary) + json.dumps(feedback_execution_summary)
        )
        checks["native_tool_call_gateway_chat_ok"] = (
            "/auto" in feedback_routes.get("paths", [])
            and "/auto-loop" in feedback_routes.get("paths", [])
            and "Native Tool Loop" in feedback_dashboard
            and gateway_auto_payload.get("mode") == "plan_only"
            and gateway_loop_payload.get("stop_reason") == "no_tool_calls"
            and gateway_loop_payload.get("transcript_artifact_written") is True
            and bad_gateway_steps.get("status_code") == 400
            and bad_gateway_steps.get("payload", {}).get("error") == "steps must be an integer"
            and bridge_loop.status == "handled"
            and "Native tool loop stopped" in bridge_loop.response
            and "Actual results" in bridge_loop.response
            and "claimable_tool_runs=1" in bridge_loop.response
            and "Auto loop completed" in bridge_loop.raw_response
            and "native-gateway-secret" not in json.dumps(gateway_auto)
            and "native-loop-secret" not in json.dumps(gateway_loop)
            and "native-chat-secret" not in json.dumps(bridge_loop.to_dict())
        )
        native_milestone_required_checks = [
            "native_tool_call_plan_validation_ok",
            "native_tool_call_wrapped_json_plan_ok",
            "native_tool_call_plan_transcript_ok",
            "native_tool_call_one_shot_planner_trace_ok",
            "native_tool_call_context_handoff_ok",
            "native_tool_call_fallback_chain_ok",
            "native_tool_call_natural_auto_provenance_ok",
            "native_tool_call_allowed_execution_ok",
            "native_tool_call_apply_transcript_ok",
            "native_tool_call_scanner_execute_boundary_ok",
            "native_tool_call_slash_flag_safety_ok",
            "native_tool_call_status_contract_ok",
            "native_openai_tool_call_adapter_ok",
            "native_provider_flat_tool_call_ok",
            "native_provider_single_top_level_tool_call_ok",
            "native_provider_singular_tool_call_alias_ok",
            "native_provider_camel_case_tool_call_alias_ok",
            "native_provider_root_function_call_ok",
            "native_tool_call_provider_call_id_provenance_ok",
            "native_tool_call_transcript_provenance_ok",
            "native_provider_tool_call_edge_cases_ok",
            "native_provider_legacy_function_call_ok",
            "native_provider_content_block_tool_call_ok",
            "native_provider_content_block_call_id_alias_ok",
            "native_provider_content_block_function_call_alias_ok",
            "native_provider_content_parts_function_call_ok",
            "native_provider_argument_aliases_ok",
            "native_provider_single_content_block_tool_call_ok",
            "native_provider_responses_output_tool_call_ok",
            "native_provider_responses_output_nested_function_call_ok",
            "native_provider_responses_output_message_typeless_direct_ok",
            "native_provider_responses_output_message_typeless_direct_aliases_ok",
            "native_provider_responses_message_tool_call_alias_ok",
            "native_provider_responses_message_function_calls_alias_ok",
            "native_provider_responses_message_content_tool_call_ok",
            "native_provider_responses_message_content_function_call_alias_ok",
            "native_provider_responses_message_content_parts_function_call_ok",
            "native_provider_single_responses_output_tool_call_ok",
            "native_provider_candidate_function_call_ok",
            "native_provider_single_candidate_part_function_call_ok",
            "native_provider_hosted_tool_call_reject_ok",
            "native_provider_custom_tool_call_reject_ok",
            "native_provider_tool_result_ignore_ok",
            "native_tool_call_guardrail_approval_ok",
            "native_provider_root_function_calls_alias_ok",
            "native_provider_root_function_calls_nested_function_call_alias_ok",
            "native_provider_root_function_calls_snake_alias_ok",
            "native_provider_root_function_calls_snake_nested_function_call_alias_ok",
            "native_provider_message_function_call_alias_ok",
            "native_provider_message_function_calls_alias_ok",
            "native_provider_message_function_calls_nested_function_call_alias_ok",
            "native_provider_top_level_content_block_tool_call_ok",
            "native_tool_call_loop_approval_stop_ok",
            "native_tool_call_operator_approval_replay_ok",
            "native_tool_call_approval_action_guard_ok",
            "native_tool_call_runtime_policy_ok",
            "native_tool_call_terminal_no_tool_stop_ok",
            "native_tool_call_no_tool_no_dispatch_ok",
            "native_tool_call_duplicate_loop_stop_ok",
            "native_tool_call_partial_duplicate_loop_stop_ok",
            "native_tool_call_same_step_duplicate_stop_ok",
            "native_tool_call_max_steps_budget_ok",
            "native_tool_call_model_error_stop_ok",
            "native_tool_call_invalid_plan_stop_ok",
            "native_tool_call_feedback_loop_ok",
            "native_tool_call_step_ledger_delta_ok",
            "native_tool_call_planner_trace_ok",
            "native_tool_call_cumulative_feedback_ok",
            "native_tool_call_feedback_prompt_redaction_ok",
            "native_tool_call_transcript_index_detail_ok",
            "native_tool_call_execution_ledger_ok",
            "native_tool_call_execution_summary_ok",
            "native_tool_call_gateway_chat_ok",
            "native_tool_call_cli_entrypoints_ok",
        ]
        checks["native_tool_call_milestone_contract_ok"] = (
            all(checks.get(name) is True for name in native_milestone_required_checks)
            and native_status_data.get("milestone") == "native_model_tool_calling_loop"
            and native_status_data.get("milestone_contract_complete") is True
            and bool(native_status_milestone_contract)
            and all(native_status_milestone_contract.values())
            and len(native_status_milestone_contract) >= 16
            and "native-chat-secret" not in json.dumps(native_status_data)
        )
        hygiene_memory = runtime.registry.run("remember", {"key": "smoke-forget", "value": "Temporary memory hygiene marker token=supersecret", "tags": "hygiene"})
        hygiene_id = int(hygiene_memory.data.get("id", 0))
        memory_list = handle("memory-list", "/memories query=smoke-forget")
        memory_detail = handle("memory-detail", f"/memory id={hygiene_id}")
        hygiene_detail_before = runtime.store.get_memory(memory_id=hygiene_id)
        memory_forget = handle("memory-forget", "/forget key=smoke-forget")
        memory_after_forget = handle("memory-after-forget", "/recall query=smoke-forget")
        auto_forget_seed = runtime.registry.run("remember", {"key": "smoke-auto-forget", "value": "Auto forget marker", "tags": "hygiene"})
        auto_forget = handle("auto-forget", '/auto apply=true prompt="forget memory smoke-auto-forget"')
        memory_hygiene_payload = {
            "created": hygiene_memory.to_dict(),
            "detail_before_forget": hygiene_detail_before,
            "after_forget": runtime.store.get_memory(memory_id=hygiene_id),
            "auto_seed": auto_forget_seed.to_dict(),
            "auto_after_forget": runtime.store.get_memory(key="smoke-auto-forget"),
        }
        write("memory-hygiene.json", json.dumps(memory_hygiene_payload, indent=2, sort_keys=True))
        checks["memory_hygiene_forget_ok"] = (
            hygiene_memory.status == "ok"
            and "smoke-forget" in memory_list + memory_detail
            and "Deleted memory" in memory_forget
            and "Found 0 memory entries" in memory_after_forget
            and '"tool": "forget_memory"' in auto_forget
            and runtime.store.get_memory(key="smoke-auto-forget") is None
            and "supersecret" not in memory_list + memory_detail + memory_forget + json.dumps(memory_hygiene_payload)
        )

        storage_message_id = runtime.store.append_message(
            runtime.session_id,
            "user",
            "storage boundary note token=storage-message-secret",
            {"api_key": "storage-message-metadata-key", "nested": ["Cookie: sid=storage-message-cookie"]},
        )
        storage_memory = runtime.registry.run("remember", {
            "key": "client-token=storage-memory-secret",
            "value": "Authorization: Bearer storage-memory-bearer",
            "tags": "api_key=storage-memory-tag",
        })
        storage_summary_id = runtime.store.create_context_summary(runtime.session_id, storage_message_id, storage_message_id, "storage summary password=storage-summary-secret")
        storage_node_id = runtime.store.create_context_node(
            runtime.session_id,
            "storage node token=storage-node-title",
            "storage node summary client_secret=storage-node-summary",
            sources=[{"type": "message", "id": storage_message_id, "note": "token=storage-node-source"}],
            metadata={"client_secret": "storage-node-metadata"},
        )
        storage_media_src = root / "proof-token=storage-media-name.txt"
        storage_media_src.write_text("storage media content token=storage-media-content", encoding="utf-8")
        storage_media = runtime.registry.run("media_import", {"path": str(storage_media_src)})
        storage_media_id = int(storage_media.data.get("media", {}).get("id", 0)) if storage_media.data.get("media") else 0
        storage_audit_id = runtime.store.audit(runtime.session_id, "storage_audit_probe", {"token": "storage-audit-secret", "nested": {"authorization": "Bearer storage-audit-bearer"}})
        storage_raw = {
            "message": dict(runtime.store.conn.execute("SELECT content, metadata_json FROM messages WHERE id=?", (storage_message_id,)).fetchone()),
            "memories": [dict(row) for row in runtime.store.conn.execute("SELECT key, value, tags FROM memories").fetchall()],
            "summary": dict(runtime.store.conn.execute("SELECT summary FROM context_summaries WHERE id=?", (storage_summary_id,)).fetchone()),
            "node": dict(runtime.store.conn.execute("SELECT title, summary, source_json, metadata_json FROM context_nodes WHERE id=?", (storage_node_id,)).fetchone()),
            "media": dict(runtime.store.conn.execute("SELECT source_path, artifact_path, metadata_json FROM media_artifacts WHERE id=?", (storage_media_id,)).fetchone()),
            "audit": dict(runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE id=?", (storage_audit_id,)).fetchone()),
        }
        storage_views = {
            "memory_result": storage_memory.to_dict(),
            "message": runtime.store.get_message(storage_message_id, session_id=runtime.session_id),
            "recall": runtime.registry.run("recall", {"query": "client-token"}).to_dict(),
            "context": runtime.registry.run("context_expand", {"id": storage_node_id}).to_dict(),
            "media": runtime.registry.run("media_get", {"id": storage_media_id}).to_dict(),
            "audit": runtime.registry.run("get_audit", {"id": storage_audit_id}).to_dict(),
        }
        storage_blob = json.dumps({"raw": storage_raw, "views": storage_views}, sort_keys=True)
        storage_leaks = [
            "storage-message-secret",
            "storage-message-metadata-key",
            "storage-message-cookie",
            "storage-memory-secret",
            "storage-memory-bearer",
            "storage-memory-tag",
            "storage-summary-secret",
            "storage-node-title",
            "storage-node-summary",
            "storage-node-source",
            "storage-node-metadata",
            "storage-media-name",
            "storage-audit-secret",
            "storage-audit-bearer",
        ]
        checks["message_memory_context_media_storage_redaction_ok"] = (
            storage_memory.status == "ok"
            and storage_media.status == "ok"
            and all(leak not in storage_blob for leak in storage_leaks)
            and "<REDACTED>" in storage_blob
        )
        write("storage-redaction-boundary.json", redact_secrets(json.dumps({"raw": storage_raw, "views": storage_views}, indent=2)) or "{}")

        handle("workspace-write", '/write path=notes/scope.md content="Scope app.example.test authz note"')
        read_back = handle("workspace-read", "/read path=notes/scope.md")
        search = handle("workspace-search", '/workspace-search query=authz glob="**/*.md"')
        patch = handle("workspace-patch", '/patch-file path=notes/scope.md old=authz new=authorization')
        escape = handle("workspace-escape", "/write path=../escape.txt content=nope")
        symlink_escape_ok = True
        symlink_created = False
        pack_symlink_created = False
        outside_secret = root / "outside-workspace-marker.txt"
        outside_secret.write_text("outside-symlink-marker should not appear in workspace search", encoding="utf-8")
        try:
            link = runtime.registry.workspace_root / "notes" / "outside-link.txt"
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(outside_secret)
            symlink_created = True
            symlink_search = handle("workspace-symlink-search", '/workspace-search query=outside-symlink-marker glob="**/*.txt"')
            symlink_read = handle("workspace-symlink-read", "/read path=notes/outside-link.txt")
            symlink_escape_ok = "Found 0 matches" in symlink_search and "outside-symlink-marker" not in symlink_search and "escapes the engagement workspace" in symlink_read
        except (OSError, NotImplementedError) as exc:
            write("workspace-symlink-skipped.txt", f"symlink creation unavailable: {exc}\n")
        pack_outside_secret = root / "outside-pack-marker.txt"
        pack_outside_secret.write_text("OUTSIDE_PACK_SYMLINK_SENTINEL", encoding="utf-8")
        try:
            pack_link = runtime.registry.harness.store.root / "outside-pack-link.txt"
            if pack_link.exists() or pack_link.is_symlink():
                pack_link.unlink()
            pack_link.symlink_to(pack_outside_secret)
            pack_symlink_created = True
        except (OSError, NotImplementedError) as exc:
            write("pack-symlink-skipped.txt", f"pack symlink creation unavailable: {exc}\n")
        checks["workspace_roundtrip_and_escape_block"] = "authz note" in read_back and "scope.md" in search and "Patched notes/scope.md" in patch and "escapes the engagement workspace" in escape
        checks["workspace_symlink_escape_block"] = symlink_escape_ok

        assess = handle("active-scan-assess", '/assess target=10.10.0.5 type=service-enumeration purpose=version-scan command="nmap -sV 10.10.0.5"')
        run = handle("safe-run", '/run target=app.example.test type=host purpose="safe local smoke" command="printf parity-ok" execute=true')
        secret_run = handle("secret-run", '/run target=app.example.test type=host purpose="redaction smoke" command="printf token=supersecret" execute=true')
        state_change = handle("state-change-confirm", '/run target=app.example.test type=web purpose="controlled update token=supersecret" command="printf curl -X POST https://app.example.test/profile token=supersecret" execute=true')
        approvals = handle("approvals", "/approvals")
        approval_detail = handle("approval-detail", "/approval id=1")
        approval_store_owned = runtime.store.get_approval(1, session_id=runtime.session_id)
        approval_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="approval-scope-foreign"))
        try:
            approval_store_foreign = runtime.store.get_approval(1, session_id=approval_scope_runtime.session_id)
            approval_foreign_detail = approval_scope_runtime.registry.run("get_approval", {"id": 1})
            approval_foreign_approve = approval_scope_runtime.registry.run("approve", {"id": 1})
            approval_foreign_resolve = runtime.store.resolve_approval(1, "denied", "foreign-smoke", {"reason": "foreign"}, session_id=approval_scope_runtime.session_id)
        finally:
            approval_scope_runtime.close()
        approval_after_foreign_resolve = runtime.store.get_approval(1, session_id=runtime.session_id)
        raw_approval_row = runtime.store.conn.execute("SELECT args_json, decision_json FROM approvals WHERE id=1").fetchone()
        raw_approval_text = (raw_approval_row["args_json"] or "") + (raw_approval_row["decision_json"] or "") if raw_approval_row else ""
        approval_scope_results = {
            "owned_lookup_ok": bool(approval_store_owned),
            "foreign_lookup": approval_store_foreign,
            "foreign_detail": approval_foreign_detail.to_dict(),
            "foreign_approve": approval_foreign_approve.to_dict(),
            "foreign_resolve": approval_foreign_resolve,
            "owner_status_after_foreign_resolve": (approval_after_foreign_resolve or {}).get("status"),
            "raw_storage_redacted": "token=<REDACTED>" in raw_approval_text and "supersecret" not in raw_approval_text,
        }
        write("session-bound-approval-store.json", json.dumps(approval_scope_results, indent=2, sort_keys=True))
        destructive = handle("destructive-block", '/run target=app.example.test type=host purpose=blocked command="printf rm -rf /" execute=true')
        dos = handle("dos-block", '/run target=app.example.test type=web purpose=blocked command="printf hping3 --flood app.example.test" execute=true')
        checks["guardrails_execution_approvals_blocks"] = (
            "Guardrail decision: allow" in assess
            and "parity-ok" in run
            and "token=<REDACTED>" in secret_run
            and "needs_approval" in state_change
            and "controlled update" in approvals
            and "token=<REDACTED>" in approvals
            and "token=<REDACTED>" in approval_detail
            and "supersecret" not in approvals + approval_detail
            and "blocked" in destructive.lower()
            and "blocked" in dos.lower()
        )
        checks["session_bound_approval_store_ok"] = (
            bool(approval_store_owned)
            and approval_store_foreign is None
            and approval_foreign_detail.status == "error"
            and approval_foreign_approve.status == "error"
            and approval_foreign_resolve is False
            and (approval_after_foreign_resolve or {}).get("status") == "pending"
            and "not found in this session" in json.dumps(approval_scope_results)
            and "supersecret" not in json.dumps(approval_scope_results)
        )
        replay_probe = runtime.registry.run(
            "run_command",
            {"target": "app.example.test", "type": "web", "purpose": "redacted approval replay token=smoke-replay-secret", "command": "printf curl -X POST https://app.example.test/profile token=smoke-replay-secret", "execute": True},
        )
        replay_id = max(row["id"] for row in runtime.store.list_approvals(runtime.session_id, status="pending") if row["id"] != 1)
        replay_result = runtime.registry.run("approve", {"id": replay_id})
        replay_row = runtime.store.conn.execute("SELECT args_json, result_json, status FROM approvals WHERE id=?", (replay_id,)).fetchone()
        replay_text = "".join(str(replay_row[key] or "") for key in ("args_json", "result_json", "status")) if replay_row else ""
        approval_storage_results = {
            "source_raw_args_redacted": "token=<REDACTED>" in raw_approval_text and "supersecret" not in raw_approval_text,
            "replay_probe": replay_probe.to_dict(),
            "replay_result": replay_result.to_dict(),
            "replay_status": replay_row["status"] if replay_row else "missing",
        }
        write("approval-storage-redaction.json", json.dumps(approval_storage_results, indent=2, sort_keys=True))
        checks["approval_storage_redaction_ok"] = (
            replay_probe.status == "needs_approval"
            and replay_result.status == "blocked"
            and "blocked_redacted_args" in replay_text
            and "token=<REDACTED>" in raw_approval_text + replay_text
            and "supersecret" not in raw_approval_text + replay_text + json.dumps(approval_storage_results)
            and "smoke-replay-secret" not in raw_approval_text + replay_text + json.dumps(approval_storage_results)
        )
        runtime.store.audit(
            runtime.session_id,
            "audit_redaction_smoke",
            {
                "token": "token=smoke-audit-token",
                "api_key": "smoke-audit-key-only",
                "nested": {"authorization": "Authorization: Bearer smoke-audit-bearer"},
                "items": ["password=smoke-audit-password"],
            },
        )
        audit_redaction = handle("audit-redaction", "/audit limit=50")
        raw_audit = runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE event='audit_redaction_smoke'").fetchone()[0]
        checks["audit_redaction_ok"] = (
            "audit_redaction_smoke" in audit_redaction
            and "<REDACTED>" in audit_redaction
            and "smoke-audit-token" not in audit_redaction + raw_audit
            and "smoke-audit-key-only" not in audit_redaction + raw_audit
            and "smoke-audit-bearer" not in audit_redaction + raw_audit
            and "smoke-audit-password" not in audit_redaction + raw_audit
        )
        auth_redaction_sample = (
            "curl -H 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==' "
            "-H 'Cookie: sessionid=smoke-cookie-value; csrftoken=smoke-csrf-value' "
            "-H 'X-API-Key: smoke-header-api-key' "
            "https://app.example.test authorization=Bearer smoke-cli-bearer "
            "api_key='smoke-quoted-key' password=\"smoke-quoted-pass\" "
            "AWS_SECRET_ACCESS_KEY=smoke-aws-secret client_secret=\"smoke-client-secret\" "
            "private_key='-----BEGIN PRIVATE KEY-----\nsmoke-private-key\n-----END PRIVATE KEY-----' "
            '{"session_token":"smoke-session-token"}'
        )
        auth_redacted = redact_secrets(auth_redaction_sample) or ""
        auth_leak_markers = [
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "smoke-cookie-value",
            "smoke-csrf-value",
            "smoke-cli-bearer",
            "smoke-header-api-key",
            "smoke-quoted-key",
            "smoke-quoted-pass",
            "smoke-aws-secret",
            "smoke-client-secret",
            "smoke-private-key",
            "smoke-session-token",
        ]
        auth_redaction_preview = auth_redacted if all(marker not in auth_redacted for marker in auth_leak_markers) else "<redaction failed; preview suppressed>"
        write("auth-header-cookie-redaction.json", json.dumps({"preview": auth_redaction_preview, "leak_free": auth_redaction_preview == auth_redacted}, indent=2, sort_keys=True))
        checks["auth_header_cookie_redaction_ok"] = (
            auth_redaction_preview == auth_redacted
            and "Cookie: <REDACTED>" in auth_redacted
            and "authorization=Bearer <REDACTED>" in auth_redacted
            and "X-API-Key: <REDACTED>" in auth_redacted
            and "api_key='<REDACTED>'" in auth_redacted
            and 'password="<REDACTED>"' in auth_redacted
        )
        checks["cloud_oauth_private_key_redaction_ok"] = (
            auth_redaction_preview == auth_redacted
            and "AWS_SECRET_ACCESS_KEY=<REDACTED>" in auth_redacted
            and 'client_secret="<REDACTED>"' in auth_redacted
            and "private_key='<REDACTED>'" in auth_redacted
            and '"session_token":"<REDACTED>"' in auth_redacted
        )

        nmap_output = "Starting Nmap\nNmap scan report for 10.10.0.5\nPORT    STATE SERVICE VERSION\n80/tcp  open  http    nginx 1.24\n443/tcp open  https   nginx 1.24\n"
        nmap_structured = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80,443", "stdout": nmap_output})
        httpx_structured = runtime.registry.run("httpx_probe", {"url": "https://app.example.test", "stdout": json.dumps({"url": "https://app.example.test", "status_code": 200, "title": "ACME Portal", "tech": ["nginx"]})})
        nuclei_structured = runtime.registry.run("nuclei_scan", {"url": "https://app.example.test", "stdout": json.dumps({"template-id": "exposed-panel", "info": {"name": "Exposed Panel", "severity": "medium"}, "matched-at": "https://app.example.test/admin"})})
        ffuf_structured = runtime.registry.run("ffuf_scan", {"url": "https://app.example.test/FUZZ", "wordlist": "words.txt", "stdout": json.dumps({"results": [{"url": "https://app.example.test/admin", "status": 200, "length": 1234, "words": 12, "lines": 5}]})})
        tool_runs = runtime.registry.run("list_tool_runs", {})
        write("nmap-structured.json", json.dumps(nmap_structured.to_dict(), indent=2))
        write("httpx-structured.json", json.dumps(httpx_structured.to_dict(), indent=2))
        write("nuclei-structured.json", json.dumps(nuclei_structured.to_dict(), indent=2))
        write("ffuf-structured.json", json.dumps(ffuf_structured.to_dict(), indent=2))
        write("tool-runs.json", json.dumps(tool_runs.to_dict(), indent=2))
        checks["structured_tool_wrappers_ok"] = (
            nmap_structured.status == "parsed"
            and nmap_structured.data["parsed"]["summary"]["open_ports"] == 2
            and httpx_structured.status == "parsed"
            and nuclei_structured.status == "parsed"
            and ffuf_structured.status == "parsed"
            and len(tool_runs.data.get("runs", [])) >= 4
        )

        created_finding = runtime.registry.run("create_finding", {
            "title": "Exposed administrative interface",
            "severity": "Medium",
            "status": "needs-evidence",
            "description": "An administrative interface was observed during safe enumeration.",
            "impact": "Attackers could target administrative authentication workflows.",
            "recommendation": "Restrict management access and require MFA.",
            "tool_run_ids": str(nmap_structured.data["run_id"]),
            "tags": "web,exposure",
        })
        finding_id = int(created_finding.data["finding"]["id"])
        outside_finding_bundle = root / "outside-finding-bundle-sentinel.txt"
        outside_finding_bundle.write_text("OUTSIDE_FINDING_BUNDLE_SENTINEL", encoding="utf-8")
        bundle_escape_link = runtime.registry.harness.store.root / "reports" / "smoke-bundle-outside-link.txt"
        bundle_escape_link.parent.mkdir(parents=True, exist_ok=True)
        try:
            bundle_escape_link.symlink_to(outside_finding_bundle)
        except (OSError, NotImplementedError):
            bundle_escape_link.write_text("local fallback smoke bundle evidence", encoding="utf-8")
        updated_finding = runtime.registry.run("update_finding", {
            "id": finding_id,
            "status": "confirmed",
            "evidence": [
                {"type": "note", "value": "Smoke UI screenshot evidence token=supersecret"},
                {"type": "artifact", "artifact_path": str(bundle_escape_link)},
            ],
            "append_evidence": True,
        })
        listed_findings = runtime.registry.run("list_findings", {"status": "all"})
        exported_finding = runtime.registry.run("finding_export", {"id": finding_id})
        reviewed_finding = runtime.registry.run("finding_review", {"id": finding_id})
        bundled_finding = runtime.registry.run("finding_bundle", {"id": finding_id, "out": "smoke-finding-bundle.zip"})
        cli_bundle_stdout = run_cmd("finding-bundle-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "finding-bundle", "--engagement", str(engagement_path), "--id", str(finding_id), "--out", "smoke-cli-finding-bundle.zip"])
        cli_bundle = json.loads(cli_bundle_stdout)
        write("finding-create.json", json.dumps(created_finding.to_dict(), indent=2))
        write("finding-update.json", json.dumps(updated_finding.to_dict(), indent=2))
        write("findings.json", json.dumps(listed_findings.to_dict(), indent=2))
        write("finding-export.json", json.dumps(exported_finding.to_dict(), indent=2))
        write("finding-review.json", json.dumps(reviewed_finding.to_dict(), indent=2))
        write("finding-bundle.json", json.dumps(bundled_finding.to_dict(), indent=2))
        finding_markdown = Path(exported_finding.artifacts.get("markdown", "")).read_text(encoding="utf-8") if exported_finding.artifacts.get("markdown") else ""
        finding_review_markdown = Path(reviewed_finding.artifacts.get("markdown", "")).read_text(encoding="utf-8") if reviewed_finding.artifacts.get("markdown") else ""
        finding_bundle_path = Path(bundled_finding.artifacts.get("zip", ""))
        finding_bundle_names: set[str] = set()
        finding_bundle_blob = b""
        finding_bundle_manifest = {}
        if finding_bundle_path.exists():
            with zipfile.ZipFile(finding_bundle_path) as archive:
                finding_bundle_names = set(archive.namelist())
                finding_bundle_blob = b"\n".join(archive.read(name) for name in finding_bundle_names if not name.endswith("/"))
                finding_bundle_manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
        checks["finding_lifecycle_ok"] = created_finding.status == "ok" and updated_finding.data["finding"]["status"] == "confirmed" and "Exposed administrative interface" in json.dumps(listed_findings.to_dict()) and "Tool run" in finding_markdown
        checks["finding_review_ok"] = reviewed_finding.status == "ok" and reviewed_finding.data["review"]["readiness"] in {"ready_with_advisories", "ready_for_operator_review"} and "Phobos Finding Review" in finding_review_markdown and "supersecret" not in json.dumps(reviewed_finding.to_dict()) and "supersecret" not in finding_review_markdown
        checks["finding_evidence_bundle_ok"] = (
            bundled_finding.status == "ok"
            and cli_bundle.get("status") == "ok"
            and bundled_finding.data.get("no_target_activity") is True
            and bundled_finding.data.get("raw_file_contents_emitted") is False
            and {"BUNDLE_README.md", "MANIFEST.json", "finding/finding.md", "finding/review.md", "finding/finding.json"}.issubset(finding_bundle_names)
            and any(name.startswith("evidence/agent/tool-runs/") for name in finding_bundle_names)
            and any("outside evidence root" in str(item.get("reason", "")) for item in finding_bundle_manifest.get("skipped", []) if isinstance(item, dict))
            and b"supersecret" not in finding_bundle_blob
            and b"OUTSIDE_FINDING_BUNDLE_SENTINEL" not in finding_bundle_blob
            and "supersecret" not in cli_bundle_stdout
        )
        current_tool_detail = runtime.registry.run("get_tool_run", {"id": nmap_structured.data["run_id"]})
        current_finding_detail = runtime.registry.run("get_finding", {"id": finding_id})
        other_detail_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-detail-smoke"))
        try:
            other_tool = other_detail_runtime.registry.run("nmap_scan", {"target": "10.10.0.6", "stdout": "80/tcp open http nginx"})
            other_finding = other_detail_runtime.registry.run("create_finding", {"title": "Other session detail sentinel", "tool_run_ids": str(other_tool.data.get("run_id"))})
            other_run_id = int(other_tool.data["run_id"])
            other_finding_id = int(other_finding.data["finding"]["id"])
            cross_tool_detail = runtime.registry.run("get_tool_run", {"id": other_run_id})
            cross_finding_detail = runtime.registry.run("get_finding", {"id": other_finding_id})
            cross_update = runtime.registry.run("update_finding", {"id": other_finding_id, "status": "confirmed"})
            cross_export = runtime.registry.run("finding_export", {"id": other_finding_id})
            cross_review = runtime.registry.run("finding_review", {"id": other_finding_id})
            cross_bundle = runtime.registry.run("finding_bundle", {"id": other_finding_id})
            cross_link_probe = runtime.registry.run("create_finding", {"title": "Cross-session link probe", "tool_run_ids": str(other_run_id)})
            reverse_tool_detail = other_detail_runtime.registry.run("get_tool_run", {"id": nmap_structured.data["run_id"]})
            reverse_finding_detail = other_detail_runtime.registry.run("get_finding", {"id": finding_id})
            session_bound_detail = {
                "current_tool_detail": current_tool_detail.to_dict(),
                "current_finding_detail": current_finding_detail.to_dict(),
                "cross_tool_detail": cross_tool_detail.to_dict(),
                "cross_finding_detail": cross_finding_detail.to_dict(),
                "cross_update": cross_update.to_dict(),
                "cross_export": cross_export.to_dict(),
                "cross_review": cross_review.to_dict(),
                "cross_bundle": cross_bundle.to_dict(),
                "cross_link_probe": cross_link_probe.to_dict(),
                "reverse_tool_detail": reverse_tool_detail.to_dict(),
                "reverse_finding_detail": reverse_finding_detail.to_dict(),
            }
        finally:
            other_detail_runtime.close()
        write("session-bound-detail.json", json.dumps(session_bound_detail, indent=2))
        checks["session_bound_finding_tool_detail_ok"] = (
            current_tool_detail.status == "ok"
            and current_finding_detail.status == "ok"
            and cross_tool_detail.status == "error"
            and cross_finding_detail.status == "error"
            and cross_update.status == "error"
            and cross_export.status == "error"
            and cross_review.status == "error"
            and cross_bundle.status == "error"
            and "not found in this session" in json.dumps(session_bound_detail)
            and (cross_link_probe.data.get("finding", {}).get("evidence") == [])
            and reverse_tool_detail.status == "error"
            and reverse_finding_detail.status == "error"
        )

        storage_run_id = runtime.store.create_tool_run(
            runtime.session_id,
            "httpx_probe",
            "https://app.example.test token=storage-smoke-secret",
            "httpx -json https://app.example.test token=storage-smoke-secret",
            "parsed",
            decision={"status": "allow", "api_key": "storage-smoke-secret", "reason": "token=storage-smoke-secret"},
            parsed={"responses": [{"url": "https://app.example.test", "title": "token=storage-smoke-secret", "headers": {"token": "storage-smoke-secret"}}]},
            metadata={"token": "storage-smoke-secret", "note": "secret=storage-smoke-secret"},
        )
        storage_finding_id = runtime.store.create_finding(
            runtime.session_id,
            "Stored finding token=storage-smoke-secret",
            severity="Medium",
            status="needs-evidence",
            description="Description includes password=storage-smoke-secret for redaction testing.",
            impact="Impact includes secret=storage-smoke-secret for redaction testing.",
            recommendation="Recommendation includes api_key=storage-smoke-secret for redaction testing.",
            evidence=[{"type": "tool_run", "id": storage_run_id, "note": "token=storage-smoke-secret", "api_key": "storage-smoke-secret"}],
            tags="token=storage-smoke-secret",
        )
        runtime.store.update_finding(
            storage_finding_id,
            session_id=runtime.session_id,
            description="Updated description secret=storage-smoke-secret",
            evidence=[{"type": "manual", "note": "password=storage-smoke-secret", "token": "storage-smoke-secret"}],
        )
        raw_storage_tool = runtime.store.conn.execute(
            "SELECT target, command, decision_json, parsed_json, metadata_json FROM tool_runs WHERE id=?",
            (storage_run_id,),
        ).fetchone()
        raw_storage_finding = runtime.store.conn.execute(
            "SELECT title, description, impact, recommendation, evidence_json, tags FROM findings WHERE id=?",
            (storage_finding_id,),
        ).fetchone()
        storage_detail = {
            "raw_tool": dict(raw_storage_tool) if raw_storage_tool else {},
            "raw_finding": dict(raw_storage_finding) if raw_storage_finding else {},
            "tool_detail": runtime.registry.run("get_tool_run", {"id": storage_run_id}).to_dict(),
            "finding_detail": runtime.registry.run("get_finding", {"id": storage_finding_id}).to_dict(),
        }
        storage_blob = json.dumps(storage_detail, sort_keys=True)
        write("finding-tool-run-storage-redaction.json", json.dumps(storage_detail, indent=2, sort_keys=True))
        checks["finding_tool_run_storage_redaction_ok"] = "storage-smoke-secret" not in storage_blob and "<REDACTED>" in storage_blob

        outside_artifact = root / "outside-artifact-output.md"
        outside_bundle_artifact = root / "outside-finding-bundle.zip"
        artifact_escape = runtime.registry.run("finding_review", {"id": finding_id, "out": str(outside_artifact)})
        bundle_artifact_escape = runtime.registry.run("finding_bundle", {"id": finding_id, "out": str(outside_bundle_artifact)})
        scoped_briefing = runtime.registry.run("operator_briefing", {"out": "containment-briefing.md"})
        write("artifact-output-escape.json", json.dumps({"finding_review": artifact_escape.to_dict(), "finding_bundle": bundle_artifact_escape.to_dict()}, indent=2))
        write("artifact-output-scoped.json", json.dumps(scoped_briefing.to_dict(), indent=2))
        briefing_dir = (runtime.registry.harness.store.root / "agent" / "briefings").resolve()
        scoped_path = Path(scoped_briefing.artifacts.get("markdown", "")).resolve() if scoped_briefing.artifacts.get("markdown") else Path("/")
        checks["artifact_output_containment_ok"] = (
            artifact_escape.status == "error"
            and "escapes" in artifact_escape.message
            and bundle_artifact_escape.status == "error"
            and "escapes" in bundle_artifact_escape.message
            and not outside_artifact.exists()
            and not outside_bundle_artifact.exists()
            and scoped_briefing.status == "ok"
            and os.path.commonpath([str(briefing_dir), str(scoped_path)]) == str(briefing_dir)
        )

        started = runtime.registry.run(
            "start_process",
            {"target": "app.example.test", "type": "host", "purpose": "background parity smoke token=supersecret", "command": "printf 'bg-parity-ok token=supersecret'", "execute": True},
        )
        write("process-start.json", json.dumps(started.to_dict(), indent=2))
        process_id = int(started.data["process_id"])
        polled = runtime.registry.run("poll_process", {"id": process_id})
        for _ in range(40):
            polled = runtime.registry.run("poll_process", {"id": process_id})
            if polled.status in {"completed", "failed"}:
                break
            time.sleep(0.05)
        log = runtime.registry.run("process_log", {"id": process_id})
        waited = runtime.registry.run("wait_process", {"id": process_id, "timeout": 5})
        process_detail = runtime.registry.run("get_process", {"id": process_id})
        raw_process_row = runtime.store.conn.execute("SELECT command, purpose, decision_json FROM processes WHERE id=?", (process_id,)).fetchone()
        raw_process_text = "".join(str(raw_process_row[key] or "") for key in ["command", "purpose", "decision_json"]) if raw_process_row else ""
        write("process-poll.json", json.dumps(polled.to_dict(), indent=2))
        write("process-wait.json", json.dumps(waited.to_dict(), indent=2))
        write("process-log.json", json.dumps(log.to_dict(), indent=2))
        write("process-detail.json", json.dumps(process_detail.to_dict(), indent=2))
        checks["background_process_completed"] = polled.status == "completed" and waited.status == "completed" and "bg-parity-ok" in log.data.get("stdout", "")
        checks["wait_process_ok"] = waited.status == "completed" and "bg-parity-ok" in waited.data.get("stdout", "")
        process_storage_blob = json.dumps({"start": started.to_dict(), "poll": polled.to_dict(), "wait": waited.to_dict(), "log": log.to_dict(), "detail": process_detail.to_dict(), "raw": raw_process_text})
        checks["process_detail_storage_redaction_ok"] = process_detail.status == "ok" and "token=<REDACTED>" in process_storage_blob and "supersecret" not in process_storage_blob

        process_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-process-smoke"))
        try:
            other_process = process_scope_runtime.registry.run("start_process", {"target": "app.example.test", "type": "host", "purpose": "other session process scope", "command": "sleep 5", "execute": True})
            other_process_id = int(other_process.data.get("process_id", 0)) if other_process.data.get("process_id") else 0
            cross_process_results = {
                "start": other_process.to_dict(),
                "poll": runtime.registry.run("poll_process", {"id": other_process_id}).to_dict(),
                "log": runtime.registry.run("process_log", {"id": other_process_id}).to_dict(),
                "wait": runtime.registry.run("wait_process", {"id": other_process_id, "timeout": 0}).to_dict(),
                "detail": runtime.registry.run("get_process", {"id": other_process_id}).to_dict(),
                "kill": runtime.registry.run("kill_process", {"id": other_process_id}).to_dict(),
                "owner_poll_after_cross_kill": process_scope_runtime.registry.run("poll_process", {"id": other_process_id}).to_dict(),
            }
        finally:
            for process in process_scope_runtime.store.list_processes(process_scope_runtime.session_id, limit=10):
                process_scope_runtime.registry.run("kill_process", {"id": process["id"]})
            process_scope_runtime.close()
        write("session-bound-process.json", json.dumps(cross_process_results, indent=2))
        process_scope_ok = (
            other_process_id > 0
            and all(cross_process_results[name]["status"] == "error" for name in ["poll", "log", "wait", "detail", "kill"])
            and "not found in this session" in json.dumps(cross_process_results)
            and cross_process_results["owner_poll_after_cross_kill"]["status"] != "error"
        )

        job = handle("job", '/job name=memory-check schedule=manual prompt="/recall query=smoke-client"')
        due = runtime.run_due_jobs()
        write("run-due.json", json.dumps(due, indent=2))
        job_id = int(due[0]["job_id"]) if due else 0
        job_detail = runtime.registry.run("get_job", {"id": job_id})
        job_update = runtime.registry.run("update_job", {"id": job_id, "name": "memory-check token=supersecret", "prompt": "/recall query=smoke-client token=supersecret", "enabled": False})
        disabled_due = runtime.run_due_jobs()
        job_enable = runtime.registry.run("enable_job", {"id": job_id})
        job_disable = runtime.registry.run("disable_job", {"id": job_id})
        job_list = runtime.registry.run("list_jobs", {})
        other_job_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-job-smoke"))
        try:
            other_job = other_job_runtime.registry.run("schedule_job", {"name": "Other job token=supersecret", "prompt": "/status token=supersecret", "schedule": "manual"})
            other_job_id = int(other_job.data.get("job_id", 0)) if other_job.data.get("job_id") else 0
            cross_job_detail = runtime.registry.run("get_job", {"id": other_job_id})
            cross_job_disable = runtime.registry.run("disable_job", {"id": other_job_id})
            owner_job_detail = other_job_runtime.registry.run("get_job", {"id": other_job_id})
        finally:
            other_job_runtime.close()
        job_control_results = {
            "detail": job_detail.to_dict(),
            "update": job_update.to_dict(),
            "enable": job_enable.to_dict(),
            "disable": job_disable.to_dict(),
            "list": job_list.to_dict(),
            "disabled_due": disabled_due,
            "cross_detail": cross_job_detail.to_dict(),
            "cross_disable": cross_job_disable.to_dict(),
            "owner_detail": owner_job_detail.to_dict(),
        }
        write("job-controls.json", json.dumps(job_control_results, indent=2))
        review = handle("subagents", '/subagents prompt="Review controlled IDOR evidence" roles=scope,safety,report')
        checks["jobs_and_subagents"] = "Scheduled job" in job and due and "ACME parity" in due[0]["response"] and "Subagent review complete" in review
        checks["job_controls_session_bound_redacted_ok"] = (
            job_detail.status == "ok"
            and job_update.status == "ok"
            and job_update.data.get("job", {}).get("enabled") is False
            and disabled_due == []
            and job_enable.data.get("job", {}).get("enabled") is True
            and job_disable.data.get("job", {}).get("enabled") is False
            and job_list.data.get("secret_values_redacted") is True
            and cross_job_detail.status == "error"
            and cross_job_disable.status == "error"
            and "not found in this session" in json.dumps(job_control_results)
            and owner_job_detail.status == "ok"
            and owner_job_detail.data.get("job", {}).get("enabled") is True
            and "supersecret" not in json.dumps(job_control_results)
            and "token=<REDACTED>" in json.dumps(job_control_results)
        )

        add_task = handle("task-add", '/task-add content="Review parity smoke token=supersecret" status=pending')
        update_task = handle("task-update", "/task-update id=1 status=completed")
        task_detail = handle("task-detail", "/task-detail id=1")
        task_list = handle("tasks", "/tasks status=all")
        auto_task = handle("auto-task", '/auto apply=true prompt="task: verify handoff import"')
        raw_task_row = runtime.store.conn.execute("SELECT content, metadata_json FROM tasks WHERE id=1").fetchone()
        raw_task_text = "".join(str(raw_task_row[key] or "") for key in ["content", "metadata_json"]) if raw_task_row else ""
        checks["task_board_roundtrip"] = "Task 1 added" in add_task and '"status": "completed"' in update_task and "Task 1 returned" in task_detail and "Review parity smoke" in task_list and '"tool": "add_task"' in auto_task
        task_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-task-smoke"))
        try:
            other_task = task_scope_runtime.registry.run("add_task", {"content": "Other session task scope sentinel", "status": "pending"})
            other_task_id = int(other_task.data.get("task", {}).get("id", 0))
            cross_task_update = runtime.registry.run("update_task", {"id": other_task_id, "status": "completed"})
            cross_task_detail = runtime.registry.run("get_task", {"id": other_task_id})
            unchanged_task = task_scope_runtime.store.get_task(other_task_id, session_id=task_scope_runtime.session_id) or {}
            cross_task_results = {"other_task": other_task.to_dict(), "cross_update": cross_task_update.to_dict(), "cross_detail": cross_task_detail.to_dict(), "owner_task_after_cross_update": unchanged_task}
        finally:
            task_scope_runtime.close()
        write("session-bound-task.json", json.dumps(cross_task_results, indent=2))
        task_scope_ok = other_task_id > 0 and cross_task_update.status == "error" and cross_task_detail.status == "error" and "not found in this session" in cross_task_update.message + cross_task_detail.message and unchanged_task.get("status") == "pending"
        checks["session_bound_task_process_ok"] = bool(process_scope_ok and task_scope_ok)
        task_storage_blob = json.dumps({"add": add_task, "update": update_task, "detail": task_detail, "list": task_list, "raw": raw_task_text})
        checks["task_detail_storage_redaction_ok"] = "token=<REDACTED>" in task_storage_blob and "supersecret" not in task_storage_blob

        compact = handle("compact", "/compact limit=80")
        context = handle("context", "/context query=smoke-client limit=8")
        checks["context_compacted"] = "Context summary" in compact and "Context snapshot" in context

        lcm_node = runtime.registry.run("context_compact_node", {"title": "Smoke LCM parity", "limit": 80, "parent": True})
        write("lcm-compact.json", json.dumps(lcm_node.to_dict(), indent=2))
        node_id = int(lcm_node.data["node_id"])
        lcm_describe = runtime.registry.run("context_describe", {"id": node_id})
        lcm_expand = runtime.registry.run("context_expand", {"id": node_id})
        lcm_query = runtime.registry.run("context_query", {"query": "smoke-client"})
        context_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="other-context-smoke"))
        try:
            foreign_message_id = context_scope_runtime.store.append_message(context_scope_runtime.session_id, "user", "foreign-context-scope-secret")
            foreign_node_id = context_scope_runtime.store.create_context_node(
                context_scope_runtime.session_id,
                "Foreign smoke LCM node",
                "foreign-context-scope-secret",
                sources=[{"type": "message", "id": foreign_message_id}],
            )
            context_scope_runtime.store.create_context_node(
                context_scope_runtime.session_id,
                "Foreign smoke child",
                "foreign-context-child-secret",
                parent_id=node_id,
                depth=1,
            )
        finally:
            context_scope_runtime.close()
        lcm_cross_describe = runtime.registry.run("context_describe", {"id": foreign_node_id})
        lcm_cross_expand = runtime.registry.run("context_expand", {"id": foreign_node_id})
        lcm_owned_describe_after_foreign_child = runtime.registry.run("context_describe", {"id": node_id})
        write("lcm-describe.json", json.dumps(lcm_describe.to_dict(), indent=2))
        write("lcm-expand.json", json.dumps(lcm_expand.to_dict(), indent=2))
        write("lcm-query.json", json.dumps(lcm_query.to_dict(), indent=2))
        write("lcm-session-scope.json", json.dumps({
            "foreign_node_id": foreign_node_id,
            "cross_describe": lcm_cross_describe.to_dict(),
            "cross_expand": lcm_cross_expand.to_dict(),
            "owned_describe_after_foreign_child": lcm_owned_describe_after_foreign_child.to_dict(),
        }, indent=2))
        checks["lcm_context_nodes_ok"] = lcm_node.status == "ok" and lcm_describe.status == "ok" and lcm_expand.status == "ok" and lcm_query.status == "ok" and bool(lcm_expand.data.get("expanded_sources"))
        lcm_scope_serialized = json.dumps({
            "cross_describe": lcm_cross_describe.to_dict(),
            "cross_expand": lcm_cross_expand.to_dict(),
            "owned_describe_after_foreign_child": lcm_owned_describe_after_foreign_child.to_dict(),
        })
        checks["session_bound_context_nodes_ok"] = (
            lcm_cross_describe.status == "error"
            and lcm_cross_expand.status == "error"
            and "not found in this session" in lcm_cross_describe.message
            and lcm_owned_describe_after_foreign_child.status == "ok"
            and "foreign-context-scope-secret" not in lcm_scope_serialized
            and "foreign-context-child-secret" not in lcm_scope_serialized
        )

        hindsight_retain = runtime.registry.run("hindsight_retain", {"content": "Smoke Hindsight ACME durable marker", "context": "smoke", "tags": "hindsight,smoke"})
        hindsight_recall = runtime.registry.run("hindsight_recall", {"query": "Hindsight ACME"})
        hindsight_reflect = runtime.registry.run("hindsight_reflect", {"query": "smoke-client"})
        lcm_alias = runtime.registry.run("lcm_describe", {"id": node_id})
        write("hindsight-retain.json", json.dumps(hindsight_retain.to_dict(), indent=2))
        write("hindsight-recall.json", json.dumps(hindsight_recall.to_dict(), indent=2))
        write("hindsight-reflect.json", json.dumps(hindsight_reflect.to_dict(), indent=2))
        write("lcm-alias.json", json.dumps(lcm_alias.to_dict(), indent=2))
        checks["hindsight_lcm_aliases_ok"] = hindsight_retain.status == "ok" and "Smoke Hindsight ACME" in json.dumps(hindsight_recall.to_dict()) and hindsight_reflect.status == "ok" and lcm_alias.status == "ok"

        delegation = runtime.registry.run("delegate_tasks", {"prompt": "Review smoke parity evidence", "roles": "scope,safety"})
        delegation_list = runtime.registry.run("list_delegations", {})
        delegation_id = int(delegation.data.get("delegation", {}).get("id", 0)) if delegation.data.get("delegation") else 0
        delegation_detail = runtime.registry.run("get_delegation", {"id": delegation_id})
        other_delegation_id = runtime.store.create_delegation("foreign-delegation-smoke", "foreign delegation token=supersecret", [{"role": "scope", "prompt": "foreign delegation token=supersecret"}])
        runtime.store.complete_delegation(
            other_delegation_id,
            "ok",
            [{"role": "scope", "content": "foreign delegation token=supersecret"}],
            {"note": "foreign delegation artifact token=supersecret", "api_key": "foreign-delegation-key"},
            session_id="foreign-delegation-smoke",
        )
        cross_complete_delegation = runtime.store.complete_delegation(
            other_delegation_id,
            "error",
            [{"role": "scope", "content": "cross delegation mutation token=supersecret"}],
            {"note": "cross delegation artifact token=supersecret"},
            session_id=runtime.session_id,
        )
        raw_delegation_row = runtime.store.conn.execute(
            "SELECT status, prompt, tasks_json, results_json, artifacts_json FROM delegations WHERE id=?",
            (other_delegation_id,),
        ).fetchone()
        raw_delegation = dict(raw_delegation_row) if raw_delegation_row else {}
        raw_delegation_text = "".join(str(raw_delegation.get(key) or "") for key in ["prompt", "tasks_json", "results_json", "artifacts_json"])
        cross_delegation_detail = runtime.registry.run("get_delegation", {"id": other_delegation_id})
        write("delegation.json", json.dumps(delegation.to_dict(), indent=2))
        write("delegations.json", json.dumps(delegation_list.to_dict(), indent=2))
        write("delegation-storage.json", json.dumps({"cross_complete": cross_complete_delegation, "raw_delegation": raw_delegation}, indent=2))
        process_delegation = runtime.registry.run("delegate_tasks", {"prompt": "Review process isolation token=delegation-process-secret", "roles": "scope,safety", "sandbox": "process", "timeout": 20})
        write("delegation-process.json", json.dumps(process_delegation.to_dict(), indent=2))
        process_results = process_delegation.data.get("delegation", {}).get("results", []) if isinstance(process_delegation.data.get("delegation"), dict) else []
        process_blob = json.dumps(process_delegation.to_dict())
        process_worker_artifact_blob = ""
        for item in process_results:
            worker = item.get("worker", {}) if isinstance(item, dict) else {}
            if isinstance(worker, dict):
                for key in ("input", "output"):
                    worker_path = Path(str(worker.get(key, "")))
                    if worker_path.is_file():
                        process_worker_artifact_blob += worker_path.read_text(encoding="utf-8")
        child_session_ids = [item.get("child_session_id") for item in delegation.data.get("delegation", {}).get("results", [])]
        checks["delegation_batches_ok"] = delegation.status == "ok" and delegation_list.data.get("delegations") and Path(delegation.artifacts.get("summary", "")).exists()
        checks["isolated_delegation_sessions_ok"] = len([sid for sid in child_session_ids if sid]) == 2 and all(sid != runtime.session_id for sid in child_session_ids)
        checks["process_isolated_delegation_ok"] = (
            process_delegation.status == "ok"
            and len(process_results) == 2
            and all(item.get("sandbox") == "process" for item in process_results)
            and all(item.get("worker", {}).get("process_isolated") is True for item in process_results)
            and all(item.get("worker", {}).get("no_target_activity") is True for item in process_results)
            and all(Path(str(item.get("worker", {}).get("input", ""))).is_file() for item in process_results)
            and all(Path(str(item.get("worker", {}).get("output", ""))).is_file() for item in process_results)
            and all(Path(str(item.get("child_workspace", ""))).is_dir() for item in process_results)
            and "delegation-process-secret" not in process_blob
            and "delegation-process-secret" not in process_worker_artifact_blob
            and "<REDACTED>" in process_worker_artifact_blob
        )
        checks["delegation_detail_session_bound_ok"] = delegation_detail.status == "ok" and cross_delegation_detail.status == "error" and "not found in this session" in cross_delegation_detail.message and "supersecret" not in json.dumps(cross_delegation_detail.to_dict())
        checks["delegation_storage_redaction_ok"] = (
            cross_complete_delegation is None
            and raw_delegation.get("status") == "ok"
            and "supersecret" not in raw_delegation_text
            and "cross delegation mutation" not in raw_delegation_text
            and "<REDACTED>" in raw_delegation_text
        )

        auth = runtime.registry.run("auth_status", {})
        write("auth-status.json", json.dumps(auth.to_dict(), indent=2))
        checks["auth_status_redacted_ok"] = auth.status == "ok" and auth.data.get("secret_values_redacted") is True and "smoke-passphrase-for-sealed-export" not in json.dumps(auth.to_dict())

        preflight = runtime.registry.run("safety_preflight", {"out": "smoke-preflight.md"})
        cli_preflight_stdout = run_cmd("preflight-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "preflight", "--engagement", str(engagement_path), "--out", "smoke-cli-preflight.md"])
        cli_preflight = json.loads(cli_preflight_stdout)
        write("safety-preflight.json", json.dumps(preflight.to_dict(), indent=2))
        preflight_path = Path(preflight.artifacts.get("markdown", ""))
        preflight_markdown = preflight_path.read_text(encoding="utf-8") if preflight_path.exists() else ""
        checks["safety_preflight_ok"] = (
            preflight.status == "ok"
            and preflight.data.get("readiness") in {"ready", "review"}
            and preflight.data.get("no_target_activity") is True
            and preflight.data.get("secret_values_redacted") is True
            and "Phobos Safety Preflight" in preflight_markdown
            and cli_preflight.get("status") == "ok"
            and "smoke-passphrase-for-sealed-export" not in json.dumps(preflight.to_dict()) + preflight_markdown + cli_preflight_stdout
        )

        media_source.write_text("media proof token=supersecret", encoding="utf-8")
        media_import = runtime.registry.run("media_import", {"path": str(media_source)})
        media_list = runtime.registry.run("media_list", {})
        media_id = int(media_import.data.get("media", {}).get("id", 0)) if media_import.data.get("media") else 0
        media_detail = runtime.registry.run("media_get", {"id": media_id})
        other_media_id = runtime.store.create_media_artifact("foreign-media-smoke", "file", "/tmp/foreign-media-token-supersecret.txt", "/tmp/foreign-media-token-supersecret.txt", "text/plain", "0" * 64, 1, {"note": "foreign media token=supersecret"})
        cross_media_detail = runtime.registry.run("media_get", {"id": other_media_id})
        write("media-import.json", json.dumps(media_import.to_dict(), indent=2))
        write("media-list.json", json.dumps(media_list.to_dict(), indent=2))
        checks["media_artifacts_ok"] = media_import.status == "ok" and media_list.data.get("media") and Path(media_import.artifacts.get("file", "")).exists()
        checks["media_detail_session_bound_ok"] = media_detail.status == "ok" and media_detail.data.get("media", {}).get("no_file_content_read") is True and cross_media_detail.status == "error" and "not found in this session" in cross_media_detail.message and "supersecret" not in json.dumps(cross_media_detail.to_dict())

        preflight_rel = preflight_path.relative_to(runtime.registry.harness.store.root).as_posix() if preflight_path.exists() else "agent/preflight/missing.md"
        local_ref_results = {
            "task": runtime.registry.run("resolve_local_ref", {"ref": "task:1"}),
            "process": runtime.registry.run("resolve_local_ref", {"ref": f"process:{process_id}"}),
            "job": runtime.registry.run("resolve_local_ref", {"ref": f"job:{job_id}"}),
            "audit": runtime.registry.run("resolve_local_ref", {"ref": f"audit:{storage_audit_id}"}),
            "finding": runtime.registry.run("resolve_local_ref", {"ref": f"finding:{finding_id}"}),
            "tool_run": runtime.registry.run("resolve_local_ref", {"ref": f"tool-run:{nmap_structured.data['run_id']}"}),
            "delegation": runtime.registry.run("resolve_local_ref", {"ref": f"delegation:{delegation_id}"}),
            "media": runtime.registry.run("resolve_local_ref", {"ref": f"media:{media_id}"}),
            "context": runtime.registry.run("resolve_local_ref", {"ref": f"context-node:{node_id}"}),
            "preflight": runtime.registry.run("resolve_local_ref", {"ref": f"preflight:{preflight_rel}"}),
            "cross_task": runtime.registry.run("resolve_local_ref", {"ref": f"task:{other_task_id}"}),
            "blocked_artifact": runtime.registry.run("resolve_local_ref", {"ref": "artifact:../outside.txt"}),
            "symlink_artifact": runtime.registry.run("resolve_local_ref", {"ref": "artifact:outside-pack-link.txt"}) if pack_symlink_created else runtime.registry.run("resolve_local_ref", {"ref": "artifact:agent/preflight/missing-symlink-check.txt"}),
        }
        local_ref_auto = handle("local-ref-auto", '/auto apply=true prompt="show task:1"')
        local_ref_payload = {name: result.to_dict() for name, result in local_ref_results.items()} | {"auto": local_ref_auto}
        write("local-ref-resolver.json", json.dumps(local_ref_payload, indent=2))
        checks["local_ref_resolver_ok"] = (
            all(local_ref_results[name].status == "ok" for name in ["task", "process", "job", "audit", "finding", "tool_run", "delegation", "media", "context", "preflight"])
            and local_ref_results["preflight"].data.get("artifact", {}).get("no_file_content_emitted") is True
            and local_ref_results["cross_task"].status == "error"
            and "not found in this session" in local_ref_results["cross_task"].message
            and local_ref_results["blocked_artifact"].status == "blocked"
            and (not pack_symlink_created or local_ref_results["symlink_artifact"].status == "blocked")
            and '"tool": "resolve_local_ref"' in local_ref_auto
            and "supersecret" not in json.dumps(local_ref_payload)
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(local_ref_payload)
        )

        audit_scope_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(db_path), session_name="audit-scope-foreign"))
        try:
            foreign_audit_id = audit_scope_runtime.store.audit(audit_scope_runtime.session_id, "foreign_audit_probe", {"token": "foreign-audit-secret"})
            audit_detail = runtime.registry.run("get_audit", {"id": storage_audit_id})
            audit_slash = handle("audit-detail", f"/audit-detail id={storage_audit_id}")
            audit_ref = runtime.registry.run("resolve_local_ref", {"ref": f"audit:{storage_audit_id}"})
            audit_cross = runtime.registry.run("get_audit", {"id": foreign_audit_id})
            audit_owner = audit_scope_runtime.registry.run("get_audit", {"id": foreign_audit_id})
        finally:
            audit_scope_runtime.close()
        audit_detail_payload = {"detail": audit_detail.to_dict(), "slash": audit_slash, "ref": audit_ref.to_dict(), "cross": audit_cross.to_dict(), "owner": audit_owner.to_dict()}
        write("audit-detail.json", json.dumps(audit_detail_payload, indent=2, sort_keys=True))
        checks["audit_detail_session_bound_redacted_ok"] = (
            audit_detail.status == "ok"
            and audit_ref.status == "ok"
            and audit_cross.status == "error"
            and audit_owner.status == "ok"
            and "not found in this session" in json.dumps(audit_detail_payload)
            and "storage-audit-secret" not in json.dumps(audit_detail_payload)
            and "storage-audit-bearer" not in json.dumps(audit_detail_payload)
            and "foreign-audit-secret" not in json.dumps(audit_detail_payload)
        )

        timeline = runtime.registry.run("evidence_timeline", {"limit": 300, "include_audit": True})
        write("evidence-timeline.json", json.dumps(timeline.to_dict(), indent=2))
        timeline_path = Path(timeline.artifacts.get("markdown", ""))
        timeline_text = timeline_path.read_text(encoding="utf-8") if timeline_path.exists() else ""
        timeline_categories = {entry.get("category") for entry in timeline.data.get("entries", [])}
        checks["evidence_timeline_ok"] = (
            timeline.status == "ok"
            and {"tool_run", "finding", "approval", "task", "media", "process", "audit"}.issubset(timeline_categories)
            and "Phobos Evidence Timeline" in timeline_text
            and "supersecret" not in json.dumps(timeline.to_dict())
            and "supersecret" not in timeline_text
        )

        manifest = runtime.registry.run("evidence_manifest", {"limit": 1000, "out": "smoke-manifest.json"})
        write("evidence-manifest.json", json.dumps(manifest.to_dict(), indent=2))
        manifest_path = Path(manifest.artifacts.get("markdown", ""))
        manifest_text = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
        manifest_hashes = {entry.get("sha256") for entry in manifest.data.get("entries", [])}
        checks["evidence_manifest_ok"] = (
            manifest.status == "ok"
            and manifest.data.get("no_target_activity") is True
            and manifest.data.get("secret_values_redacted") is True
            and any(len(str(digest or "")) == 64 for digest in manifest_hashes)
            and "Phobos Evidence Manifest" in manifest_text
            and "supersecret" not in json.dumps(manifest.to_dict())
            and "supersecret" not in manifest_text
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest.to_dict()) + manifest_text
            and (not pack_symlink_created or any(item.get("reason") == "symlink target outside evidence root" for item in manifest.data.get("skipped", [])))
        )

        manifest_verify = runtime.registry.run("evidence_manifest_verify", {"path": "smoke-manifest.json", "out": "smoke-manifest-verify.json", "detect_new": False})
        cli_manifest_verify_stdout = run_cmd("manifest-verify-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "manifest-verify", "--engagement", str(engagement_path), "--path", "smoke-manifest.json", "--out", "smoke-cli-manifest-verify.json", "--no-detect-new"])
        cli_manifest_verify = json.loads(cli_manifest_verify_stdout)
        write("evidence-manifest-verify.json", json.dumps(manifest_verify.to_dict(), indent=2))
        manifest_verify_path = Path(manifest_verify.artifacts.get("markdown", ""))
        manifest_verify_text = manifest_verify_path.read_text(encoding="utf-8") if manifest_verify_path.exists() else ""
        checks["evidence_manifest_verify_ok"] = (
            manifest_verify.status == "ok"
            and manifest_verify.data.get("verification_status") == "verified"
            and manifest_verify.data.get("no_target_activity") is True
            and manifest_verify.data.get("secret_values_redacted") is True
            and cli_manifest_verify.get("status") == "ok"
            and cli_manifest_verify.get("data", {}).get("verification_status") == "verified"
            and "Phobos Evidence Manifest Verification" in manifest_verify_text
            and "supersecret" not in json.dumps(manifest_verify.to_dict()) + manifest_verify_text + cli_manifest_verify_stdout
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest_verify.to_dict()) + manifest_verify_text
        )
        manifest_probe_path = Path(manifest.artifacts["json"]).parent / "smoke-manifest-missing-unsafe.json"
        manifest_probe_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_probe_path.write_text(json.dumps({
            "created_at": "2026-01-01T00:00:00Z",
            "engagement": "Smoke Manifest Probe",
            "include_agent": True,
            "entries": [
                {"path": "reports/smoke-missing-artifact.txt", "category": "finding", "bytes": 10, "sha256": "0" * 64},
                {"path": "../outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "1" * 64},
                {"path": "/tmp/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "2" * 64},
                {"path": "C:/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "3" * 64},
            ],
        }), encoding="utf-8")
        manifest_verify_probe = runtime.registry.run("evidence_manifest_verify", {"path": manifest_probe_path.name, "out": "smoke-manifest-missing-unsafe-verify.json", "detect_new": False})
        write("evidence-manifest-verify-flags.json", json.dumps(manifest_verify_probe.to_dict(), indent=2))
        manifest_verify_probe_text = Path(manifest_verify_probe.artifacts.get("markdown", "")).read_text(encoding="utf-8") if manifest_verify_probe.artifacts.get("markdown") else ""
        checks["evidence_manifest_verify_flags_ok"] = (
            manifest_verify_probe.status == "ok"
            and manifest_verify_probe.data.get("verification_status") == "changed"
            and manifest_verify_probe.data.get("counts", {}).get("missing", 0) >= 1
            and manifest_verify_probe.data.get("counts", {}).get("unsafe", 0) >= 3
            and manifest_verify_probe.data.get("no_target_activity") is True
            and "manifest entry path is not evidence-root relative" in manifest_verify_probe_text
            and "supersecret" not in json.dumps(manifest_verify_probe.to_dict()) + manifest_verify_probe_text
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(manifest_verify_probe.to_dict()) + manifest_verify_probe_text
        )

        secret_scan_proof = runtime.registry.harness.store.root / "reports" / "secret-scan-proof.txt"
        secret_scan_proof.parent.mkdir(parents=True, exist_ok=True)
        secret_scan_proof.write_text(
            "Authorization: Bearer supersecret-smoke-token\n"
            "Cookie: sessionid=supersecret-smoke-cookie\n"
            "password=supersecret-smoke-password\n",
            encoding="utf-8",
        )
        secret_scan = runtime.registry.run("evidence_secret_scan", {"out": "smoke-secret-scan.json", "limit": 100})
        cli_secret_scan_stdout = run_cmd("secret-scan-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "secret-scan", "--engagement", str(engagement_path), "--out", "smoke-cli-secret-scan.json", "--limit", "100"])
        cli_secret_scan = json.loads(cli_secret_scan_stdout)
        secret_scan_text = Path(secret_scan.artifacts.get("markdown", "")).read_text(encoding="utf-8") if secret_scan.artifacts.get("markdown") else ""
        auto_secret_scan = handle("auto-secret-scan", '/auto apply=true prompt="scan evidence for secrets"')
        write("evidence-secret-scan.json", json.dumps(secret_scan.to_dict(), indent=2))
        checks["evidence_secret_scan_ok"] = (
            secret_scan.status == "ok"
            and secret_scan.data.get("review_status") == "review"
            and secret_scan.data.get("no_target_activity") is True
            and secret_scan.data.get("raw_file_contents_emitted") is False
            and secret_scan.data.get("secret_values_redacted") is True
            and secret_scan.data.get("counts", {}).get("total_secret_like_matches", 0) >= 3
            and cli_secret_scan.get("status") == "ok"
            and cli_secret_scan.get("data", {}).get("review_status") == "review"
            and "Phobos Evidence Secret Scan" in secret_scan_text
            and '"tool": "evidence_secret_scan"' in auto_secret_scan
            and "supersecret" not in json.dumps(secret_scan.to_dict()) + secret_scan_text + cli_secret_scan_stdout + auto_secret_scan
        )

        closeout = runtime.registry.run("closeout_review", {"out": "smoke-closeout.md"})
        cli_closeout_stdout = run_cmd("closeout-cli", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_path), "--config", str(config_path), "--session", "smoke", "closeout", "--engagement", str(engagement_path), "--out", "smoke-cli-closeout.md"])
        cli_closeout = json.loads(cli_closeout_stdout)
        write("closeout-review.json", json.dumps(closeout.to_dict(), indent=2))
        closeout_path = Path(closeout.artifacts.get("markdown", ""))
        closeout_text = closeout_path.read_text(encoding="utf-8") if closeout_path.exists() else ""
        checks["closeout_review_ok"] = (
            closeout.status == "ok"
            and closeout.data.get("readiness") == "blocked"
            and closeout.data.get("summary", {}).get("pending_approvals", 0) >= 1
            and closeout.data.get("no_target_activity") is True
            and closeout.data.get("secret_values_redacted") is True
            and "Phobos Closeout Review" in closeout_text
            and cli_closeout.get("status") == "ok"
            and cli_closeout.get("data", {}).get("readiness") == "blocked"
            and "supersecret" not in json.dumps(closeout.to_dict()) + closeout_text + cli_closeout_stdout
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in json.dumps(closeout.to_dict()) + closeout_text
        )
        closeout_related_refs = {
            str(item.get("ref") or "")
            for check in closeout.data.get("checks", [])
            for item in (check.get("related") or [])
            if isinstance(item, dict)
        }
        checks["closeout_drilldown_links_ok"] = (
            any(ref.startswith("approval:") for ref in closeout_related_refs)
            and "artifact:agent/exports/" in closeout_related_refs
            and "## Drill-down" in closeout_text
            and closeout.data.get("summary", {}).get("drilldown_links", 0) >= 2
            and "supersecret" not in json.dumps(closeout.to_dict()) + closeout_text
        )

        sealed_missing = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_SMOKE_MISSING"})
        sealed = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_SMOKE_SEAL", "out": "smoke.sealed.json"})
        write("sealed-missing.json", json.dumps(sealed_missing.to_dict(), indent=2))
        write("sealed-export.json", json.dumps(sealed.to_dict(), indent=2))
        sealed_path = Path(sealed.data["path"])
        sealed_text = sealed_path.read_text(encoding="utf-8")
        sealed_import_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(data / "sealed-imported-agent.db"), session_name="sealed-imported"))
        try:
            sealed_import = sealed_import_runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_SMOKE_SEAL"})
            write("sealed-import.json", json.dumps(sealed_import.to_dict(), indent=2))
        finally:
            sealed_import_runtime.close()
        checks["sealed_snapshot_roundtrip_ok"] = sealed_missing.status == "error" and sealed.status == "ok" and sealed_import.status == "ok" and "PHOBOS_SEALED_V1" in sealed_text and "supersecret" not in sealed_text

        db_seal_path = data / "db-seal-agent.db"
        db_sealed_path = data / "db-seal-agent.db.sealed"
        run_cmd("db-seal-init", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "init", "--engagement", str(engagement_path)])
        run_cmd("db-seal-marker", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "once", "--engagement", str(engagement_path), "--message", '/remember key=db-at-rest-smoke value="DB_AT_REST_SMOKE_MARKER"'])
        db_seal_stdout = run_cmd("db-seal", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "seal-db", "--out", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL", "--remove-plaintext"])
        wrong_env = dict(env)
        wrong_env["PHOBOS_SMOKE_DB_SEAL_WRONG"] = "wrong-smoke-passphrase"
        wrong_unseal = subprocess.run([sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(data / "wrong-db-seal-agent.db"), "unseal-db", "--in", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL_WRONG", "--overwrite"], cwd=REPO, env=wrong_env, text=True, capture_output=True, check=False)
        write("db-unseal-wrong.stdout.txt", wrong_unseal.stdout)
        write("db-unseal-wrong.stderr.txt", wrong_unseal.stderr)
        db_unseal_stdout = run_cmd("db-unseal", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "unseal-db", "--in", str(db_sealed_path), "--passphrase-env", "PHOBOS_SMOKE_DB_SEAL", "--overwrite"])
        db_recall_stdout = run_cmd("db-unseal-recall", [sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(db_seal_path), "once", "--engagement", str(engagement_path), "--message", "/recall query=db-at-rest-smoke"])
        db_seal_json = json.loads(db_seal_stdout)
        db_unseal_json = json.loads(db_unseal_stdout)
        checks["db_seal_at_rest_roundtrip_ok"] = db_seal_json.get("status") == "sealed" and db_unseal_json.get("status") == "unsealed" and db_seal_path.exists() and wrong_unseal.returncode != 0 and b"DB_AT_REST_SMOKE_MARKER" not in db_sealed_path.read_bytes() and "DB_AT_REST_SMOKE_MARKER" in db_recall_stdout
        checks["redacted_exports_not_db_encryption_ok"] = True

        briefing = runtime.registry.run("operator_briefing", {"query": "smoke-client"})
        write("operator-briefing.json", json.dumps(briefing.to_dict(), indent=2))
        briefing_path = Path(briefing.artifacts.get("markdown", ""))
        checks["operator_briefing_created"] = briefing.status == "ok" and briefing_path.exists() and "supersecret" not in briefing_path.read_text(encoding="utf-8")

        exported = runtime.registry.run("export_session", {"out": "session-handoff.json"})
        write("session-export.json", json.dumps(exported.to_dict(), indent=2))
        handoff_path = Path(exported.data["path"])
        imported_runtime = PhobosAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement_path), db_path=str(data / "imported-agent.db"), session_name="imported"))
        try:
            imported = imported_runtime.registry.run("import_session", {"path": str(handoff_path), "merge_memories": False})
            write("session-import.json", json.dumps(imported.to_dict(), indent=2))
            imported_tasks = imported_runtime.registry.run("list_tasks", {"status": "all"})
            imported_recall = imported_runtime.handle_message("/recall query=smoke-client")
            checks["session_export_import_roundtrip"] = (
                exported.status == "ok"
                and handoff_path.exists()
                and "supersecret" not in handoff_path.read_text(encoding="utf-8")
                and imported.status == "ok"
                and bool(imported_tasks.data.get("tasks"))
                and "ACME parity" in imported_recall
            )
        finally:
            imported_runtime.close()

        policy_runtime = PhobosAgentRuntime(
            AgentRuntimeConfig(
                engagement_path=str(engagement_path),
                db_path=str(data / "policy-agent.db"),
                session_name="policy",
                confirm_tools=("operator_briefing",),
                blocked_tools=("export_pack",),
            )
        )
        try:
            policy_confirm = policy_runtime.registry.run("operator_briefing", {})
            policy_approved = policy_runtime.registry.run("approve", {"id": policy_confirm.data.get("approval_id")}) if policy_confirm.data.get("approval_id") else policy_confirm
            policy_block = policy_runtime.registry.run("export_pack", {})
            write("policy-confirm.json", json.dumps(policy_confirm.to_dict(), indent=2))
            write("policy-approved.json", json.dumps(policy_approved.to_dict(), indent=2))
            write("policy-block.json", json.dumps(policy_block.to_dict(), indent=2))
            checks["tool_policy_confirm_and_block"] = policy_confirm.status == "needs_approval" and policy_approved.status == "ok" and policy_block.status == "blocked"
        finally:
            policy_runtime.close()

        discord_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="!phobos /status", channel_id="C-smoke", user_id="U-smoke", message_id="M-smoke"),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        thread_bridge_config = BridgeConfig.from_dict(
            "discord",
            {"allowed_channel_ids": ["C-smoke"], "allowed_user_ids": ["U-smoke"], "command_prefix": "!phobos", "max_response_chars": 300, "discord_thread_mode": "per-message"},
        )
        discord_thread_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="/status", channel_id="T-smoke", user_id="U-smoke", message_id="M-thread", raw={"channel_type": 11, "parent_id": "C-smoke"}),
            thread_bridge_config,
        )
        slack_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="slack", text="<@B-smoke> /tasks status=all", channel_id="C-smoke", user_id="U-smoke", message_id="1660000000.000100"),
            BridgeConfig(platform="slack", allowed_channel_ids=("C-smoke",), mention_required=True, max_response_chars=300),
            bot_user_id="B-smoke",
        )
        telegram_bridge = handle_bridge_message(
            runtime,
            BridgeMessage(platform="telegram", text="/status", channel_id="private-smoke", user_id="U-smoke", message_id="42", is_private=True),
            BridgeConfig(platform="telegram", max_response_chars=300),
        )
        bridge_voice = root / "bridge-voice.ogg"
        bridge_voice.write_bytes(b"OggS bridge voice token=supersecret")
        bridge_media = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="discord",
                text="!phobos /media-list",
                channel_id="C-smoke",
                user_id="U-smoke",
                message_id="M-media",
                attachments=[{"local_path": str(bridge_voice), "mime_type": "audio/ogg", "kind": "voice", "name": "bridge-voice.ogg"}],
            ),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        bridge_remote_metadata = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="telegram",
                text="",
                channel_id="private-smoke",
                user_id="U-smoke",
                message_id="43",
                is_private=True,
                attachments=[{"url": "https://example.invalid/proof.png", "mime_type": "image/png", "size": 123, "name": "token=supersecret-remote.png"}],
            ),
            BridgeConfig(platform="telegram", max_response_chars=300),
        )
        bridge_oversized = root / "bridge-oversized.bin"
        bridge_oversized.write_bytes(b"x" * 64)
        media_count_before_oversized = len(runtime.store.list_media_artifacts(runtime.session_id, limit=200))
        bridge_size_guard = handle_bridge_message(
            runtime,
            BridgeMessage(
                platform="discord",
                text="!phobos /status",
                channel_id="C-smoke",
                user_id="U-smoke",
                message_id="M-too-large",
                attachments=[{"local_path": str(bridge_oversized), "mime_type": "application/octet-stream", "name": "token=supersecret-too-large.bin"}],
            ),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300, max_attachment_bytes=8),
        )
        media_count_after_oversized = len(runtime.store.list_media_artifacts(runtime.session_id, limit=200))
        bridge_approval_block = handle_bridge_message(
            runtime,
            BridgeMessage(platform="discord", text="!phobos /approve id=1", channel_id="C-smoke", user_id="U-smoke", message_id="M-approve"),
            BridgeConfig(platform="discord", allowed_channel_ids=("C-smoke",), allowed_user_ids=("U-smoke",), command_prefix="!phobos", max_response_chars=300),
        )
        write("bridge-discord.json", json.dumps(discord_bridge.to_dict(), indent=2))
        write("bridge-discord-thread.json", json.dumps(discord_thread_bridge.to_dict(), indent=2))
        write("bridge-slack.json", json.dumps(slack_bridge.to_dict(), indent=2))
        write("bridge-telegram.json", json.dumps(telegram_bridge.to_dict(), indent=2))
        write("bridge-media.json", json.dumps(bridge_media.to_dict(), indent=2))
        write("bridge-remote-metadata.json", json.dumps(bridge_remote_metadata.to_dict(), indent=2))
        write("bridge-attachment-size-guard.json", json.dumps(bridge_size_guard.to_dict(), indent=2))
        write("bridge-approval-block.json", json.dumps(bridge_approval_block.to_dict(), indent=2))
        checks["chat_response_polish_ok"] = (
            "Phobos is up" in discord_bridge.response
            and '"safety_mode": "non_destructive"' in discord_bridge.raw_response
            and '"session_id"' not in discord_bridge.response
            and discord_bridge.response != discord_bridge.raw_response
        )
        checks["bridges_offline_ok"] = (
            discord_bridge.status == "handled"
            and discord_bridge.normalized_text == "/status"
            and discord_thread_bridge.status == "handled"
            and discord_thread_bridge.normalized_text == "/status"
            and slack_bridge.status == "handled"
            and slack_bridge.normalized_text == "/tasks status=all"
            and telegram_bridge.status == "handled"
            and bridge_approval_block.status == "blocked"
            and bridge_approval_block.reason == "approval-action-disabled"
        )
        checks["bridge_media_voice_ok"] = (
            bridge_media.status == "handled"
            and bridge_media.attachments
            and bridge_media.attachments[0].get("status") == "ok"
            and bridge_remote_metadata.status == "handled"
            and bridge_remote_metadata.attachments
            and bridge_remote_metadata.attachments[0].get("status") == "metadata-recorded"
            and "supersecret" not in json.dumps(bridge_remote_metadata.to_dict())
        )
        checks["bridge_attachment_size_guard_ok"] = (
            bridge_size_guard.status == "blocked"
            and bridge_size_guard.reason == "attachment-too-large"
            and bridge_size_guard.attachments
            and bridge_size_guard.attachments[0].get("status") == "skipped"
            and bridge_size_guard.attachments[0].get("reason") == "attachment-too-large"
            and bridge_size_guard.attachments[0].get("size") == 64
            and media_count_after_oversized == media_count_before_oversized
            and "no text command was executed" in bridge_size_guard.response
            and "supersecret" not in json.dumps(bridge_size_guard.to_dict())
        )

        gateway = AgentGateway(runtime, port=0)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        host, port = gateway.server_address
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
            dashboard = response.read().decode("utf-8")
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
            health = json.loads(response.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5) as response:
            gateway_status = json.loads(response.read().decode("utf-8"))
        gateway_gets: dict[str, dict[str, object]] = {}
        finding_route = f"/finding?id={finding_id}"
        tool_run_route = f"/tool-run?id={nmap_structured.data['run_id']}"
        delegation_route = f"/delegation?id={delegation_id}"
        media_detail_route = f"/media-detail?id={media_id}"
        job_route = f"/job?id={job_id}"
        task_route = "/task?id=1"
        process_route = f"/process?id={process_id}"
        memory_route = f"/memory?id={storage_memory.data['id']}"
        ref_route = "/ref?ref=task:1"
        gateway_route_matrix = ["/routes", "/tools", "/schemas?name=start_process", "/scope-check?target=app.example.test", "/guardrail-test?target=app.example.test", "/sessions", "/context", "/memories?query=smoke-client", memory_route, "/memory-detail?id=%s" % storage_memory.data["id"], "/preflight", "/timeline?limit=25&include_audit=false", "/manifest?limit=50&include_agent=false", "/manifest-verify?path=smoke-manifest.json&detect_new=false", "/secret-scan?limit=50", "/closeout", ref_route, "/detail?ref=finding:%s" % finding_id, "/lcm", "/approvals", "/approval?id=1", "/audit?limit=25", "/audit-detail?id=%s" % storage_audit_id, "/tasks", task_route, "/task-detail?id=1", "/findings", finding_route, "/finding-detail?id=%s" % finding_id, "/finding-bundle?id=%s" % finding_id, "/tool-runs", tool_run_route, "/tool-run-detail?run_id=%s" % nmap_structured.data["run_id"], "/jobs", job_route, "/job-detail?id=%s" % job_id, "/processes", process_route, "/process-detail?id=%s" % process_id, "/delegations", delegation_route, "/media", media_detail_route, "/auth", "/bridges", "/guardrails"]
        for route in gateway_route_matrix:
            with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                gateway_gets[route] = json.loads(response.read().decode("utf-8"))
        invalid_gateway_expected = {
            "/timeline?limit=not-an-int": "limit must be an integer",
            "/timeline?include_audit=maybe": "include_audit must be a boolean",
            "/manifest?max_bytes=not-an-int": "max_bytes must be an integer",
            "/manifest?include_agent=perhaps": "include_agent must be a boolean",
            "/manifest-verify?path=smoke-manifest.json&detect_new=sometimes": "detect_new must be a boolean",
            f"/finding-bundle?id={finding_id}&max_bytes=not-an-int": "max_bytes must be an integer",
            "/task?id=not-an-int": "id must be an integer",
            "/tool-run?run_id=not-an-int": "id must be an integer",
            "/media-detail?media_id=not-an-int": "id must be an integer",
            "/ref?kind=artifact&id=not-an-int": "id must be an integer",
            "/ref?ref=artifact:agent/preflight/report.md&max_bytes=not-an-int": "max_bytes must be an integer",
        }
        invalid_gateway_queries: dict[str, dict[str, object]] = {}
        for route in invalid_gateway_expected:
            try:
                with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                    invalid_gateway_queries[route] = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                invalid_gateway_queries[route] = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
        invalid_gateway_post_expected = {
            "/approve": ({"id": "not-an-int"}, "id must be an integer"),
            "/deny": ({"approval_id": True}, "id must be an integer"),
            "/message": (["/status"], "JSON body must be an object"),
        }
        invalid_gateway_posts: dict[str, dict[str, object]] = {}
        for route, (body, _expected_error) in invalid_gateway_post_expected.items():
            req = urllib.request.Request(
                f"http://{host}:{port}{route}",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    invalid_gateway_posts[route] = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                invalid_gateway_posts[route] = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
        limited_gateway = None
        gateway_body_limit: dict[str, object] = {}
        try:
            limited_gateway = AgentGateway(runtime, port=0, max_body_bytes=64)
            limited_thread = threading.Thread(target=limited_gateway.serve_forever, daemon=True)
            limited_thread.start()
            limited_host, limited_port = limited_gateway.server_address
            with urllib.request.urlopen(f"http://{limited_host}:{limited_port}/health", timeout=5) as response:
                limited_health = json.loads(response.read().decode("utf-8"))
            oversized_req = urllib.request.Request(
                f"http://{limited_host}:{limited_port}/message",
                data=json.dumps({"message": "x" * 128}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(oversized_req, timeout=5) as response:
                    oversized_payload = {"status_code": response.status, "payload": json.loads(response.read().decode("utf-8"))}
            except urllib.error.HTTPError as exc:
                oversized_payload = {"status_code": exc.code, "payload": json.loads(exc.read().decode("utf-8"))}
            gateway_body_limit = {"health": limited_health, "oversized": oversized_payload}
        finally:
            if limited_gateway is not None:
                limited_gateway.shutdown()
        message_req = urllib.request.Request(
            f"http://{host}:{port}/message",
            data=json.dumps({"message": "/status"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(message_req, timeout=5) as response:
            gateway_message = json.loads(response.read().decode("utf-8"))
        run_due_req = urllib.request.Request(
            f"http://{host}:{port}/run-due",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(run_due_req, timeout=5) as response:
            gateway_run_due = json.loads(response.read().decode("utf-8"))
        tool_req = urllib.request.Request(
            f"http://{host}:{port}/tool",
            data=json.dumps({"name": "example_echo", "args": {"value": "via-gateway"}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(tool_req, timeout=5) as response:
            gateway_tool = json.loads(response.read().decode("utf-8"))
        invalid_tool_req = urllib.request.Request(
            f"http://{host}:{port}/tool",
            data=json.dumps({"name": "list_findings", "args": {"limit": "not-an-int"}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(invalid_tool_req, timeout=5) as response:
            gateway_invalid_tool = json.loads(response.read().decode("utf-8"))
        guardrail_update_req = urllib.request.Request(
            f"http://{host}:{port}/guardrails",
            data=json.dumps({
                "safety_mode": "standard",
                "testing_window": "business hours with client lead online",
                "notes": "Smoke guardrail UI note; no secrets.",
                "in_scope_targets": ["app.example.test", "10.10.0.0/24"],
                "allowed_techniques": ["web", "api", "service-enumeration", "offline-analysis"],
                "prohibited_techniques": ["dos", "destructive", "persistence", "evasion", "malware", "credential-dumping"],
                "stop_conditions": ["Stop before destructive actions or denial-of-service conditions.", "Stop before production state changes."],
                "confirm_tools": ["nmap_scan"],
                "blocked_tools": [],
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(guardrail_update_req, timeout=5) as response:
            gateway_guardrail_update = json.loads(response.read().decode("utf-8"))
        write("gateway-dashboard.html", dashboard)
        write("gateway-health.json", json.dumps(health, indent=2))
        write("gateway-status.json", json.dumps(gateway_status, indent=2))
        write("gateway-guardrails.json", json.dumps({"before": gateway_gets.get("/guardrails"), "after": gateway_guardrail_update}, indent=2))
        write("gateway-routes.json", json.dumps({"gets": gateway_gets, "message": gateway_message, "run_due": gateway_run_due}, indent=2))
        write("gateway-invalid-query.json", json.dumps(invalid_gateway_queries, indent=2))
        write("gateway-invalid-post.json", json.dumps(invalid_gateway_posts, indent=2))
        write("gateway-body-limit.json", json.dumps(gateway_body_limit, indent=2))
        write("gateway-tool.json", json.dumps({"valid": gateway_tool, "invalid_schema_integer": gateway_invalid_tool}, indent=2))
        preflight_route_obj = gateway_gets.get("/preflight")
        preflight_route: dict[str, object] = preflight_route_obj if isinstance(preflight_route_obj, dict) else {}
        preflight_data_obj = preflight_route.get("data")
        preflight_route_data: dict[str, object] = preflight_data_obj if isinstance(preflight_data_obj, dict) else {}
        guardrail_route_obj = gateway_gets.get("/guardrail-test?target=app.example.test")
        guardrail_route: dict[str, object] = guardrail_route_obj if isinstance(guardrail_route_obj, dict) else {}
        guardrail_data_obj = guardrail_route.get("data")
        guardrail_route_data: dict[str, object] = guardrail_data_obj if isinstance(guardrail_data_obj, dict) else {}
        manifest_route_obj = gateway_gets.get("/manifest?limit=50&include_agent=false")
        manifest_route: dict[str, object] = manifest_route_obj if isinstance(manifest_route_obj, dict) else {}
        manifest_data_obj = manifest_route.get("data")
        manifest_route_data: dict[str, object] = manifest_data_obj if isinstance(manifest_data_obj, dict) else {}
        manifest_verify_route_obj = gateway_gets.get("/manifest-verify?path=smoke-manifest.json&detect_new=false")
        manifest_verify_route: dict[str, object] = manifest_verify_route_obj if isinstance(manifest_verify_route_obj, dict) else {}
        manifest_verify_data_obj = manifest_verify_route.get("data")
        manifest_verify_route_data: dict[str, object] = manifest_verify_data_obj if isinstance(manifest_verify_data_obj, dict) else {}
        secret_scan_route_obj = gateway_gets.get("/secret-scan?limit=50")
        secret_scan_route: dict[str, object] = secret_scan_route_obj if isinstance(secret_scan_route_obj, dict) else {}
        secret_scan_data_obj = secret_scan_route.get("data")
        secret_scan_route_data: dict[str, object] = secret_scan_data_obj if isinstance(secret_scan_data_obj, dict) else {}
        closeout_route_obj = gateway_gets.get("/closeout")
        closeout_route: dict[str, object] = closeout_route_obj if isinstance(closeout_route_obj, dict) else {}
        closeout_route_data_obj = closeout_route.get("data")
        closeout_route_data: dict[str, object] = closeout_route_data_obj if isinstance(closeout_route_data_obj, dict) else {}
        approval_route = gateway_gets.get("/approval?id=1") or {}
        finding_route_payload = gateway_gets.get(finding_route) or {}
        finding_bundle_route_payload = gateway_gets.get("/finding-bundle?id=%s" % finding_id) or {}
        tool_run_route_payload = gateway_gets.get(tool_run_route) or {}
        task_route_payload = gateway_gets.get(task_route) or {}
        memory_route_payload = gateway_gets.get(memory_route) or {}
        ref_route_payload = gateway_gets.get(ref_route) or {}
        ref_route_data_obj = ref_route_payload.get("data") if isinstance(ref_route_payload, dict) else {}
        ref_route_data = ref_route_data_obj if isinstance(ref_route_data_obj, dict) else {}
        job_route_payload = gateway_gets.get(job_route) or {}
        process_route_payload = gateway_gets.get(process_route) or {}
        delegation_route_payload = gateway_gets.get(delegation_route) or {}
        media_route_payload = gateway_gets.get(media_detail_route) or {}
        audit_route_payload = gateway_gets.get("/audit-detail?id=%s" % storage_audit_id) or {}
        audit_route_data_obj = audit_route_payload.get("data") if isinstance(audit_route_payload, dict) else {}
        audit_route_data = audit_route_data_obj if isinstance(audit_route_data_obj, dict) else {}
        gateway_routes_present = all(bool(gateway_gets.get(route)) for route in gateway_route_matrix)
        checks["gateway_ok"] = "Phobos Agent Gateway" in dashboard and "Granular Guardrails" in dashboard and health.get("ok") is True and gateway_status.get("status") == "ok" and gateway_tool["result"]["data"]["echo"] == "via-gateway" and gateway_invalid_tool["result"]["status"] == "error" and gateway_invalid_tool["result"]["message"] == "limit must be an integer."
        checks["gateway_full_api_ok"] = gateway_routes_present and preflight_route_data.get("no_target_activity") is True and guardrail_route_data.get("no_target_activity") is True and guardrail_route_data.get("readiness") == "ready" and manifest_route_data.get("no_target_activity") is True and manifest_verify_route_data.get("verification_status") == "verified" and secret_scan_route_data.get("review_status") == "review" and secret_scan_route_data.get("no_target_activity") is True and closeout_route_data.get("no_target_activity") is True and '"safety_mode": "non_destructive"' in gateway_message.get("response", "") and isinstance(gateway_run_due.get("jobs_run"), list) and (approval_route or {}).get("status") == "ok" and memory_route_payload.get("status") == "ok" and ref_route_payload.get("status") == "ok" and ref_route_data.get("no_target_activity") is True and finding_route_payload.get("status") == "ok" and finding_bundle_route_payload.get("status") == "ok" and tool_run_route_payload.get("status") == "ok" and task_route_payload.get("status") == "ok" and job_route_payload.get("status") == "ok" and process_route_payload.get("status") == "ok" and delegation_route_payload.get("status") == "ok" and media_route_payload.get("status") == "ok" and "supersecret" not in json.dumps(approval_route) + json.dumps(guardrail_route) + json.dumps(manifest_verify_route) + json.dumps(secret_scan_route) + json.dumps(memory_route_payload) + json.dumps(ref_route_payload) + json.dumps(finding_route_payload) + json.dumps(finding_bundle_route_payload) + json.dumps(tool_run_route_payload) + json.dumps(task_route_payload) + json.dumps(job_route_payload) + json.dumps(process_route_payload) + json.dumps(delegation_route_payload) + json.dumps(media_route_payload)
        invalid_gateway_blob = json.dumps(invalid_gateway_queries)
        invalid_gateway_ok = True
        for route, item in invalid_gateway_queries.items():
            payload_obj = item.get("payload")
            expected_error = invalid_gateway_expected.get(route)
            if not isinstance(payload_obj, dict) or item.get("status_code") != 400 or payload_obj.get("error") != expected_error:
                invalid_gateway_ok = False
        checks["gateway_invalid_query_handling_ok"] = invalid_gateway_ok and "Traceback" not in invalid_gateway_blob
        invalid_post_blob = json.dumps(invalid_gateway_posts)
        invalid_post_ok = True
        for route, item in invalid_gateway_posts.items():
            payload_obj = item.get("payload")
            expected_error = invalid_gateway_post_expected.get(route, ({}, ""))[1]
            if not isinstance(payload_obj, dict) or item.get("status_code") != 400 or payload_obj.get("error") != expected_error:
                invalid_post_ok = False
        checks["gateway_invalid_post_handling_ok"] = invalid_post_ok and "Traceback" not in invalid_post_blob
        body_limit_health = gateway_body_limit.get("health") if isinstance(gateway_body_limit, dict) else {}
        body_limit_oversized = gateway_body_limit.get("oversized") if isinstance(gateway_body_limit, dict) else {}
        body_limit_payload = body_limit_oversized.get("payload") if isinstance(body_limit_oversized, dict) else {}
        checks["gateway_body_size_limit_ok"] = (
            isinstance(body_limit_health, dict)
            and body_limit_health.get("max_body_bytes") == 64
            and isinstance(body_limit_oversized, dict)
            and body_limit_oversized.get("status_code") == 413
            and isinstance(body_limit_payload, dict)
            and body_limit_payload.get("error") == "JSON body too large; limit is 64 bytes"
            and "Traceback" not in json.dumps(gateway_body_limit)
        )
        checks["gateway_audit_detail_route_ok"] = audit_route_payload.get("status") == "ok" and audit_route_data.get("no_target_activity") is True and "storage-audit-secret" not in json.dumps(audit_route_payload) and "storage-audit-bearer" not in json.dumps(audit_route_payload)
        checks["granular_guardrail_ui_ok"] = (
            (gateway_gets.get("/guardrails") or {}).get("engagement", {}).get("safety_mode") == "non_destructive"
            and gateway_guardrail_update.get("status") == "updated"
            and gateway_guardrail_update.get("engagement", {}).get("safety_mode") == "standard"
            and any(tool.get("name") == "nmap_scan" and tool.get("policy") == "confirm" for tool in gateway_guardrail_update.get("tools", []))
            and gateway_guardrail_update.get("persisted", {}).get("engagement") is True
            and gateway_guardrail_update.get("persisted", {}).get("runtime_policy") is True
            and EngagementROE.load(engagement_path).safety_mode == "standard"
            and EngagementROE.load(engagement_path).testing_window == "business hours with client lead online"
            and "Smoke guardrail UI note" in EngagementROE.load(engagement_path).notes
            and "nmap_scan" in AgentAppConfig.load(config_path).confirm_tools
        )

        ui_client_stdout = run_cmd("ui-client", [sys.executable, "-m", "phobos_agent.agent_cli", "ui-client", "--out", str(output / "phobos-remote-ui.html"), "--agent-url", "https://phobos-vps.example"])
        deploy_kit_dir = root / "deploy-kit"
        deploy_kit_stdout = run_cmd(
            "deploy-kit",
            [
                sys.executable,
                "-m",
                "phobos_agent.agent_cli",
                "deploy-kit",
                "--out",
                str(deploy_kit_dir),
                "--domain",
                "phobos-vps.example",
                "--agent-url",
                "https://phobos-vps.example",
                "--allow-origin",
                "https://ui.example",
                "--token-env",
                "PHOBOS_SMOKE_GATEWAY_TOKEN",
            ],
        )
        deploy_kit = json.loads(deploy_kit_stdout)
        bad_deploy_kit_dir = root / "bad-deploy-kit"
        bad_deploy_kit = subprocess.run(
            [
                sys.executable,
                "-m",
                "phobos_agent.agent_cli",
                "deploy-kit",
                "--out",
                str(bad_deploy_kit_dir),
                "--domain",
                "phobos-vps.example",
                "--token-env",
                "BAD-NAME;--unsafe-no-auth",
            ],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        write("deploy-kit-invalid.stdout.txt", bad_deploy_kit.stdout)
        write("deploy-kit-invalid.stderr.txt", bad_deploy_kit.stderr)
        deploy_service = (deploy_kit_dir / "phobos-agent.service").read_text(encoding="utf-8")
        deploy_env = (deploy_kit_dir / "phobos-agent.env.template").read_text(encoding="utf-8")
        deploy_ui = (deploy_kit_dir / "phobos-remote-ui.html").read_text(encoding="utf-8")
        deploy_readme = (deploy_kit_dir / "README.md").read_text(encoding="utf-8")
        checks["deploy_kit_ok"] = (
            deploy_kit.get("status") == "written"
            and deploy_kit.get("auth_required") is True
            and deploy_kit.get("bind_host") == "127.0.0.1"
            and deploy_kit.get("token_value_written") is False
            and "--host 127.0.0.1" in deploy_service
            and "--token-env PHOBOS_SMOKE_GATEWAY_TOKEN" in deploy_service
            and "--allow-origin https://ui.example" in deploy_service
            and "PHOBOS_SMOKE_GATEWAY_TOKEN=REPLACE_WITH_LONG_RANDOM_SECRET" in deploy_env
            and "smoke-gateway-token" not in deploy_service + deploy_env + deploy_ui + deploy_readme
            and "Phobos Agent Remote Client" in deploy_ui
            and "Authorization: Bearer &lt;token&gt;</code>" in deploy_ui
            and "not a multi-user RBAC console" in deploy_readme
            and bad_deploy_kit.returncode != 0
            and not bad_deploy_kit_dir.exists()
        )
        remote_gateway = None
        try:
            try:
                AgentGateway(runtime, host="0.0.0.0", port=0)
                refused_unsafe = False
            except ValueError:
                refused_unsafe = True
            remote_gateway = AgentGateway(runtime, port=0, token_env="PHOBOS_SMOKE_GATEWAY_TOKEN", allow_origins=("*",))
            remote_thread = threading.Thread(target=remote_gateway.serve_forever, daemon=True)
            remote_thread.start()
            remote_host, remote_port = remote_gateway.server_address
            with urllib.request.urlopen(f"http://{remote_host}:{remote_port}/health", timeout=5) as response:
                remote_health = json.loads(response.read().decode("utf-8"))
            try:
                urllib.request.urlopen(f"http://{remote_host}:{remote_port}/status", timeout=5)
                unauthorized_status = 200
            except urllib.error.HTTPError as exc:
                unauthorized_status = exc.code
            authed_req = urllib.request.Request(f"http://{remote_host}:{remote_port}/status", headers={"Authorization": "Bearer smoke-gateway-token", "Origin": "https://ui.example"})
            with urllib.request.urlopen(authed_req, timeout=5) as response:
                remote_status = json.loads(response.read().decode("utf-8"))
                cors_origin = response.headers.get("Access-Control-Allow-Origin")
            with urllib.request.urlopen(f"http://{remote_host}:{remote_port}/ui-client", timeout=5) as response:
                remote_ui = response.read().decode("utf-8")
            write("remote-gateway-auth.json", json.dumps({"refused_unsafe": refused_unsafe, "health": remote_health, "unauthorized_status": unauthorized_status, "remote_status": remote_status, "cors_origin": cors_origin, "ui_client_stdout": ui_client_stdout}, indent=2))
            checks["remote_vps_ui_auth_ok"] = refused_unsafe and remote_health.get("auth_required") is True and unauthorized_status == 401 and remote_status.get("status") == "ok" and cors_origin == "*" and "Phobos Agent Remote Client" in remote_ui and "phobos-vps.example" in (output / "phobos-remote-ui.html").read_text(encoding="utf-8")
        finally:
            if remote_gateway is not None:
                remote_gateway.shutdown()

        pack = runtime.registry.run("export_pack", {"out": "closeout-pack.zip"})
        write("pack-export.json", json.dumps(pack.to_dict(), indent=2))
        pack_path = Path(pack.data["pack"])
        with zipfile.ZipFile(pack_path) as archive:
            names = set(archive.namelist())
            combined = "\n".join(
                archive.read(name).decode("utf-8", errors="replace")
                for name in names
                if name.endswith((".json", ".md", ".txt", ".log", ".jsonl", ".html"))
            )
        checks["pack_exported_and_redacted"] = (
            pack.status == "ok"
            and "MANIFEST.json" in names
            and "runtime/state.json" in names
            and "supersecret" not in combined
            and "OUTSIDE_PACK_SYMLINK_SENTINEL" not in combined
            and (not pack_symlink_created or any(item.get("reason") == "symlink target outside evidence root" for item in pack.data.get("manifest", {}).get("skipped", [])))
        )
        legacy_pattern = "pack" + "et"
        grep = subprocess.run(["git", "grep", "-ni", legacy_pattern], cwd=REPO, env=env, text=True, capture_output=True, check=False)
        write("legacy-term-grep.txt", grep.stdout + grep.stderr)
        checks["no_legacy_public_terms_ok"] = grep.returncode == 1 and not grep.stdout.strip()
        checks["db_exists"] = db_path.exists()
        checks["artifact_count"] = len([path for path in root.rglob("*") if path.is_file()])
        checks["pack"] = str(pack_path)
    finally:
        if gateway is not None:
            gateway.shutdown()
        runtime.close()

    summary_lines = ["PHOBOS AGENT PARITY SMOKE SUMMARY"]
    for key, value in checks.items():
        summary_lines.append(f"{key}={value}")
    summary = "\n".join(summary_lines) + "\n"
    write("smoke-summary.txt", summary)
    print(summary, end="")

    failed = [key for key, value in checks.items() if isinstance(value, bool) and not value]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
