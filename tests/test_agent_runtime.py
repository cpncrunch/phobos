import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import unittest
from unittest import mock
import zipfile
from pathlib import Path

from offsec_agent_harness import AgentAppConfig, AgentGateway, AgentRuntimeConfig, BridgeConfig, BridgeDispatchResult, BridgeMessage, EngagementROE, OffSecAgentRuntime, bridge_doctor, chunk_text, discover_skills, handle_bridge_message, load_skill
from offsec_agent_harness.agent_bridges import DiscordGatewayBridge
from offsec_agent_harness.agent_crypto import seal_bytes, unseal_bytes
from offsec_agent_harness.agent_tools import ToolResult
from offsec_agent_harness.model_adapters import AnthropicMessagesAdapter, BaseModelAdapter, FallbackModelAdapter, GeminiAdapter, ModelResponse, OpenAICompatibleAdapter, OpenAIResponsesAdapter


class FakePlannerAdapter(BaseModelAdapter):
    provider = "fake-planner"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model planned a safe memory write",
                    "tool_calls": [
                        {
                            "tool": "remember",
                            "args": {"key": "model-plan", "value": "model planner worked"},
                            "reason": "operator asked for durable local state",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallValidationAdapter(BaseModelAdapter):
    provider = "fake-tool-call-validation"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model mixed valid and invalid tool calls",
                    "tool_calls": [
                        {"tool": "missing_tool", "args": {}, "reason": "unknown tool should be rejected before dispatch"},
                        {"tool": "remember", "args": {"key": "missing-value"}, "reason": "missing required value should be rejected before approval"},
                        {"tool": "list_tasks", "args": {"status": "pending", "limit": "2"}, "reason": "safe local status read"},
                        {
                            "tool": "run_command",
                            "args": {"target": "app.example.test", "purpose": "fake guarded dry run", "command": "printf should-not-run", "execute": True},
                            "reason": "command execution must be forced back to dry-run unless explicit execute=true is supplied",
                        },
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeWrappedJsonToolPlanAdapter(BaseModelAdapter):
    provider = "fake-wrapped-json-tool-plan"

    def __init__(self, marker: Path):
        self.marker = marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('wrapped-json-should-not-run', encoding='utf-8')\""
            plan = {
                "summary": "wrapped JSON model plan selected safe local memory and a dry-run command",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-wrapped-json", "value": "wrapped JSON model plan accepted"},
                        "reason": "prove fenced/surrounded JSON was parsed before registry validation",
                    },
                    {
                        "tool": "run_command",
                        "args": {"target": "app.example.test", "purpose": "wrapped JSON native plan dry-run", "command": command, "execute": True},
                        "reason": "execution-capable calls must still be coerced to dry-run without explicit execute=true",
                    },
                ],
                "warnings": [],
            }
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=(
                    'Planner preface with decoy braces {"note":"ignore","token":"wrapped-json-secret"}.\n'
                    "```json\n"
                    + json.dumps(plan, indent=2)
                    + "\n```\nTrailing provider prose with an unmatched brace {not-json"
                ),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeFailingToolPlanAdapter(BaseModelAdapter):
    provider = "fake-tool-call-primary-fails"

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        raise RuntimeError("primary native tool planner failed token=fallback-secret")

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        raise RuntimeError("generate() should not be used for fallback tool planning")


class FakeFallbackToolPlanAdapter(BaseModelAdapter):
    provider = "fake-tool-call-fallback"

    def __init__(self, marker: Path):
        self.marker = marker
        self.seen_tool_names: list[str] = []
        self.allow_seen: bool | None = None

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        self.allow_seen = allow_command_execution
        command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('fallback-should-not-run', encoding='utf-8')\""
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "fallback provider produced native tool-call plan",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "fallback-native", "value": "fallback chain selected native tool plan"},
                        "reason": "safe local memory proves fallback tool planning succeeded",
                    },
                    {
                        "tool": "run_command",
                        "args": {"target": "app.example.test", "purpose": "fallback native dry-run", "command": command, "execute": True},
                        "reason": "command execution still requires explicit operator execute=true after fallback planning",
                    },
                ],
                "warnings": [],
            }),
            raw={"model": "fake-fallback-tool-model", "native_tool_calls": True, "native_tool_call_count": 2, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response without tool plan")


class FakeNaturalAutoToolPlanAdapter(BaseModelAdapter):
    provider = "fake-natural-auto-tool-plan"

    def __init__(self, marker: Path):
        self.marker = marker
        self.allow_seen: bool | None = None
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.allow_seen = allow_command_execution
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('natural-auto-should-not-run', encoding='utf-8')\""
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "native planner handled a natural-language auto-execute message",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-natural-auto", "value": "natural native auto model plan ran"},
                        "reason": "safe local memory proves natural-message model planning used the registry boundary",
                    },
                    {
                        "tool": "run_command",
                        "args": {"target": "app.example.test", "purpose": "natural native auto dry-run", "command": command, "execute": True},
                        "reason": "natural-message command plans still require explicit slash execute=true and stay dry-run",
                    },
                ],
                "warnings": [],
            }),
            raw={"model": "fake-natural-auto-tool-plan", "native_tool_calls": True, "native_tool_call_count": 2, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallAllowedExecutionAdapter(BaseModelAdapter):
    provider = "fake-tool-call-allowed-execution"

    def __init__(self, marker: Path):
        self.marker = marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            command = f"python -c \"from pathlib import Path; Path({str(self.marker)!r}).write_text('native-allowed-executed', encoding='utf-8')\""
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model selected an allowed command that still needs explicit execution intent",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native allowed execution ledger proof",
                                "command": command,
                                "execute": True,
                                "timeout": "5",
                            },
                            "reason": "low-risk in-scope command should execute only when /auto execute=true is explicit",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallScannerExecutionAdapter(BaseModelAdapter):
    provider = "fake-tool-call-scanner-execution"

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model proposed a structured scanner wrapper with execute=true",
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
                            "reason": "scanner wrappers must obey the same explicit operator execute boundary as raw commands",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallGuardrailAdapter(BaseModelAdapter):
    provider = "fake-tool-call-guardrail"

    def __init__(self, confirm_marker: Path, block_marker: Path):
        self.confirm_marker = confirm_marker
        self.block_marker = block_marker

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "fake model proposed target-affecting calls that must stay guardrailed",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native guardrail confirm boundary",
                                "command": f"curl -X POST https://app.example.test/api/native-check && touch {self.confirm_marker}",
                                "execute": True,
                            },
                            "reason": "state-changing HTTP must queue approval instead of executing",
                        },
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "outside.example.test",
                                "purpose": "native guardrail block boundary",
                                "command": f"printf blocked-native > {self.block_marker}",
                                "execute": True,
                            },
                            "reason": "out-of-scope target must block instead of executing",
                        },
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallOperatorApprovalReplayAdapter(BaseModelAdapter):
    provider = "fake-tool-call-operator-approval-replay"

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
                    "summary": "fake model proposed a confirm-gated command that needs direct operator approval before execution",
                    "tool_calls": [
                        {
                            "tool": "run_command",
                            "args": {
                                "target": "app.example.test",
                                "purpose": "native operator approval replay boundary",
                                "command": command,
                                "execute": True,
                                "timeout": "5",
                            },
                            "reason": "state-changing-looking native plan must queue, then execute only after explicit /approve",
                        }
                    ],
                    "warnings": [],
                }),
            )
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallLoopApprovalStopAdapter(BaseModelAdapter):
    provider = "fake-tool-call-loop-approval-stop"

    def __init__(self, confirm_marker: Path):
        self.confirm_marker = confirm_marker
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if len(self.prompts) > 1:
            payload = {
                "summary": "unsafe continuation should not be requested after approval is queued",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "approval-stop-bypass", "value": "loop continued after approval"},
                        "reason": "this would prove the approval boundary was bypassed",
                    }
                ],
                "warnings": [],
            }
        else:
            payload = {
                "summary": "first step queues a confirm-level command",
                "tool_calls": [
                    {
                        "tool": "run_command",
                        "args": {
                            "target": "app.example.test",
                            "purpose": "native loop approval stop boundary",
                            "command": f"curl -X POST https://app.example.test/api/native-loop-stop && touch {self.confirm_marker}",
                            "execute": True,
                        },
                        "reason": "state-changing HTTP should queue approval and stop the native loop",
                    }
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class FakeToolCallFeedbackAdapter(BaseModelAdapter):
    provider = "fake-tool-call-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if "Stored memory" in prompt:
            payload = {"summary": "feedback loop complete", "tool_calls": [], "warnings": []}
        elif "Workspace file not found" in prompt:
            payload = {
                "summary": "recover from the tool error with a safe local memory write",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "feedback-recovered", "value": "model feedback loop recovered after tool error"},
                        "reason": "previous tool result was an error, so record the recovery marker",
                    }
                ],
                "warnings": [],
            }
        else:
            payload = {
                "summary": "first try a safe local read that will produce a recoverable tool error",
                "tool_calls": [
                    {
                        "tool": "workspace_read",
                        "args": {"path": "missing-feedback-fixture.txt"},
                        "reason": "safe local read used to exercise tool-result feedback",
                    }
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class FakeToolCallModelErrorAfterFeedbackAdapter(BaseModelAdapter):
    provider = "fake-tool-call-model-error-after-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            raise RuntimeError("native planner failed after feedback token=model-error-secret")
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "first step writes a local marker before the model fails on feedback",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-model-error-stop", "value": "native model error first step ran"},
                        "reason": "safe local marker proves the loop stops after a later model error without replaying tools",
                    }
                ],
                "warnings": [],
            }),
        )


class FakeToolCallInvalidAfterFeedbackAdapter(BaseModelAdapter):
    provider = "fake-tool-call-invalid-after-feedback"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            return ModelResponse(
                provider=self.provider,
                role=role,
                content=json.dumps({
                    "summary": "model proposed only invalid native tool calls after feedback",
                    "tool_calls": [
                        {"tool": "missing_tool", "args": {}, "reason": "unknown tools must not dispatch"},
                        {"tool": "remember", "args": {"key": "invalid-plan-withheld"}, "reason": "missing required value must be rejected before dispatch"},
                    ],
                    "warnings": ["token=invalid-plan-secret should be redacted from transcripts"],
                }),
            )
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "first step writes a local marker before invalid model plan stop",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-invalid-plan-stop", "value": "native invalid plan first step ran"},
                        "reason": "safe local marker proves the loop had feedback before invalid-plan stop",
                    }
                ],
                "warnings": [],
            }),
        )


class FakeToolCallTerminalNoToolAdapter(BaseModelAdapter):
    provider = "fake-tool-call-terminal-no-tool"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if "Previous Phobos tool results" in prompt:
            payload = {
                "summary": "model intentionally stopped after the successful native tool result",
                "tool_calls": [],
                "warnings": ["no further tool calls are needed"],
            }
        else:
            payload = {
                "summary": "first native step stores one local memory marker",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "terminal-stop-marker", "value": "model ran exactly once"},
                        "reason": "safe local memory proves the first native step ran",
                    }
                ],
                "warnings": [],
            }
        return ModelResponse(provider=self.provider, role=role, content=json.dumps(payload))


class FakeToolCallDuplicatePlanAdapter(BaseModelAdapter):
    provider = "fake-tool-call-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "fake model repeated the same native tool call",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "duplicate-loop-marker", "value": "native duplicate loop ran once"},
                        "reason": "repeated safe local call should stop the loop before re-dispatch",
                    }
                ],
                "warnings": [],
            }),
        )


class FakeToolCallPartialDuplicatePlanAdapter(BaseModelAdapter):
    provider = "fake-tool-call-partial-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        if len(self.prompts) == 1:
            calls = [
                {
                    "tool": "remember",
                    "args": {"key": "partial-duplicate-loop-marker", "value": "native partial duplicate loop ran once"},
                    "reason": "first safe local call should run exactly once",
                }
            ]
        else:
            calls = [
                {
                    "tool": "remember",
                    "args": {"key": "partial-duplicate-loop-marker", "value": "native partial duplicate loop ran once"},
                    "reason": "paraphrased duplicate should still be detected by tool args, not reason text",
                },
                {
                    "tool": "remember",
                    "args": {"key": "partial-duplicate-new-call", "value": "this call must be withheld with the duplicate batch"},
                    "reason": "a mixed duplicate+new batch must not partially dispatch after a repeat",
                },
            ]
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "fake model emitted a partial duplicate native tool batch",
                "tool_calls": calls,
                "warnings": [],
            }),
        )


class FakeToolCallSameStepDuplicatePlanAdapter(BaseModelAdapter):
    provider = "fake-tool-call-same-step-duplicate-plan"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        calls = [
            {
                "tool": "remember",
                "args": {"key": "same-step-duplicate-marker", "value": "this duplicate batch must not dispatch"},
                "reason": "first duplicate call in the same model batch",
            },
            {
                "tool": "remember",
                "args": {"key": "same-step-duplicate-marker", "value": "this duplicate batch must not dispatch"},
                "reason": "same tool and args in the same batch should stop before any dispatch",
            },
        ]
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "fake model emitted duplicate tool+args in one native batch",
                "tool_calls": calls,
                "warnings": [],
            }),
        )


class FakeToolCallMaxStepsAdapter(BaseModelAdapter):
    provider = "fake-tool-call-max-steps"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        step = len(self.prompts)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": f"fake model emitted bounded native step {step}",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": f"max-step-{step}", "value": f"native max-step budget ran step {step}"},
                        "reason": "unique safe local call keeps the loop progressing until the explicit max-step budget stops it",
                    }
                ],
                "warnings": [],
            }),
        )


class FakeToolCallApprovalActionAdapter(BaseModelAdapter):
    provider = "fake-tool-call-approval-action"

    def __init__(self):
        self.approval_id = 1
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "fake model attempted approval-control actions",
                "tool_calls": [
                    {"tool": "approve", "args": {"id": self.approval_id}, "reason": "model must not approve queued actions"},
                    {"tool": "deny", "args": {"id": self.approval_id, "reason": "model must not deny queued actions"}, "reason": "model must not deny queued actions"},
                ],
                "warnings": [],
            }),
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class FakeToolCallRuntimePolicyAdapter(BaseModelAdapter):
    provider = "fake-tool-call-runtime-policy"

    def __init__(self):
        self.prompts: list[str] = []

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        if "Return ONLY JSON" not in prompt:
            return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")
        self.prompts.append(prompt)
        return ModelResponse(
            provider=self.provider,
            role=role,
            content=json.dumps({
                "summary": "fake model proposed calls governed by runtime tool policy",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {"key": "native-policy-confirm", "value": "native runtime policy approval replayed"},
                        "reason": "confirm_tools must queue safe local tools until direct operator approval",
                    },
                    {
                        "tool": "workspace_read",
                        "args": {"path": "policy-blocked-fixture.txt"},
                        "reason": "blocked_tools must hard-block even harmless local reads",
                    },
                ],
                "warnings": [],
            }),
        )


class FakeToolPlanContextAdapter(BaseModelAdapter):
    provider = "fake-tool-plan-context"

    def __init__(self):
        self.contexts: list[str] = []
        self.seen_tool_names: list[str] = []

    def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
        self.contexts.append(context)
        self.seen_tool_names = [str(item.get("name")) for item in tool_specs]
        saw_runtime_context = "planning-context-marker" in context and "app.example.test" in context
        return ModelResponse(
            provider=self.provider,
            role="impact",
            content=json.dumps({
                "summary": "fake model used bounded runtime context for tool planning",
                "tool_calls": [
                    {
                        "tool": "remember",
                        "args": {
                            "key": "native-context-handoff",
                            "value": "model saw redacted runtime context" if saw_runtime_context else "model context missing",
                        },
                        "reason": "safe local memory proves planner context was delivered",
                    }
                ],
                "warnings": [],
            }),
            raw={"model": "fake-context-tool-model", "native_tool_calls": False, "native_tool_call_count": 0, "rejected_native_tool_call_count": 0},
        )

    def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
        return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")


class AgentRuntimeTests(unittest.TestCase):
    def make_runtime(self, tmp: str) -> tuple[OffSecAgentRuntime, Path]:
        tmp_path = Path(tmp)
        engagement = tmp_path / "engagement.json"
        EngagementROE(
            name="Runtime Test",
            authorized=True,
            in_scope_targets=["app.example.test", "10.10.0.0/24"],
            evidence_dir=str(tmp_path / "evidence"),
        ).save(engagement)
        runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(tmp_path / "agent.db"), session_name="unit"))
        return runtime, engagement

    def test_gateway_rejects_invalid_typed_query_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                gateway = AgentGateway(runtime, port=0, max_body_bytes=64)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
                    health = json.loads(response.read().decode("utf-8"))
                self.assertEqual(health.get("max_body_bytes"), 64)
                for route, expected_error in [
                    ("/task?id=not-an-int", "id must be an integer"),
                    ("/approval?approval_id=not-an-int", "id must be an integer"),
                    ("/media-detail?media_id=not-an-int", "id must be an integer"),
                    ("/timeline?include_audit=maybe", "include_audit must be a boolean"),
                    ("/manifest?include_agent=perhaps", "include_agent must be a boolean"),
                    ("/manifest-verify?detect_new=sometimes", "detect_new must be a boolean"),
                    ("/auto-transcript?max_ledger=not-an-int", "max_ledger must be an integer"),
                    ("/ref?kind=artifact&id=not-an-int", "id must be an integer"),
                    ("/ref?ref=artifact:agent/preflight/report.md&max_bytes=not-an-int", "max_bytes must be an integer"),
                ]:
                    with self.subTest(route=route):
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5)
                        self.assertEqual(raised.exception.code, 400)
                        payload = json.loads(raised.exception.read().decode("utf-8"))
                        self.assertEqual(payload.get("error"), expected_error)
                        self.assertNotIn("Traceback", json.dumps(payload))
                for route, body, expected_error in [
                    ("/approve", {"id": "not-an-int"}, "id must be an integer"),
                    ("/deny", {"approval_id": True}, "id must be an integer"),
                    ("/message", ["/status"], "JSON body must be an object"),
                ]:
                    with self.subTest(route=route, body=body):
                        req = urllib.request.Request(
                            f"http://{host}:{port}{route}",
                            data=json.dumps(body).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            urllib.request.urlopen(req, timeout=5)
                        self.assertEqual(raised.exception.code, 400)
                        payload = json.loads(raised.exception.read().decode("utf-8"))
                        self.assertEqual(payload.get("error"), expected_error)
                        self.assertNotIn("Traceback", json.dumps(payload))
                for route, body, expected_error in [
                    ("/message", b"{", "JSON body must be valid JSON"),
                    ("/message", b"\xff", "JSON body must be UTF-8"),
                ]:
                    with self.subTest(route=route, raw_body=body):
                        req = urllib.request.Request(
                            f"http://{host}:{port}{route}",
                            data=body,
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            urllib.request.urlopen(req, timeout=5)
                        self.assertEqual(raised.exception.code, 400)
                        payload = json.loads(raised.exception.read().decode("utf-8"))
                        self.assertEqual(payload.get("error"), expected_error)
                        self.assertNotIn("Traceback", json.dumps(payload))
                tool_req = urllib.request.Request(
                    f"http://{host}:{port}/tool",
                    data=json.dumps({"name": "list_findings", "args": {"limit": "not-an-int"}}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(tool_req, timeout=5) as response:
                    tool_payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(tool_payload["result"]["status"], "error")
                self.assertEqual(tool_payload["result"]["message"], "limit must be an integer.")
                self.assertNotIn("invalid literal", json.dumps(tool_payload))
                self.assertNotIn("Traceback", json.dumps(tool_payload))
                bool_tool_req = urllib.request.Request(
                    f"http://{host}:{port}/tool",
                    data=json.dumps({"name": "run_command", "args": {"execute": "maybe"}}, separators=(",", ":")).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(bool_tool_req, timeout=5) as response:
                    bool_tool_payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(bool_tool_payload["result"]["status"], "error")
                self.assertEqual(bool_tool_payload["result"]["message"], "execute must be a boolean.")
                self.assertNotIn("Traceback", json.dumps(bool_tool_payload))
                required_tool_req = urllib.request.Request(
                    f"http://{host}:{port}/tool",
                    data=json.dumps({"name": "workspace_write", "args": {"path": "notes/missing.md"}}, separators=(",", ":")).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(required_tool_req, timeout=5) as response:
                    required_tool_payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(required_tool_payload["result"]["status"], "error")
                self.assertEqual(required_tool_payload["result"]["message"], "content is required.")
                self.assertNotIn("Traceback", json.dumps(required_tool_payload))
                oversized_req = urllib.request.Request(
                    f"http://{host}:{port}/message",
                    data=json.dumps({"message": "x" * 128}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with mock.patch.object(runtime, "handle_message", side_effect=AssertionError("oversized request dispatched")):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(oversized_req, timeout=5)
                self.assertEqual(raised.exception.code, 413)
                payload = json.loads(raised.exception.read().decode("utf-8"))
                self.assertEqual(payload.get("error"), "JSON body too large; limit is 64 bytes")
                self.assertNotIn("Traceback", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_gateway_rejects_invalid_body_limit_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                for value, expected_error in [
                    (0, "max_body_bytes must be positive"),
                    (-1, "max_body_bytes must be positive"),
                    (True, "max_body_bytes must be an integer"),
                    ("not-an-int", "max_body_bytes must be an integer"),
                ]:
                    with self.subTest(value=value):
                        with self.assertRaisesRegex(ValueError, expected_error):
                            AgentGateway(runtime, port=0, max_body_bytes=value)
            finally:
                runtime.close()

    def test_config_scalar_parsing_does_not_enable_unsafe_booleans(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(name="Config Scalar Test", authorized=True, in_scope_targets=["app.example.test"], evidence_dir=str(tmp_path / "evidence")).save(engagement)
            cfg_path = tmp_path / "agent.config.json"
            cfg_path.write_text(json.dumps({
                "workspace_dir": str(tmp_path / "workspace"),
                "plugin_dirs": str(tmp_path / "plugins"),
                "max_context_messages": "7",
                "tool_timeout": "9",
                "auto_execute_natural": "false",
                "auto_model_planning": "off",
                "max_auto_steps": "3",
                "blocked_tools": "export_pack",
                "confirm_tools": ["workspace_write"],
                "skill_bundles": {"demo": "demo-skill"},
                "providers": {"provider": "heuristic", "model": "unit"},
                "bridges": {
                    "discord": {
                        "enabled": "true",
                        "allow_all": "false",
                        "allow_approval_actions": "0",
                        "ignore_bots": "yes",
                        "mention_required": "no",
                        "import_attachments": "on",
                        "max_attachment_bytes": "4096",
                        "max_response_chars": "240",
                        "max_message_chars": "500",
                        "poll_interval": "0.5",
                        "response_polish": "false",
                        "discord_thread_continue_without_trigger": "false",
                    }
                },
            }), encoding="utf-8")

            cfg = AgentAppConfig.load(cfg_path)
            self.assertFalse(cfg.auto_execute_natural)
            self.assertFalse(cfg.auto_model_planning)
            self.assertEqual(cfg.max_auto_steps, 3)
            self.assertEqual(cfg.max_context_messages, 7)
            self.assertEqual(cfg.tool_timeout, 9)
            self.assertEqual(cfg.plugin_dirs, [str(tmp_path / "plugins")])
            self.assertEqual(cfg.blocked_tools, ["export_pack"])
            self.assertEqual(cfg.skill_bundles, {"demo": ["demo-skill"]})
            bridge_cfg = BridgeConfig.from_dict("discord", cfg.bridges["discord"])
            self.assertTrue(bridge_cfg.enabled)
            self.assertFalse(bridge_cfg.allow_all)
            self.assertFalse(bridge_cfg.allow_approval_actions)
            self.assertTrue(bridge_cfg.ignore_bots)
            self.assertFalse(bridge_cfg.mention_required)
            self.assertTrue(bridge_cfg.import_attachments)
            self.assertEqual(bridge_cfg.max_attachment_bytes, 4096)
            self.assertEqual(bridge_cfg.max_response_chars, 240)
            self.assertEqual(bridge_cfg.max_message_chars, 500)
            self.assertEqual(bridge_cfg.poll_interval, 0.5)
            self.assertIs(bridge_cfg.extra.get("response_polish"), False)
            self.assertIs(bridge_cfg.extra.get("discord_thread_continue_without_trigger"), False)

            runtime = OffSecAgentRuntime(cfg.to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "config-scalar", config_path=str(cfg_path)))
            try:
                preflight = runtime.registry.run("safety_preflight", {})
                self.assertEqual(preflight.status, "ok", preflight.to_dict())
                serialized_preflight = json.dumps(preflight.to_dict())
                self.assertIn("auto_execute_natural=False", serialized_preflight)
                self.assertNotIn("allow_all=true", serialized_preflight)
            finally:
                runtime.close()

            bad_cfg = tmp_path / "bad.config.json"
            bad_cfg.write_text(json.dumps({"auto_execute_natural": "maybe"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "auto_execute_natural must be a boolean"):
                AgentAppConfig.load(bad_cfg)
            bad_bridge = tmp_path / "bad-bridge.config.json"
            bad_bridge.write_text(json.dumps({"bridges": {"discord": {"allow_all": "maybe"}}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bridges.discord.allow_all must be a boolean"):
                AgentAppConfig.load(bad_bridge)

            completed = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--config", str(bad_cfg), "--db", str(tmp_path / "bad.db"), "init", "--engagement", str(engagement),
            ], text=True, capture_output=True, check=False)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Invalid --config", completed.stderr or completed.stdout)
            self.assertNotIn("Traceback", completed.stderr + completed.stdout)

    def test_tool_registry_validates_schema_args_before_dispatch_or_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
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

                number_tool_spec = {
                    "description": "Unit-only JSON-schema number validation boundary.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "threshold": {"type": "number", "minimum": 0.1, "maximum": 10, "description": "Unit threshold."},
                            "label": {"type": "string", "description": "Optional label."},
                        },
                        "required": ["threshold"],
                        "additionalProperties": True,
                    },
                }
                collection_tool_spec = {
                    "description": "Unit-only JSON-schema array/object validation boundary.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {"type": "string", "pattern": r"^[a-z][a-z0-9_-]*$", "x-pattern-error": "must be lowercase safe item text"},
                                "description": "Ordered unit items.",
                            },
                            "options": {
                                "type": "object",
                                "properties": {
                                    "mode": {"type": "string", "enum": ["safe", "review"]},
                                    "retries": {"type": "integer", "minimum": 1, "maximum": 3},
                                },
                                "required": ["mode"],
                                "additionalProperties": False,
                                "description": "Structured unit options.",
                            },
                        },
                        "required": ["items"],
                        "additionalProperties": True,
                    },
                }
                size_tool_spec = {
                    "description": "Unit-only JSON-schema string/collection size-bound validation boundary.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "minLength": 3, "maxLength": 8, "description": "Bounded unit label."},
                            "items": {"type": "array", "minItems": 1, "maxItems": 2, "description": "Bounded unit items."},
                            "options": {"type": "object", "minProperties": 1, "maxProperties": 2, "description": "Bounded unit options."},
                        },
                        "required": ["label", "items", "options"],
                        "additionalProperties": True,
                    },
                }
                pattern_tool_spec = {
                    "description": "Unit-only JSON-schema string pattern validation boundary.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "label": {
                                "type": "string",
                                "pattern": r"^[A-Z][A-Z0-9_-]{2,7}$",
                                "x-pattern-error": "must be an uppercase safe label",
                                "description": "Pattern-bounded unit label.",
                            },
                        },
                        "required": ["label"],
                        "additionalProperties": True,
                    },
                }
                closed_tool_spec = {
                    "description": "Unit-only JSON-schema closed-object validation boundary.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "description": "Closed-schema unit label."},
                        },
                        "required": ["label"],
                        "additionalProperties": False,
                    },
                }

                runtime.registry.register_tool(
                    "schema_number_echo",
                    schema_number_echo,
                    number_tool_spec,
                )
                runtime.registry.register_tool(
                    "schema_collection_echo",
                    schema_collection_echo,
                    collection_tool_spec,
                )
                runtime.registry.register_tool(
                    "schema_size_echo",
                    schema_size_echo,
                    size_tool_spec,
                )
                runtime.registry.register_tool(
                    "schema_pattern_echo",
                    schema_pattern_echo,
                    pattern_tool_spec,
                )
                runtime.registry.register_tool(
                    "schema_closed_echo",
                    schema_closed_echo,
                    closed_tool_spec,
                )
                invalid_cases = [
                    ("get_job", {"id": "not-an-int"}, "id must be an integer."),
                    ("poll_process", {"id": "not-an-int"}, "id must be an integer."),
                    ("poll_process", {"id": "1.5"}, "id must be an integer."),
                    ("poll_process", {"id": ""}, "id is required."),
                    ("poll_process", {"id": 0}, "id must be at least 1."),
                    ("schema_number_echo", {"threshold": "not-a-number"}, "threshold must be a number."),
                    ("schema_number_echo", {"threshold": True}, "threshold must be a number."),
                    ("schema_number_echo", {"threshold": "nan"}, "threshold must be a number."),
                    ("schema_number_echo", {"threshold": "0.05"}, "threshold must be at least 0.1."),
                    ("schema_number_echo", {"threshold": 11}, "threshold must be at most 10."),
                    ("schema_number_echo", {"threshold": ""}, "threshold is required."),
                    ("schema_collection_echo", {"items": "not-an-array"}, "items must be an array."),
                    ("schema_collection_echo", {"items": [], "options": ["not-an-object"]}, "options must be an object."),
                    ("schema_collection_echo", {"items": ""}, "items is required."),
                    ("schema_collection_echo", {"items": ["alpha", 7], "options": {"mode": "safe"}}, "items[1] must be a string."),
                    ("schema_collection_echo", {"items": ["Bad Space"], "options": {"mode": "safe"}}, "items[0] must be lowercase safe item text."),
                    ("schema_collection_echo", {"items": ["alpha"], "options": {"mode": "unsafe"}}, "options.mode must be one of: safe, review."),
                    ("schema_collection_echo", {"items": ["alpha"], "options": {}}, "options.mode is required."),
                    ("schema_collection_echo", {"items": ["alpha"], "options": {"extra": True}}, "options.extra is not an allowed field."),
                    ("schema_collection_echo", {"items": ["alpha"], "options": {"mode": "safe", "retries": "bad"}}, "options.retries must be an integer."),
                    ("schema_collection_echo", {"items": ["alpha"], "options": {"mode": "safe", "retries": 4}}, "options.retries must be at most 3."),
                    ("schema_size_echo", {"label": "ab", "items": ["one"], "options": {"mode": "safe"}}, "label must be at least 3 characters."),
                    ("schema_size_echo", {"label": "too-long-label", "items": ["one"], "options": {"mode": "safe"}}, "label must be at most 8 characters."),
                    ("schema_size_echo", {"label": "okay", "items": [], "options": {"mode": "safe"}}, "items must contain at least 1 item."),
                    ("schema_size_echo", {"label": "okay", "items": ["one", "two", "three"], "options": {"mode": "safe"}}, "items must contain at most 2 items."),
                    ("schema_size_echo", {"label": "okay", "items": ["one"], "options": {}}, "options must contain at least 1 field."),
                    ("schema_size_echo", {"label": "okay", "items": ["one"], "options": {"a": 1, "b": 2, "c": 3}}, "options must contain at most 2 fields."),
                    ("schema_pattern_echo", {"label": "lower"}, "label must be an uppercase safe label."),
                    ("schema_pattern_echo", {"label": "BAD SPACE"}, "label must be an uppercase safe label."),
                    ("schema_pattern_echo", {"label": ""}, "label must be an uppercase safe label."),
                    ("sealed_export", {"passphrase_env": "bad env name"}, "passphrase_env must be an environment variable name."),
                    ("schema_closed_echo", {"label": "okay", "typo": "ignored?"}, "typo is not an allowed argument."),
                    ("schema_closed_echo", {"label": "okay", "alpha": 1, "zulu": 2}, "Unexpected arguments: alpha, zulu."),
                    ("list_findings", {"limit": "not-an-int"}, "limit must be an integer."),
                    ("list_findings", {"limit": 0}, "limit must be at least 1."),
                    ("list_findings", {"limit": 5001}, "limit must be at most 5000."),
                    ("evidence_timeline", {"limit": True}, "limit must be an integer."),
                    ("evidence_timeline", {"limit": 501}, "limit must be at most 500."),
                    ("evidence_manifest", {"max_bytes": 0}, "max_bytes must be at least 1."),
                    ("evidence_manifest", {"max_bytes": 500000001}, "max_bytes must be at most 500000000."),
                    ("evidence_secret_scan", {"max_bytes": 50000001}, "max_bytes must be at most 50000000."),
                    ("workspace_read", {"path": "notes/too-large.md", "limit": 1000001}, "limit must be at most 1000000."),
                    ("workspace_search", {"query": "unit", "limit": 1001}, "limit must be at most 1000."),
                    ("process_log", {"id": 1, "limit": 200001}, "limit must be at most 200000."),
                    ("wait_process", {"id": 1, "timeout": 301}, "timeout must be at most 300."),
                    ("run_command", {"timeout": 601}, "timeout must be at most 600."),
                    ("nmap_scan", {"target": "app.example.test", "timeout": 301}, "timeout must be at most 300."),
                    ("ffuf_scan", {"url": "https://app.example.test/FUZZ", "rate": 51}, "rate must be at most 50."),
                    ("run_command", {"execute": "maybe"}, "execute must be a boolean."),
                    ("workspace_write", {"path": ["notes/bad-string.md"], "content": "bad"}, "path must be a string."),
                    ("scope_check", {"target": {"host": "app.example.test"}}, "target must be a string."),
                    ("workspace_write", {"path": "notes/bad.md", "content": "bad", "append": "sometimes"}, "append must be a boolean."),
                    ("create_finding", {"title": "Bad enum finding", "status": "client-ready"}, "status must be one of: draft, needs-evidence, confirmed, resolved, accepted-risk, false-positive."),
                    ("evidence_timeline", {"order": "sideways"}, "order must be one of: desc, asc, newest, newest-first, oldest, oldest-first."),
                    ("media_import", {"path": str(Path(tmp) / "missing-media.txt"), "kind": "screenshot"}, "kind must be one of: image, audio, voice, video, file."),
                    ("nmap_scan", {"target": "app.example.test", "profile": "loud"}, "profile must be one of: safe, version, quick."),
                ]
                for tool_name, tool_args, expected_message in invalid_cases:
                    with self.subTest(tool=tool_name):
                        result = runtime.registry.run(tool_name, tool_args)
                        serialized = json.dumps(result.to_dict())
                        self.assertEqual(result.status, "error")
                        self.assertEqual(result.message, expected_message)
                        self.assertNotIn("invalid literal", serialized)
                        self.assertNotIn("Traceback", serialized)

                missing_required = runtime.registry.run("workspace_write", {"path": "notes/missing-required.md"})
                self.assertEqual(missing_required.status, "error")
                self.assertEqual(missing_required.message, "content is required.")
                self.assertFalse((runtime.registry.workspace_root / "notes" / "missing-required.md").exists())
                self.assertEqual(number_dispatches, [])
                self.assertEqual(collection_dispatches, [])

                valid_number = runtime.registry.run("schema_number_echo", {"threshold": "1.25", "label": "unit"})
                valid_collection = runtime.registry.run("schema_collection_echo", {"items": ["alpha", "beta"], "options": {"mode": "safe"}})
                valid_size = runtime.registry.run("schema_size_echo", {"label": "bounded", "items": ["alpha", "beta"], "options": {"mode": "safe", "phase": "unit"}})
                valid_pattern = runtime.registry.run("schema_pattern_echo", {"label": "ABC_12"})
                valid_closed = runtime.registry.run("schema_closed_echo", {"label": "closed", "_policy_approved": True})
                self.assertEqual(valid_number.status, "ok", valid_number.to_dict())
                self.assertEqual(valid_number.data["threshold"], 1.25)
                self.assertEqual(valid_number.data["threshold_type"], "float")
                self.assertEqual(number_dispatches, [{"threshold": 1.25, "label": "unit"}])
                self.assertEqual(valid_collection.status, "ok", valid_collection.to_dict())
                self.assertEqual(valid_collection.data["items"], ["alpha", "beta"])
                self.assertEqual(valid_collection.data["options"], {"mode": "safe"})
                self.assertEqual(collection_dispatches, [{"items": ["alpha", "beta"], "options": {"mode": "safe"}}])
                self.assertEqual(valid_size.status, "ok", valid_size.to_dict())
                self.assertEqual(valid_size.data["label"], "bounded")
                self.assertEqual(size_dispatches, [{"label": "bounded", "items": ["alpha", "beta"], "options": {"mode": "safe", "phase": "unit"}}])
                self.assertEqual(valid_pattern.status, "ok", valid_pattern.to_dict())
                self.assertEqual(valid_pattern.data["label"], "ABC_12")
                self.assertEqual(pattern_dispatches, [{"label": "ABC_12"}])
                self.assertEqual(valid_closed.status, "ok", valid_closed.to_dict())
                self.assertEqual(closed_dispatches, [{"label": "closed", "_policy_approved": True}])

                valid_limit = runtime.registry.run("list_findings", {"limit": "2"})
                valid_json_integer_number = runtime.registry.run("list_findings", {"limit": 2.0})
                self.assertEqual(valid_limit.status, "ok", valid_limit.to_dict())
                self.assertEqual(valid_json_integer_number.status, "ok", valid_json_integer_number.to_dict())
                dry_run = runtime.registry.run("run_command", {"target": "app.example.test", "type": "local", "purpose": "boolean dry-run regression", "command": "printf bool-validation-ok", "execute": "false"})
                self.assertEqual(dry_run.status, "dry_run", dry_run.to_dict())
                runtime.registry.run("workspace_write", {"path": "notes/boolean.md", "content": "old"})
                overwrite = runtime.registry.run("workspace_write", {"path": "notes/boolean.md", "content": "new", "append": "false"})
                append = runtime.registry.run("workspace_write", {"path": "notes/boolean.md", "content": "-tail", "append": "true"})
                self.assertEqual(overwrite.status, "ok", overwrite.to_dict())
                self.assertEqual(append.status, "ok", append.to_dict())
                self.assertEqual((runtime.registry.workspace_root / "notes" / "boolean.md").read_text(encoding="utf-8"), "new-tail")
                self.assertFalse((runtime.registry.workspace_root / "notes" / "bad.md").exists())

                valid_task = runtime.registry.run("add_task", {"content": "schema enum task", "status": "in-progress"})
                valid_finding = runtime.registry.run("create_finding", {"title": "Schema enum finding", "severity": "med", "status": "needs_evidence"})
                valid_filtered_findings = runtime.registry.run("list_findings", {"status": "needs_evidence"})
                valid_timeline = runtime.registry.run("evidence_timeline", {"order": "oldest-first", "limit": "5"})
                self.assertEqual(valid_task.status, "ok", valid_task.to_dict())
                self.assertEqual(valid_task.data["task"]["status"], "in_progress")
                self.assertEqual(valid_finding.status, "ok", valid_finding.to_dict())
                self.assertEqual(valid_finding.data["finding"]["severity"], "Medium")
                self.assertEqual(valid_finding.data["finding"]["status"], "needs-evidence")
                self.assertEqual(valid_filtered_findings.status, "ok", valid_filtered_findings.to_dict())
                self.assertTrue(any(item["title"] == "Schema enum finding" for item in valid_filtered_findings.data["findings"]))
                self.assertEqual(valid_timeline.status, "ok", valid_timeline.to_dict())

                confirm_runtime = OffSecAgentRuntime(
                    AgentRuntimeConfig(
                        engagement_path=str(engagement),
                        db_path=str(Path(tmp) / "confirm-agent.db"),
                        session_name="confirm-validation",
                        confirm_tools=("list_findings", "workspace_write", "add_task", "schema_number_echo", "schema_collection_echo", "schema_size_echo", "schema_pattern_echo", "schema_closed_echo"),
                    )
                )
                try:
                    confirm_runtime.registry.register_tool("schema_number_echo", schema_number_echo, number_tool_spec)
                    confirm_runtime.registry.register_tool("schema_collection_echo", schema_collection_echo, collection_tool_spec)
                    confirm_runtime.registry.register_tool("schema_size_echo", schema_size_echo, size_tool_spec)
                    confirm_runtime.registry.register_tool("schema_pattern_echo", schema_pattern_echo, pattern_tool_spec)
                    confirm_runtime.registry.register_tool("schema_closed_echo", schema_closed_echo, closed_tool_spec)
                    before = len(confirm_runtime.store.list_approvals(confirm_runtime.session_id, status="all"))
                    rejected = confirm_runtime.registry.run("list_findings", {"limit": "not-an-int"})
                    rejected_fractional_integer = confirm_runtime.registry.run("list_findings", {"limit": 1.5})
                    rejected_bound = confirm_runtime.registry.run("list_findings", {"limit": 0})
                    rejected_ceiling = confirm_runtime.registry.run("list_findings", {"limit": 5001})
                    rejected_number = confirm_runtime.registry.run("schema_number_echo", {"threshold": "nope"})
                    rejected_blank_required_scalar = confirm_runtime.registry.run("schema_number_echo", {"threshold": ""})
                    accepted_number = confirm_runtime.registry.run("schema_number_echo", {"threshold": "2.5"})
                    rejected_array = confirm_runtime.registry.run("schema_collection_echo", {"items": "queued-string"})
                    rejected_object = confirm_runtime.registry.run("schema_collection_echo", {"items": [], "options": "queued-string"})
                    rejected_nested_object = confirm_runtime.registry.run("schema_collection_echo", {"items": ["queued"], "options": {"mode": "unsafe"}})
                    accepted_collection = confirm_runtime.registry.run("schema_collection_echo", {"items": ["queued"], "options": {"mode": "safe"}})
                    rejected_size = confirm_runtime.registry.run("schema_size_echo", {"label": "ab", "items": ["queued"], "options": {"mode": "safe"}})
                    accepted_size = confirm_runtime.registry.run("schema_size_echo", {"label": "queued", "items": ["queued"], "options": {"mode": "safe"}})
                    rejected_pattern = confirm_runtime.registry.run("schema_pattern_echo", {"label": "queued"})
                    accepted_pattern = confirm_runtime.registry.run("schema_pattern_echo", {"label": "QUEUED"})
                    rejected_closed = confirm_runtime.registry.run("schema_closed_echo", {"label": "queued", "extra": "nope"})
                    accepted_closed = confirm_runtime.registry.run("schema_closed_echo", {"label": "queued"})
                    rejected_bool = confirm_runtime.registry.run("workspace_write", {"path": "notes/queued.md", "content": "nope", "append": "maybe"})
                    rejected_string = confirm_runtime.registry.run("workspace_write", {"path": {"bad": "queued.md"}, "content": "nope"})
                    rejected_required = confirm_runtime.registry.run("workspace_write", {"path": "notes/queued.md"})
                    rejected_enum = confirm_runtime.registry.run("add_task", {"content": "queued enum task", "status": "sideways"})
                    after = len(confirm_runtime.store.list_approvals(confirm_runtime.session_id, status="all"))
                    self.assertEqual(rejected.status, "error")
                    self.assertEqual(rejected.message, "limit must be an integer.")
                    self.assertEqual(rejected_fractional_integer.status, "error")
                    self.assertEqual(rejected_fractional_integer.message, "limit must be an integer.")
                    self.assertEqual(rejected_bound.status, "error")
                    self.assertEqual(rejected_bound.message, "limit must be at least 1.")
                    self.assertEqual(rejected_ceiling.status, "error")
                    self.assertEqual(rejected_ceiling.message, "limit must be at most 5000.")
                    self.assertEqual(rejected_number.status, "error")
                    self.assertEqual(rejected_number.message, "threshold must be a number.")
                    self.assertEqual(rejected_blank_required_scalar.status, "error")
                    self.assertEqual(rejected_blank_required_scalar.message, "threshold is required.")
                    self.assertEqual(accepted_number.status, "needs_approval", accepted_number.to_dict())
                    self.assertEqual(accepted_number.data.get("tool"), "schema_number_echo")
                    self.assertEqual(rejected_array.status, "error")
                    self.assertEqual(rejected_array.message, "items must be an array.")
                    self.assertEqual(rejected_object.status, "error")
                    self.assertEqual(rejected_object.message, "options must be an object.")
                    self.assertEqual(rejected_nested_object.status, "error")
                    self.assertEqual(rejected_nested_object.message, "options.mode must be one of: safe, review.")
                    self.assertEqual(accepted_collection.status, "needs_approval", accepted_collection.to_dict())
                    self.assertEqual(accepted_collection.data.get("tool"), "schema_collection_echo")
                    self.assertEqual(rejected_size.status, "error")
                    self.assertEqual(rejected_size.message, "label must be at least 3 characters.")
                    self.assertEqual(accepted_size.status, "needs_approval", accepted_size.to_dict())
                    self.assertEqual(accepted_size.data.get("tool"), "schema_size_echo")
                    self.assertEqual(rejected_pattern.status, "error")
                    self.assertEqual(rejected_pattern.message, "label must be an uppercase safe label.")
                    self.assertEqual(accepted_pattern.status, "needs_approval", accepted_pattern.to_dict())
                    self.assertEqual(accepted_pattern.data.get("tool"), "schema_pattern_echo")
                    self.assertEqual(rejected_closed.status, "error")
                    self.assertEqual(rejected_closed.message, "extra is not an allowed argument.")
                    self.assertEqual(accepted_closed.status, "needs_approval", accepted_closed.to_dict())
                    self.assertEqual(accepted_closed.data.get("tool"), "schema_closed_echo")
                    self.assertEqual(rejected_bool.status, "error")
                    self.assertEqual(rejected_bool.message, "append must be a boolean.")
                    self.assertEqual(rejected_string.status, "error")
                    self.assertEqual(rejected_string.message, "path must be a string.")
                    self.assertEqual(rejected_required.status, "error")
                    self.assertEqual(rejected_required.message, "content is required.")
                    self.assertEqual(rejected_enum.status, "error")
                    self.assertEqual(rejected_enum.message, "status must be one of: pending, in_progress, completed, cancelled.")
                    self.assertEqual(after, before + 5)
                finally:
                    confirm_runtime.close()
            finally:
                runtime.close()

    def test_scope_check_is_read_only_redacted_and_gateway_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                summary = runtime.registry.run("scope_check", {})
                self.assertEqual(summary.status, "ok", summary.to_dict())
                self.assertTrue(summary.data["no_target_activity"])
                self.assertEqual(summary.data["scope_status"], "ready")

                in_scope = runtime.registry.run("scope_check", {"target": "https://app.example.test/login?token=supersecret"})
                out_scope = runtime.registry.run("scope_check", {"target": "outside.example.test"})
                self.assertEqual(in_scope.status, "ok", in_scope.to_dict())
                self.assertEqual(in_scope.data["target_check"]["decision"], "allow")
                self.assertTrue(in_scope.data["target_check"]["in_scope"])
                self.assertEqual(out_scope.data["target_check"]["decision"], "block")
                self.assertFalse(out_scope.data["target_check"]["in_scope"])

                slash = runtime.handle_message('/scope target="https://app.example.test/login?token=supersecret"')
                schema = runtime.handle_message("/schemas name=scope_check")
                auto = runtime.handle_message('/auto apply=true prompt="is app.example.test in scope?"')
                self.assertIn("scope_check", schema)
                self.assertIn('"decision": "allow"', slash)
                self.assertIn('"tool": "scope_check"', auto)
                self.assertNotIn("supersecret", json.dumps({"summary": summary.to_dict(), "in_scope": in_scope.to_dict(), "out_scope": out_scope.to_dict()}) + slash + schema + auto)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                encoded = urllib.parse.urlencode({"target": "app.example.test"})
                with urllib.request.urlopen(f"http://{host}:{port}/scope-check?{encoded}", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["target_check"]["decision"], "allow")

                raw_audit = "\n".join(row[0] or "" for row in runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE event IN ('tool_call', 'tool_result')").fetchall())
                self.assertNotIn("supersecret", raw_audit)
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_safety_preflight_reports_readiness_without_target_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            gateway = None
            try:
                preflight = runtime.registry.run("safety_preflight", {"out": "unit-preflight"})
                self.assertEqual(preflight.status, "ok", preflight.to_dict())
                self.assertEqual(preflight.data["readiness"], "ready")
                self.assertTrue(preflight.data["no_target_activity"])
                self.assertTrue(preflight.data["secret_values_redacted"])
                markdown_path = Path(preflight.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Safety Preflight", markdown)
                self.assertIn("Local SQLite/WAL/SHM remain plaintext", markdown)

                slash = runtime.handle_message("/preflight out=slash-preflight.md")
                self.assertIn("Safety preflight ready", slash)
                self.assertIn("safety_preflight", runtime.handle_message("/schemas name=safety_preflight"))

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/preflight", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["readiness"], "ready")
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

            unsafe_engagement = Path(tmp) / "unsafe-engagement.json"
            EngagementROE(
                name="Unsafe Readiness",
                authorized=False,
                in_scope_targets=["0.0.0.0/0"],
                prohibited_techniques=[],
                stop_conditions=[],
                evidence_dir=str(Path(tmp) / "unsafe-evidence"),
            ).save(unsafe_engagement)
            old_token = os.environ.get("PHOBOS_PREFLIGHT_TOKEN")
            os.environ["PHOBOS_PREFLIGHT_TOKEN"] = "token=supersecret"
            unsafe_runtime = OffSecAgentRuntime(AgentRuntimeConfig(
                engagement_path=str(unsafe_engagement),
                db_path=str(Path(tmp) / "unsafe-agent.db"),
                session_name="unsafe",
                auto_execute_natural=True,
                bridges={"discord": {"enabled": True, "token_env": "PHOBOS_PREFLIGHT_TOKEN", "allow_all": True, "allow_approval_actions": True, "ignore_bots": False}},
            ))
            try:
                unsafe = unsafe_runtime.registry.run("safety_preflight", {})
                self.assertEqual(unsafe.status, "ok", unsafe.to_dict())
                self.assertEqual(unsafe.data["readiness"], "blocked")
                statuses = {check["status"] for check in unsafe.data["checks"]}
                self.assertIn("fail", statuses)
                self.assertIn("warn", statuses)
                serialized = json.dumps(unsafe.to_dict()) + Path(unsafe.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertNotIn("supersecret", serialized)
            finally:
                unsafe_runtime.close()
                if old_token is None:
                    os.environ.pop("PHOBOS_PREFLIGHT_TOKEN", None)
                else:
                    os.environ["PHOBOS_PREFLIGHT_TOKEN"] = old_token

    def test_guardrail_selftest_is_read_only_redacted_and_gateway_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                selftest = runtime.registry.run("guardrail_selftest", {"target": "https://app.example.test/login?token=supersecret", "out": "unit-selftest"})
                self.assertEqual(selftest.status, "ok", selftest.to_dict())
                self.assertEqual(selftest.data["readiness"], "ready", selftest.to_dict())
                self.assertTrue(selftest.data["no_target_activity"])
                self.assertFalse(selftest.data["executed"])
                cases = {case["name"]: case for case in selftest.data["cases"]}
                self.assertEqual(cases["read_only_headers"]["actual"], "allow")
                self.assertEqual(cases["routine_active_enumeration"]["actual"], "allow")
                self.assertEqual(cases["state_changing_http"]["actual"], "confirm")
                self.assertEqual(cases["lockout_sensitive_auth"]["actual"], "confirm")
                self.assertEqual(cases["availability_impacting_pattern"]["actual"], "block")
                self.assertEqual(cases["out_of_scope_target"]["actual"], "block")
                markdown = Path(selftest.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Phobos Guardrail Self-Test", markdown)
                self.assertIn("No target activity was performed", markdown)
                self.assertNotIn("supersecret", json.dumps(selftest.to_dict()) + markdown)

                runtime.roe.safety_mode = "standard"
                standard = runtime.registry.run("guardrail_selftest", {})
                standard_cases = {case["name"]: case for case in standard.data["cases"]}
                self.assertEqual(standard.data["readiness"], "ready", standard.to_dict())
                self.assertEqual(standard_cases["routine_active_enumeration"]["actual"], "confirm")
                runtime.roe.safety_mode = "non_destructive"

                slash = runtime.handle_message('/guardrail-test target="https://app.example.test/login?token=supersecret"')
                schema = runtime.handle_message("/schemas name=guardrail_selftest")
                auto = runtime.handle_message('/auto apply=true prompt="run guardrail self-test target=app.example.test"')
                self.assertIn("Guardrail self-test ready", slash)
                self.assertIn("guardrail_selftest", schema)
                self.assertIn('"tool": "guardrail_selftest"', auto)
                self.assertNotIn("supersecret", slash + schema + auto)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                encoded = urllib.parse.urlencode({"target": "app.example.test"})
                with urllib.request.urlopen(f"http://{host}:{port}/guardrail-test?{encoded}", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertEqual(payload["data"]["readiness"], "ready")

                raw_audit = "\n".join(row[0] or "" for row in runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE event IN ('tool_call', 'tool_result', 'guardrail_selftest')").fetchall())
                self.assertNotIn("supersecret", raw_audit)
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_memory_assess_run_approval_jobs_and_subagents(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                remembered = runtime.handle_message('/remember key=client value="ACME test engagement" tags=engagement')
                self.assertIn("Stored memory", remembered)
                recalled = runtime.handle_message('/recall query=ACME')
                self.assertIn("ACME test engagement", recalled)
                hygiene = runtime.registry.run("remember", {"key": "temporary-forget", "value": "Delete me after review token=forgot-secret", "tags": "hygiene"})
                self.assertEqual(hygiene.status, "ok", hygiene.to_dict())
                memory_id = hygiene.data["id"]
                listed_memory = runtime.handle_message('/memories query=temporary-forget')
                memory_detail = runtime.handle_message(f'/memory id={memory_id}')
                self.assertIn("temporary-forget", listed_memory + memory_detail)
                self.assertNotIn("forgot-secret", listed_memory + memory_detail)
                forgotten = runtime.handle_message('/forget key=temporary-forget')
                self.assertIn("Deleted memory", forgotten)
                self.assertIsNone(runtime.store.get_memory(memory_id=memory_id))
                self.assertNotIn("Delete me after review", runtime.handle_message('/recall query="Delete me after review"'))
                runtime.handle_message('/remember key=auto-forget value="Auto-removable memory" tags=hygiene')
                auto_forget = runtime.handle_message('/auto apply=true prompt="forget memory auto-forget"')
                self.assertIn('"tool": "forget_memory"', auto_forget)
                self.assertIsNone(runtime.store.get_memory(key="auto-forget"))

                assessed = runtime.handle_message('/assess target=app.example.test type=web purpose="headers" command="curl -I https://app.example.test"')
                self.assertIn("Guardrail decision: allow", assessed)

                executed = runtime.handle_message('/run target=app.example.test type=host purpose="local smoke" command="printf agent-ok" execute=true')
                self.assertIn("[executed]", executed)
                self.assertIn("agent-ok", executed)

                confirm = runtime.handle_message('/run target=app.example.test type=web purpose="controlled test update token=supersecret" command="curl -X POST https://app.example.test/profile token=supersecret" execute=true')
                self.assertIn("needs_approval", confirm)
                approvals = runtime.handle_message('/approvals')
                approval_detail = runtime.handle_message('/approval id=1')
                self.assertIn("controlled test update", approvals)
                self.assertIn("token=<REDACTED>", approvals)
                self.assertIn("token=<REDACTED>", approval_detail)
                self.assertNotIn("supersecret", approvals + approval_detail)
                self.assertIsNotNone(runtime.store.get_approval(1, session_id=runtime.session_id))
                raw_approval = runtime.store.conn.execute("SELECT args_json, decision_json FROM approvals WHERE id=1").fetchone()
                raw_approval_text = (raw_approval["args_json"] or "") + (raw_approval["decision_json"] or "")
                self.assertIn("token=<REDACTED>", raw_approval_text)
                self.assertNotIn("supersecret", raw_approval_text)
                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="other"))
                try:
                    self.assertIsNone(runtime.store.get_approval(1, session_id=other_runtime.session_id))
                    self.assertFalse(runtime.store.resolve_approval(1, "denied", "other", {"reason": "foreign session"}, session_id=other_runtime.session_id))
                    owned_approval = runtime.store.get_approval(1, session_id=runtime.session_id)
                    self.assertIsNotNone(owned_approval)
                    self.assertEqual((owned_approval or {}).get("status"), "pending")
                    cross_session = other_runtime.handle_message('/approval id=1')
                    cross_approve = other_runtime.handle_message('/approve id=1')
                    self.assertIn("not found in this session", cross_session)
                    self.assertIn("not found in this session", cross_approve)
                finally:
                    other_runtime.close()
                denied = runtime.handle_message('/deny id=1 reason="unit test token=supersecret"')
                self.assertIn("denied", denied)
                all_approvals = runtime.handle_message('/approvals status=all')
                self.assertIn("denied", all_approvals)
                self.assertNotIn("supersecret", all_approvals)
                raw_denied = runtime.store.conn.execute("SELECT result_json FROM approvals WHERE id=1").fetchone()["result_json"]
                self.assertIn("token=<REDACTED>", raw_denied)
                self.assertNotIn("supersecret", raw_denied)

                replay_probe = runtime.handle_message('/run target=app.example.test type=web purpose="controlled replay token=replaysecret" command="curl -X POST https://app.example.test/profile token=replaysecret" execute=true')
                self.assertIn("needs_approval", replay_probe)
                replay_id = max(row["id"] for row in runtime.store.list_approvals(runtime.session_id, status="pending"))
                blocked_replay = runtime.handle_message(f"/approve id={replay_id}")
                self.assertIn("cannot be replayed safely", blocked_replay)
                replay_row = runtime.store.conn.execute("SELECT args_json, result_json, status FROM approvals WHERE id=?", (replay_id,)).fetchone()
                replay_text = "".join(str(replay_row[key] or "") for key in ("args_json", "result_json", "status"))
                self.assertIn("blocked_redacted_args", replay_text)
                self.assertNotIn("replaysecret", replay_text)

                job = runtime.handle_message('/job name=daily schedule=manual prompt="/recall query=ACME"')
                self.assertIn("Scheduled job", job)
                due = runtime.run_due_jobs()
                self.assertEqual(len(due), 1)
                self.assertIn("ACME", due[0]["response"])

                review = runtime.handle_message('/subagents prompt="Review controlled IDOR evidence" roles=scope,safety,report')
                self.assertIn("Subagent review complete", review)
            finally:
                runtime.close()

    def test_job_controls_are_session_bound_redacted_and_disable_due_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                runtime.handle_message('/remember key=job-marker value="ACME scheduled job marker" tags=engagement')
                scheduled = runtime.registry.run("schedule_job", {"name": "daily", "schedule": "manual", "prompt": "/recall query=job-marker"})
                job_id = int(scheduled.data["job_id"])
                due = runtime.run_due_jobs()
                self.assertEqual(len(due), 1)
                self.assertEqual(due[0]["job_id"], job_id)
                self.assertIn("ACME scheduled job marker", due[0]["response"])

                detail = runtime.registry.run("get_job", {"id": job_id})
                self.assertEqual(detail.status, "ok", detail.to_dict())
                self.assertIn("last_result", detail.data["job"])
                updated = runtime.registry.run(
                    "update_job",
                    {"id": job_id, "name": "daily token=supersecret", "prompt": "/recall query=job-marker token=supersecret", "enabled": False},
                )
                disabled_due = runtime.run_due_jobs()
                listed = runtime.registry.run("list_jobs", {})
                serialized = json.dumps({"updated": updated.to_dict(), "listed": listed.to_dict()})
                self.assertEqual(updated.status, "ok", updated.to_dict())
                self.assertFalse(updated.data["job"]["enabled"])
                self.assertEqual(disabled_due, [])
                self.assertIn("token=<REDACTED>", serialized)
                self.assertNotIn("supersecret", serialized)
                self.assertTrue(listed.data["secret_values_redacted"])

                reenabled = runtime.registry.run("enable_job", {"id": job_id})
                disabled = runtime.registry.run("disable_job", {"id": job_id})
                self.assertTrue(reenabled.data["job"]["enabled"])
                self.assertFalse(disabled.data["job"]["enabled"])

                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="job-other"))
                try:
                    other_job = other_runtime.registry.run("schedule_job", {"name": "other token=supersecret", "schedule": "manual", "prompt": "/status token=supersecret"})
                    other_job_id = int(other_job.data["job_id"])
                    cross_detail = runtime.registry.run("get_job", {"id": other_job_id})
                    cross_disable = runtime.registry.run("disable_job", {"id": other_job_id})
                    owner_detail = other_runtime.registry.run("get_job", {"id": other_job_id})
                    cross_blob = json.dumps({"detail": cross_detail.to_dict(), "disable": cross_disable.to_dict()})
                    self.assertEqual(cross_detail.status, "error")
                    self.assertEqual(cross_disable.status, "error")
                    self.assertIn("not found in this session", cross_blob)
                    self.assertNotIn("supersecret", cross_blob)
                    self.assertTrue(owner_detail.data["job"]["enabled"])
                finally:
                    other_runtime.close()
            finally:
                runtime.close()

    def test_natural_language_fallback_records_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                response = runtime.handle_message("What is the safest next step for a controlled IDOR?")
                self.assertNotIn("Phobos Agent response", response)
                self.assertIn("pentest assistant", response)
                execution_request = runtime.handle_message("Run nmap against app.example.test")
                self.assertIn("I didn’t run anything", execution_request)
                messages = runtime.store.recent_messages(runtime.session_id, limit=10)
                self.assertEqual(messages[-1]["role"], "assistant")
            finally:
                runtime.close()

    def test_workspace_context_process_and_audit_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                written = runtime.handle_message('/write path=notes/finding.md content="client authz note"')
                self.assertIn("Wrote notes/finding.md", written)
                read = runtime.handle_message('/read path=notes/finding.md')
                self.assertIn("client authz note", read)
                searched = runtime.handle_message('/workspace-search query=authz glob="**/*.md"')
                self.assertIn("finding.md", searched)
                patched = runtime.handle_message('/patch-file path=notes/finding.md old=authz new=authorization')
                self.assertIn("Patched notes/finding.md", patched)

                compact = runtime.handle_message('/compact limit=20')
                self.assertIn("Context summary", compact)
                context = runtime.handle_message('/context limit=4')
                self.assertIn("Context snapshot", context)

                started = runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "background smoke",
                    "command": "printf bg-ok",
                    "execute": True,
                })
                self.assertEqual(started.status, "started", started.message)
                process_id = started.data["process_id"]
                for _ in range(20):
                    polled = runtime.registry.run("poll_process", {"id": process_id})
                    if polled.status in {"completed", "failed"}:
                        break
                    time.sleep(0.05)
                self.assertEqual(polled.status, "completed", polled.to_dict())
                log = runtime.registry.run("process_log", {"id": process_id})
                self.assertIn("bg-ok", log.data["stdout"])
                processes = runtime.handle_message('/processes')
                self.assertIn("background smoke", processes)
                runtime.store.audit(
                    runtime.session_id,
                    "secret_audit_probe",
                    {
                        "token": "token=leaky-audit-token",
                        "api_key": "leaky-audit-key-only",
                        "client_secret": "leaky-client-secret",
                        "aws_secret_access_key": "leaky-aws-secret",
                        "private_key": "-----BEGIN PRIVATE KEY-----\nleaky-private-key\n-----END PRIVATE KEY-----",
                        "nested": {"auth": "Authorization: Bearer leaky-audit-bearer", "session_token": "leaky-session-token"},
                        "items": ["password=hunter2"],
                    },
                )
                audit_id = runtime.store.conn.execute("SELECT id FROM audit_log WHERE event='secret_audit_probe'").fetchone()[0]
                audit = runtime.handle_message('/audit limit=20')
                audit_detail = runtime.handle_message(f"/audit-detail id={audit_id}")
                audit_ref = runtime.registry.run("resolve_local_ref", {"ref": f"audit:{audit_id}"})
                self.assertIn("tool_call", audit)
                self.assertIn("secret_audit_probe", audit)
                self.assertIn("Audit entry", audit_detail)
                self.assertEqual(audit_ref.status, "ok", audit_ref.to_dict())
                self.assertTrue(audit_ref.data["no_target_activity"])
                self.assertEqual(audit_ref.data["entity"]["audit"]["id"], audit_id)
                self.assertNotIn("leaky-audit-token", audit)
                self.assertNotIn("leaky-audit-key-only", audit)
                self.assertNotIn("leaky-client-secret", audit)
                self.assertNotIn("leaky-aws-secret", audit)
                self.assertNotIn("leaky-private-key", audit)
                self.assertNotIn("leaky-session-token", audit)
                self.assertNotIn("leaky-audit-bearer", audit)
                self.assertNotIn("hunter2", audit)
                self.assertNotIn("leaky-audit-token", audit_detail + json.dumps(audit_ref.to_dict()))
                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="foreign-audit"))
                try:
                    foreign_audit_id = other_runtime.store.audit(other_runtime.session_id, "foreign_audit_probe", {"token": "foreign-audit-secret"})
                    self.assertIsNone(runtime.store.get_audit(foreign_audit_id, session_id=runtime.session_id))
                    cross_detail = runtime.registry.run("get_audit", {"id": foreign_audit_id})
                    cross_ref = runtime.registry.run("resolve_local_ref", {"ref": f"audit:{foreign_audit_id}"})
                    owner_detail = other_runtime.registry.run("get_audit", {"id": foreign_audit_id})
                    self.assertEqual(cross_detail.status, "error")
                    self.assertEqual(cross_ref.status, "error")
                    self.assertIn("not found in this session", cross_detail.message)
                    self.assertEqual(owner_detail.status, "ok")
                    self.assertNotIn("foreign-audit-secret", json.dumps({"cross": cross_detail.to_dict(), "ref": cross_ref.to_dict(), "owner": owner_detail.to_dict()}))
                finally:
                    other_runtime.close()
                raw_audit = runtime.store.conn.execute("SELECT data_json FROM audit_log WHERE event='secret_audit_probe'").fetchone()[0]
                self.assertNotIn("leaky-audit-token", raw_audit)
                self.assertNotIn("leaky-audit-key-only", raw_audit)
                self.assertNotIn("leaky-client-secret", raw_audit)
                self.assertNotIn("leaky-aws-secret", raw_audit)
                self.assertNotIn("leaky-private-key", raw_audit)
                self.assertNotIn("leaky-session-token", raw_audit)
                self.assertNotIn("leaky-audit-bearer", raw_audit)
                self.assertNotIn("hunter2", raw_audit)
            finally:
                runtime.close()

    def test_session_memory_context_and_media_storage_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                message_id = runtime.store.append_message(
                    runtime.session_id,
                    "user",
                    "operator note token=message-supersecret",
                    {"api_key": "message-metadata-key", "nested": ["Cookie: sid=message-cookie"]},
                )
                memory = runtime.registry.run(
                    "remember",
                    {
                        "key": "client-token=memory-supersecret",
                        "value": "Authorization: Bearer memory-bearer-secret",
                        "tags": "api_key=memory-tag-secret",
                    },
                )
                self.assertEqual(memory.status, "ok", memory.to_dict())
                self.assertNotIn("memory-supersecret", json.dumps(memory.to_dict()))
                summary_id = runtime.store.create_context_summary(
                    runtime.session_id,
                    message_id,
                    message_id,
                    "context summary password=context-summary-secret",
                )
                node_id = runtime.store.create_context_node(
                    runtime.session_id,
                    "node title token=node-title-secret",
                    "node summary client_secret=node-summary-secret",
                    sources=[{"type": "message", "id": message_id, "note": "token=node-source-secret"}],
                    metadata={"client_secret": "node-metadata-secret"},
                )
                media_src = Path(tmp) / "proof-token=media-name-secret.txt"
                media_src.write_text("media content token=media-content-secret", encoding="utf-8")
                media = runtime.registry.run("media_import", {"path": str(media_src)})
                self.assertEqual(media.status, "ok", media.to_dict())
                self.assertNotIn("media-name-secret", json.dumps(media.to_dict()) + json.dumps(media.artifacts))
                self.assertNotIn("media-content-secret", json.dumps(media.to_dict()))

                raw_message = runtime.store.conn.execute("SELECT content, metadata_json FROM messages WHERE id=?", (message_id,)).fetchone()
                raw_memory = runtime.store.conn.execute("SELECT key, value, tags FROM memories").fetchall()
                raw_summary = runtime.store.conn.execute("SELECT summary FROM context_summaries WHERE id=?", (summary_id,)).fetchone()
                raw_node = runtime.store.conn.execute("SELECT title, summary, source_json, metadata_json FROM context_nodes WHERE id=?", (node_id,)).fetchone()
                raw_media = runtime.store.conn.execute("SELECT source_path, artifact_path, metadata_json FROM media_artifacts").fetchone()
                raw_blob = json.dumps({
                    "message": dict(raw_message),
                    "memories": [dict(row) for row in raw_memory],
                    "summary": dict(raw_summary),
                    "node": dict(raw_node),
                    "media": dict(raw_media),
                }, sort_keys=True)
                for leaked in [
                    "message-supersecret",
                    "message-metadata-key",
                    "message-cookie",
                    "memory-supersecret",
                    "memory-bearer-secret",
                    "memory-tag-secret",
                    "context-summary-secret",
                    "node-title-secret",
                    "node-summary-secret",
                    "node-source-secret",
                    "node-metadata-secret",
                    "media-name-secret",
                ]:
                    self.assertNotIn(leaked, raw_blob)
                self.assertIn("<REDACTED>", raw_blob)

                read_blob = json.dumps({
                    "message": runtime.store.get_message(message_id, session_id=runtime.session_id),
                    "recall": runtime.registry.run("recall", {"query": "client-token"}).to_dict(),
                    "context": runtime.registry.run("context_expand", {"id": node_id}).to_dict(),
                    "media": runtime.registry.run("media_get", {"id": media.data["media"]["id"]}).to_dict(),
                }, sort_keys=True)
                for leaked in ["message-supersecret", "memory-bearer-secret", "node-source-secret", "media-name-secret"]:
                    self.assertNotIn(leaked, read_blob)
                self.assertIn("<REDACTED>", read_blob)
            finally:
                runtime.close()

    def test_task_and_process_ids_are_session_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            other_runtime = None
            try:
                own_task = runtime.registry.run("add_task", {"content": "own task token=supersecret"})
                self.assertEqual(own_task.status, "ok", own_task.to_dict())
                self.assertIn("token=<REDACTED>", json.dumps(own_task.to_dict()))
                self.assertNotIn("supersecret", json.dumps(own_task.to_dict()))
                own_task_id = int(own_task.data["task"]["id"])
                own_task_detail = runtime.registry.run("get_task", {"id": own_task_id})
                self.assertEqual(own_task_detail.status, "ok", own_task_detail.to_dict())
                self.assertIn("token=<REDACTED>", json.dumps(own_task_detail.to_dict()))
                raw_task = runtime.store.conn.execute("SELECT content, metadata_json FROM tasks WHERE id=?", (own_task_id,)).fetchone()
                raw_task_text = (raw_task["content"] or "") + (raw_task["metadata_json"] or "")
                self.assertIn("token=<REDACTED>", raw_task_text)
                self.assertNotIn("supersecret", raw_task_text)
                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(
                    engagement_path=runtime.config.engagement_path,
                    db_path=runtime.config.db_path,
                    session_name="other-session-scope",
                ))
                other_task = other_runtime.registry.run("add_task", {"content": "other task", "status": "pending"})
                self.assertEqual(other_task.status, "ok", other_task.to_dict())
                other_task_id = int(other_task.data["task"]["id"])
                cross_task = runtime.registry.run("update_task", {"id": other_task_id, "status": "completed"})
                cross_task_detail = runtime.registry.run("get_task", {"id": other_task_id})
                self.assertEqual(cross_task.status, "error", cross_task.to_dict())
                self.assertEqual(cross_task_detail.status, "error", cross_task_detail.to_dict())
                self.assertIn("not found in this session", cross_task.message)
                self.assertIn("not found in this session", cross_task_detail.message)
                unchanged_task = other_runtime.store.get_task(other_task_id, session_id=other_runtime.session_id)
                self.assertIsNotNone(unchanged_task)
                assert unchanged_task is not None
                self.assertEqual(unchanged_task["status"], "pending")

                own_process = runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "own process scope proof token=supersecret",
                    "command": "printf 'own-process-ok token=supersecret'",
                    "execute": True,
                })
                self.assertEqual(own_process.status, "started", own_process.to_dict())
                own_process_id = int(own_process.data["process_id"])
                raw_process = runtime.store.conn.execute("SELECT command, purpose, decision_json FROM processes WHERE id=?", (own_process_id,)).fetchone()
                raw_process_text = (raw_process["command"] or "") + (raw_process["purpose"] or "") + (raw_process["decision_json"] or "")
                self.assertIn("token=<REDACTED>", raw_process_text)
                self.assertNotIn("supersecret", raw_process_text)
                other_process = other_runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "other process scope proof",
                    "command": "sleep 10",
                    "execute": True,
                })
                self.assertEqual(other_process.status, "started", other_process.to_dict())
                other_process_id = int(other_process.data["process_id"])
                for tool_name, args in (
                    ("poll_process", {"id": other_process_id}),
                    ("process_log", {"id": other_process_id}),
                    ("wait_process", {"id": other_process_id, "timeout": 0}),
                    ("get_process", {"id": other_process_id}),
                    ("kill_process", {"id": other_process_id}),
                ):
                    cross_process = runtime.registry.run(tool_name, args)
                    self.assertEqual(cross_process.status, "error", cross_process.to_dict())
                    self.assertIn("not found in this session", cross_process.message)
                other_after_cross_kill = other_runtime.registry.run("poll_process", {"id": other_process_id})
                self.assertIn(other_after_cross_kill.status, {"running", "started", "completed", "unknown"}, other_after_cross_kill.to_dict())

                own_wait = runtime.registry.run("wait_process", {"id": own_process_id, "timeout": 5})
                self.assertEqual(own_wait.status, "completed", own_wait.to_dict())
                self.assertIn("own-process-ok", own_wait.data["stdout"])
                self.assertIn("token=<REDACTED>", json.dumps(own_wait.to_dict()))
                self.assertNotIn("supersecret", json.dumps(own_wait.to_dict()))
                own_process_detail = runtime.registry.run("get_process", {"id": own_process_id})
                self.assertEqual(own_process_detail.status, "ok", own_process_detail.to_dict())
                self.assertIn("token=<REDACTED>", json.dumps(own_process_detail.to_dict()))
                self.assertNotIn("supersecret", json.dumps(own_process_detail.to_dict()))
            finally:
                if other_runtime is not None:
                    for process in other_runtime.store.list_processes(other_runtime.session_id, limit=10):
                        other_runtime.registry.run("kill_process", {"id": process["id"]})
                    other_runtime.close()
                runtime.close()

    def test_workspace_search_does_not_follow_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                outside = Path(tmp) / "outside-workspace-secret.txt"
                outside.write_text("outside-symlink-marker should stay outside workspace", encoding="utf-8")
                link = runtime.registry.workspace_root / "outside-link.txt"
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")

                searched = runtime.handle_message('/workspace-search query=outside-symlink-marker glob="**/*.txt"')
                self.assertIn("Found 0 matches", searched)
                self.assertNotIn("outside-symlink-marker should stay outside workspace", searched)

                read = runtime.handle_message('/read path=outside-link.txt')
                self.assertIn("escapes the engagement workspace", read)

                pack_source = Path(tmp) / "outside-pack-sentinel.txt"
                pack_source.write_text("OUTSIDE_PACK_LEAK_SENTINEL", encoding="utf-8")
                pack_link = runtime.registry.workspace_root / "pack-link.txt"
                pack_link.symlink_to(pack_source)
                pack = runtime.registry.run("export_pack", {"out": "symlink-pack.zip"})
                self.assertEqual(pack.status, "ok", pack.to_dict())
                with zipfile.ZipFile(pack.data["pack"]) as archive:
                    combined = "\n".join(
                        archive.read(name).decode("utf-8", errors="replace")
                        for name in archive.namelist()
                        if name.endswith((".json", ".md", ".txt"))
                    )
                    manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
                self.assertNotIn("OUTSIDE_PACK_LEAK_SENTINEL", combined)
                self.assertTrue(any(item.get("reason") == "symlink target outside evidence root" for item in manifest.get("skipped", [])))
            finally:
                runtime.close()

    def test_runtime_artifact_outputs_block_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            old_seal = os.environ.get("PHOBOS_TEST_ARTIFACT_SEAL")
            os.environ["PHOBOS_TEST_ARTIFACT_SEAL"] = "artifact containment passphrase"
            try:
                created = runtime.registry.run("create_finding", {"title": "Artifact containment finding", "severity": "Low"})
                self.assertEqual(created.status, "ok", created.to_dict())
                finding_id = created.data["finding"]["id"]

                good = runtime.registry.run("finding_review", {"id": finding_id, "out": "nested/review"})
                self.assertEqual(good.status, "ok", good.to_dict())
                good_path = Path(good.artifacts["markdown"]).resolve()
                findings_dir = (Path(runtime.registry.harness.store.root) / "agent" / "findings").resolve()
                self.assertEqual(os.path.commonpath([str(findings_dir), str(good_path)]), str(findings_dir))
                source_manifest = runtime.registry.run("evidence_manifest", {"out": "containment-manifest.json"})
                self.assertEqual(source_manifest.status, "ok", source_manifest.to_dict())

                escape_cases = [
                    ("finding_review", {"id": finding_id, "out": str(Path(tmp) / "outside-review.md")}, Path(tmp) / "outside-review.md"),
                    ("finding_bundle", {"id": finding_id, "out": str(Path(tmp) / "outside-finding-bundle.zip")}, Path(tmp) / "outside-finding-bundle.zip"),
                    ("operator_briefing", {"out": str(Path(tmp) / "outside-briefing.md")}, Path(tmp) / "outside-briefing.md"),
                    ("export_session", {"out": str(Path(tmp) / "outside-handoff.json")}, Path(tmp) / "outside-handoff.json"),
                    ("export_pack", {"out": str(Path(tmp) / "outside-pack.zip")}, Path(tmp) / "outside-pack.zip"),
                    ("sealed_export", {"passphrase_env": "PHOBOS_TEST_ARTIFACT_SEAL", "out": str(Path(tmp) / "outside-sealed.json")}, Path(tmp) / "outside-sealed.json"),
                    ("evidence_manifest", {"out": str(Path(tmp) / "outside-manifest.json")}, Path(tmp) / "outside-manifest.json"),
                    ("evidence_manifest_verify", {"path": "containment-manifest.json", "out": str(Path(tmp) / "outside-manifest-verify.json")}, Path(tmp) / "outside-manifest-verify.json"),
                    ("evidence_secret_scan", {"out": str(Path(tmp) / "outside-secret-scan.json")}, Path(tmp) / "outside-secret-scan.json"),
                    ("closeout_review", {"out": str(Path(tmp) / "outside-closeout.md")}, Path(tmp) / "outside-closeout.md"),
                    ("guardrail_selftest", {"out": str(Path(tmp) / "outside-guardrail-selftest.md")}, Path(tmp) / "outside-guardrail-selftest.md"),
                ]
                for tool, args, outside_path in escape_cases:
                    blocked = runtime.registry.run(tool, args)
                    self.assertEqual(blocked.status, "error", blocked.to_dict())
                    self.assertIn("escapes", blocked.message)
                    self.assertFalse(outside_path.exists(), f"{tool} wrote outside artifact dir")

                symlink_target = Path(tmp) / "outside-symlink-write.md"
                symlink_target.write_text("ORIGINAL OUTSIDE CONTENT", encoding="utf-8")
                link = findings_dir / "symlink-review.md"
                try:
                    link.symlink_to(symlink_target)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")
                symlink_block = runtime.registry.run("finding_export", {"id": finding_id, "out": "symlink-review.md"})
                self.assertEqual(symlink_block.status, "error", symlink_block.to_dict())
                self.assertIn("escapes", symlink_block.message)
                self.assertEqual(symlink_target.read_text(encoding="utf-8"), "ORIGINAL OUTSIDE CONTENT")
            finally:
                runtime.close()
                if old_seal is None:
                    os.environ.pop("PHOBOS_TEST_ARTIFACT_SEAL", None)
                else:
                    os.environ["PHOBOS_TEST_ARTIFACT_SEAL"] = old_seal

    def test_evidence_timeline_tool_slash_and_gateway_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                runtime.handle_message('/task-add content="Review timeline evidence token=supersecret" status=pending')
                nmap_output = "Starting Nmap\nNmap scan report for 10.10.0.5\nPORT   STATE SERVICE VERSION\n80/tcp open  http    nginx 1.24\n"
                nmap = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80", "stdout": nmap_output})
                self.assertEqual(nmap.status, "parsed", nmap.to_dict())
                finding = runtime.registry.run("create_finding", {
                    "title": "Timeline finding token=supersecret",
                    "severity": "Low",
                    "status": "needs-evidence",
                    "tool_run_ids": str(nmap.data["run_id"]),
                })
                self.assertEqual(finding.status, "ok", finding.to_dict())
                media_src = Path(tmp) / "timeline-media.txt"
                media_src.write_text("timeline media token=supersecret", encoding="utf-8")
                media = runtime.registry.run("media_import", {"path": str(media_src)})
                self.assertEqual(media.status, "ok", media.to_dict())
                approval = runtime.registry.run("run_command", {
                    "target": "app.example.test",
                    "type": "web",
                    "purpose": "timeline confirm token=supersecret",
                    "command": "curl -X POST https://app.example.test/profile?token=supersecret",
                    "execute": True,
                })
                self.assertEqual(approval.status, "needs_approval", approval.to_dict())

                timeline = runtime.registry.run("evidence_timeline", {"include_audit": True, "limit": 100})
                self.assertEqual(timeline.status, "ok", timeline.to_dict())
                categories = {entry["category"] for entry in timeline.data["entries"]}
                self.assertTrue({"tool_run", "finding", "approval", "task", "media", "audit"}.issubset(categories), categories)
                serialized = json.dumps(timeline.to_dict())
                self.assertNotIn("supersecret", serialized)
                markdown_path = Path(timeline.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Evidence Timeline", markdown)
                self.assertIn("nmap_scan", markdown)
                self.assertNotIn("supersecret", markdown)

                slash = runtime.handle_message('/timeline limit=10 include_audit=false')
                self.assertIn("Evidence timeline assembled", slash)
                self.assertIn("markdown", slash)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/timeline?limit=50&include_audit=false", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                gateway_categories = {entry["category"] for entry in payload["data"]["entries"]}
                self.assertTrue({"tool_run", "finding", "approval", "task", "media"}.issubset(gateway_categories), gateway_categories)
                self.assertNotIn("supersecret", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_evidence_manifest_hashes_artifacts_without_content_or_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proof = evidence_root / "reports" / "manifest-proof.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof_bytes = b"manifest proof body token=supersecret"
                proof.write_bytes(proof_bytes)
                outside = Path(tmp) / "outside-manifest-sentinel.txt"
                outside.write_text("OUTSIDE_MANIFEST_SENTINEL", encoding="utf-8")
                link = evidence_root / "agent" / "media" / "manifest-escape-link.txt"
                link.parent.mkdir(parents=True, exist_ok=True)
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation unavailable: {exc}")

                manifest = runtime.registry.run("evidence_manifest", {"out": "unit-manifest.json", "limit": 100})
                self.assertEqual(manifest.status, "ok", manifest.to_dict())
                self.assertTrue(manifest.data["no_target_activity"])
                self.assertTrue(manifest.data["secret_values_redacted"])
                expected_hash = hashlib.sha256(proof_bytes).hexdigest()
                self.assertTrue(any(entry.get("sha256") == expected_hash and entry.get("category") == "finding" for entry in manifest.data["entries"]), manifest.data["entries"])
                self.assertTrue(any(item.get("reason") == "symlink target outside evidence root" for item in manifest.data["skipped"]), manifest.data["skipped"])
                serialized = json.dumps(manifest.to_dict())
                self.assertNotIn("supersecret", serialized)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", serialized)
                json_path = Path(manifest.artifacts["json"])
                markdown_path = Path(manifest.artifacts["markdown"])
                self.assertTrue(json_path.exists())
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Evidence Manifest", markdown)
                self.assertIn(expected_hash, markdown)
                self.assertNotIn("supersecret", markdown)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", markdown)

                verified = runtime.registry.run("evidence_manifest_verify", {"path": json_path.name, "out": "unit-manifest-verify.json", "detect_new": False})
                self.assertEqual(verified.status, "ok", verified.to_dict())
                self.assertEqual(verified.data["verification_status"], "verified", verified.to_dict())
                self.assertTrue(verified.data["no_target_activity"])
                self.assertTrue(verified.data["secret_values_redacted"])
                verify_markdown = Path(verified.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Phobos Evidence Manifest Verification", verify_markdown)
                self.assertNotIn("supersecret", json.dumps(verified.to_dict()) + verify_markdown)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", json.dumps(verified.to_dict()) + verify_markdown)

                new_artifact = evidence_root / "reports" / "manifest-new-artifact.txt"
                new_artifact.write_text("new artifact token=supersecret", encoding="utf-8")
                new_review = runtime.registry.run("evidence_manifest_verify", {"path": json_path.name, "out": "unit-manifest-new-review.json", "detect_new": True})
                self.assertEqual(new_review.status, "ok", new_review.to_dict())
                self.assertEqual(new_review.data["verification_status"], "review", new_review.to_dict())
                self.assertGreaterEqual(new_review.data["counts"]["new"], 1)
                self.assertNotIn("supersecret", json.dumps(new_review.to_dict()) + Path(new_review.artifacts["markdown"]).read_text(encoding="utf-8"))

                proof.write_bytes(b"manifest proof body changed token=supersecret")
                changed = runtime.registry.run("evidence_manifest_verify", {"path": json_path.name, "out": "unit-manifest-changed.json", "detect_new": False})
                self.assertEqual(changed.status, "ok", changed.to_dict())
                self.assertEqual(changed.data["verification_status"], "changed", changed.to_dict())
                self.assertGreaterEqual(changed.data["counts"]["changed"], 1)
                changed_markdown = Path(changed.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("SHA-256 mismatch", changed_markdown)
                self.assertNotIn("supersecret", json.dumps(changed.to_dict()) + changed_markdown)

                probe_manifest = evidence_root / "agent" / "manifests" / "unit-manifest-missing-unsafe.json"
                probe_manifest.write_text(json.dumps({
                    "created_at": "2026-01-01T00:00:00Z",
                    "engagement": "Unit Manifest Probe",
                    "include_agent": True,
                    "entries": [
                        {"path": "reports/manifest-missing.txt", "category": "finding", "bytes": 10, "sha256": "0" * 64},
                        {"path": "../outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "1" * 64},
                        {"path": "/tmp/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "2" * 64},
                        {"path": "C:/outside-evidence.txt", "category": "evidence", "bytes": 1, "sha256": "3" * 64},
                    ],
                }), encoding="utf-8")
                probe_review = runtime.registry.run("evidence_manifest_verify", {"path": probe_manifest.name, "out": "unit-manifest-missing-unsafe-review.json", "detect_new": False})
                self.assertEqual(probe_review.status, "ok", probe_review.to_dict())
                self.assertEqual(probe_review.data["verification_status"], "changed", probe_review.to_dict())
                self.assertGreaterEqual(probe_review.data["counts"]["missing"], 1)
                self.assertGreaterEqual(probe_review.data["counts"]["unsafe"], 3)
                probe_markdown = Path(probe_review.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("manifest entry path is not evidence-root relative", probe_markdown)
                self.assertIn("missing", probe_markdown)
                self.assertNotIn("OUTSIDE_MANIFEST_SENTINEL", json.dumps(probe_review.to_dict()) + probe_markdown)

                slash = runtime.handle_message('/manifest limit=10 out=slash-manifest.json')
                self.assertIn("Evidence manifest wrote", slash)
                self.assertIn("evidence_manifest", runtime.handle_message("/schemas name=evidence_manifest"))
                verify_slash = runtime.handle_message('/manifest-verify path=unit-manifest.json detect_new=false out=slash-manifest-verify.json')
                self.assertIn("Evidence manifest verification changed", verify_slash)
                self.assertIn("evidence_manifest_verify", runtime.handle_message("/schemas name=evidence_manifest_verify"))

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/manifest?limit=50&include_agent=false", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertFalse(payload["data"]["include_agent"])
                self.assertNotIn("supersecret", json.dumps(payload))
                with urllib.request.urlopen(f"http://{host}:{port}/manifest-verify?path=unit-manifest.json&detect_new=false", timeout=5) as response:
                    verify_payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(verify_payload["status"], "ok")
                self.assertEqual(verify_payload["data"]["verification_status"], "changed")
                self.assertTrue(verify_payload["data"]["no_target_activity"])
                self.assertNotIn("supersecret", json.dumps(verify_payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_evidence_secret_scan_reports_redacted_local_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proof = evidence_root / "reports" / "secret-scan-proof.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof.write_text(
                    "GET / HTTP/1.1\n"
                    "Authorization: Bearer scan-secret-token\n"
                    "Cookie: sessionid=scan-cookie-value\n"
                    "password=scan-password-value\n"
                    "normal line\n",
                    encoding="utf-8",
                )
                outside = Path(tmp) / "outside-secret-scan-sentinel.txt"
                outside.write_text("OUTSIDE_SECRET_SCAN_SENTINEL token=outside-scan-token", encoding="utf-8")
                link = evidence_root / "agent" / "media" / "secret-scan-escape-link.txt"
                link.parent.mkdir(parents=True, exist_ok=True)
                try:
                    link.symlink_to(outside)
                except (OSError, NotImplementedError):
                    link = None

                scan = runtime.registry.run("evidence_secret_scan", {"out": "unit-secret-scan.json", "limit": 20})
                self.assertEqual(scan.status, "ok", scan.to_dict())
                self.assertEqual(scan.data["review_status"], "review", scan.to_dict())
                self.assertTrue(scan.data["no_target_activity"])
                self.assertFalse(scan.data["raw_file_contents_emitted"])
                self.assertTrue(scan.data["secret_values_redacted"])
                self.assertGreaterEqual(scan.data["counts"]["total_secret_like_matches"], 3)
                self.assertTrue(any(item.get("path") == "reports/secret-scan-proof.txt" for item in scan.data["findings"]), scan.data["findings"])
                if link is not None:
                    self.assertTrue(any(item.get("reason") == "symlink target outside evidence root" for item in scan.data["skipped"]), scan.data["skipped"])
                json_path = Path(scan.artifacts["json"])
                markdown_path = Path(scan.artifacts["markdown"])
                self.assertTrue(json_path.exists())
                self.assertTrue(markdown_path.exists())
                combined = json.dumps(scan.to_dict()) + json_path.read_text(encoding="utf-8") + markdown_path.read_text(encoding="utf-8")
                self.assertIn("<REDACTED>", combined)
                self.assertIn("Phobos Evidence Secret Scan", combined)
                self.assertNotIn("scan-secret-token", combined)
                self.assertNotIn("scan-cookie-value", combined)
                self.assertNotIn("scan-password-value", combined)
                self.assertNotIn("OUTSIDE_SECRET_SCAN_SENTINEL", combined)

                slash = runtime.handle_message('/secret-scan limit=20 out=slash-secret-scan.json')
                schema = runtime.handle_message("/schemas name=evidence_secret_scan")
                auto = runtime.handle_message('/auto apply=true prompt="scan evidence for secrets"')
                self.assertIn("Evidence secret scan review", slash)
                self.assertIn("evidence_secret_scan", schema)
                self.assertIn('"tool": "evidence_secret_scan"', auto)
                self.assertNotIn("scan-secret-token", slash + schema + auto)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/secret-scan?limit=20", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["review_status"], "review")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertNotIn("scan-secret-token", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_closeout_review_reports_ready_state_and_blocks_pending_approvals(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proof = evidence_root / "reports" / "closeout-request-response.txt"
                proof.parent.mkdir(parents=True, exist_ok=True)
                proof.write_text("HTTP response proof token=supersecret; baseline negative control; read-only no state change.", encoding="utf-8")
                run_id = runtime.store.create_tool_run(
                    runtime.session_id,
                    "httpx_probe",
                    "https://app.example.test",
                    "httpx -json https://app.example.test",
                    "parsed",
                    parsed={"summary": {"http_services": 1}},
                    artifact_path=str(proof),
                )
                created = runtime.registry.run("create_finding", {
                    "title": "Closeout-ready exposed management route",
                    "severity": "Medium",
                    "status": "confirmed",
                    "description": "A scoped management route returned a replayable HTTP response, with baseline negative control evidence recorded.",
                    "impact": "A scoped attacker could target administrative workflows based on the observed exposure without needing unsafe validation.",
                    "recommendation": "Restrict management route access, require MFA, and monitor administrative access attempts.",
                    "tool_run_ids": str(run_id),
                    "evidence": "Read-only validation with no state change or cleanup required.",
                })
                self.assertEqual(created.status, "ok", created.to_dict())
                self.assertEqual(runtime.registry.run("evidence_timeline", {"out": "unit-timeline.md"}).status, "ok")
                self.assertEqual(runtime.registry.run("evidence_manifest", {"out": "unit-manifest.json"}).status, "ok")
                self.assertEqual(runtime.registry.run("export_pack", {"out": "unit-pack.zip"}).status, "ok")

                ready = runtime.registry.run("closeout_review", {"out": "unit-closeout.md"})
                self.assertEqual(ready.status, "ok", ready.to_dict())
                self.assertEqual(ready.data["readiness"], "ready", ready.to_dict())
                self.assertTrue(ready.data["no_target_activity"])
                markdown_path = Path(ready.artifacts["markdown"])
                self.assertTrue(markdown_path.exists())
                markdown = markdown_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Closeout Review", markdown)
                self.assertIn("Local SQLite/WAL/SHM remain plaintext", markdown)
                self.assertNotIn("supersecret", json.dumps(ready.to_dict()) + markdown)
                self.assertIn("closeout_review", runtime.handle_message("/schemas name=closeout_review"))

                queued = runtime.registry.run("run_command", {
                    "target": "app.example.test",
                    "type": "web",
                    "purpose": "closeout pending approval token=supersecret",
                    "command": "printf curl -X POST https://app.example.test/profile token=supersecret",
                    "execute": True,
                })
                self.assertEqual(queued.status, "needs_approval", queued.to_dict())
                blocked = runtime.registry.run("closeout_review", {})
                self.assertEqual(blocked.status, "ok", blocked.to_dict())
                self.assertEqual(blocked.data["readiness"], "blocked")
                self.assertEqual(blocked.data["summary"]["pending_approvals"], 1)
                blocked_markdown = Path(blocked.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertNotIn("supersecret", json.dumps(blocked.to_dict()) + blocked_markdown)
                slash = runtime.handle_message('/closeout out=slash-closeout.md')
                self.assertIn("Closeout review blocked", slash)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/closeout", timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["status"], "ok")
                self.assertEqual(payload["data"]["readiness"], "blocked")
                self.assertTrue(payload["data"]["no_target_activity"])
                self.assertNotIn("supersecret", json.dumps(payload))
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_closeout_review_includes_redacted_local_drilldown_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            try:
                evidence_root = runtime.registry.harness.store.root
                proc_dir = evidence_root / "agent" / "processes"
                proc_dir.mkdir(parents=True, exist_ok=True)
                approval_id = runtime.store.create_approval(
                    runtime.session_id,
                    "run_command",
                    {"command": "curl -X POST https://app.example.test/profile token=supersecret", "purpose": "queued token=supersecret"},
                    {"status": "confirm", "reasons": ["state change token=supersecret"]},
                )
                task_id = runtime.store.create_task(runtime.session_id, "Resolve closeout evidence token=supersecret", status="in_progress")
                active_proc = runtime.store.create_process(
                    runtime.session_id,
                    "printf token=supersecret",
                    "app.example.test",
                    "host",
                    "active closeout process token=supersecret",
                    str(proc_dir / "active.out"),
                    str(proc_dir / "active.err"),
                    str(proc_dir / "active.rc"),
                    {"status": "allow"},
                )
                runtime.store.update_process(active_proc, pid=999999, status="running")
                failed_proc = runtime.store.create_process(
                    runtime.session_id,
                    "printf token=supersecret",
                    "app.example.test",
                    "host",
                    "failed closeout process token=supersecret",
                    str(proc_dir / "failed.out"),
                    str(proc_dir / "failed.err"),
                    str(proc_dir / "failed.rc"),
                    {"status": "allow"},
                )
                runtime.store.update_process(failed_proc, pid=999998, status="failed", exit_code=1, ended_at="2026-01-01T00:00:00+00:00")
                finding_id = runtime.store.create_finding(
                    runtime.session_id,
                    "Closeout gap finding token=supersecret",
                    severity="High",
                    status="confirmed",
                    description="too short",
                    impact="too short",
                    recommendation="too short",
                    evidence=[],
                )

                result = runtime.registry.run("closeout_review", {"out": "drilldown-closeout.md"})
                self.assertEqual(result.status, "ok", result.to_dict())
                self.assertEqual(result.data["readiness"], "blocked")
                checks = {check["name"]: check for check in result.data["checks"]}

                def refs(name: str) -> set[str]:
                    return {str(item.get("ref")) for item in checks[name].get("related", [])}

                self.assertIn(f"approval:{approval_id}", refs("pending_approvals"))
                self.assertIn(f"task:{task_id}", refs("open_tasks"))
                self.assertIn(f"process:{active_proc}", refs("background_processes"))
                self.assertIn(f"process:{failed_proc}", refs("failed_processes"))
                self.assertIn(f"finding:{finding_id}", refs("finding_readiness"))
                self.assertIn("artifact:agent/manifests/", refs("manifests"))
                self.assertIn("artifact:agent/timelines/", refs("timelines"))
                self.assertIn("artifact:agent/exports/", refs("exports"))
                self.assertGreaterEqual(result.data["summary"].get("drilldown_links", 0), 7)
                markdown = Path(result.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("## Drill-down", markdown)
                self.assertIn(f"approval:{approval_id}", markdown)

                resolver_artifact = evidence_root / "agent" / "manifests" / "resolver-proof.txt"
                resolver_artifact.parent.mkdir(parents=True, exist_ok=True)
                resolver_artifact.write_text("resolver artifact body token=supersecret", encoding="utf-8")
                resolver_rel = resolver_artifact.relative_to(evidence_root).as_posix()
                resolver_symlink = evidence_root / "agent" / "manifests" / "resolver-symlink.txt"
                outside_resolver_target = Path(tmp) / "outside-resolver-target.txt"
                outside_resolver_target.write_text("outside resolver symlink token=supersecret", encoding="utf-8")
                symlink_blocked = None
                try:
                    if resolver_symlink.exists() or resolver_symlink.is_symlink():
                        resolver_symlink.unlink()
                    resolver_symlink.symlink_to(outside_resolver_target)
                    symlink_rel = resolver_symlink.relative_to(evidence_root).as_posix()
                    symlink_blocked = runtime.registry.run("resolve_local_ref", {"ref": f"artifact:{symlink_rel}"})
                except (OSError, NotImplementedError) as exc:
                    symlink_blocked = runtime.registry.run("resolve_local_ref", {"ref": "artifact:../symlink-unavailable.txt"})
                    symlink_blocked.message = f"symlink unavailable: {exc}"
                resolved_task = runtime.registry.run("resolve_local_ref", {"ref": f"task:{task_id}"})
                resolved_finding = runtime.handle_message(f"/ref finding:{finding_id}")
                resolved_artifact = runtime.registry.run("resolve_local_ref", {"ref": f"artifact:{resolver_rel}"})
                invalid_max_bytes = runtime.registry.run("resolve_local_ref", {"ref": f"artifact:{resolver_rel}", "max_bytes": "not-an-int"})
                blocked_artifact = runtime.registry.run("resolve_local_ref", {"ref": "artifact:../outside.txt"})
                auto_ref = runtime.handle_message(f'/auto apply=true prompt="show task:{task_id}"')
                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="ref-other"))
                try:
                    other_task_id = other_runtime.store.create_task(other_runtime.session_id, "foreign resolver task token=supersecret")
                    cross_task = runtime.registry.run("resolve_local_ref", {"ref": f"task:{other_task_id}"})
                finally:
                    other_runtime.close()
                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/ref?ref=task:{task_id}", timeout=5) as response:
                    gateway_ref = json.loads(response.read().decode("utf-8"))
                resolver_blob = json.dumps({
                    "task": resolved_task.to_dict(),
                    "finding": resolved_finding,
                    "artifact": resolved_artifact.to_dict(),
                    "invalid_max_bytes": invalid_max_bytes.to_dict(),
                    "blocked_artifact": blocked_artifact.to_dict(),
                    "symlink_blocked": symlink_blocked.to_dict(),
                    "auto": auto_ref,
                    "cross": cross_task.to_dict(),
                    "gateway": gateway_ref,
                }, sort_keys=True)
                self.assertEqual(resolved_task.status, "ok", resolved_task.to_dict())
                self.assertIn("token=<REDACTED>", resolver_blob)
                self.assertIn("Resolved finding", resolved_finding)
                self.assertEqual(resolved_artifact.status, "ok", resolved_artifact.to_dict())
                self.assertEqual(resolved_artifact.data["artifact"]["sha256"], hashlib.sha256(b"resolver artifact body token=supersecret").hexdigest())
                self.assertTrue(resolved_artifact.data["artifact"]["no_file_content_emitted"])
                self.assertEqual(invalid_max_bytes.status, "error", invalid_max_bytes.to_dict())
                self.assertEqual(blocked_artifact.status, "blocked", blocked_artifact.to_dict())
                if resolver_symlink.is_symlink():
                    self.assertEqual(symlink_blocked.status, "blocked", symlink_blocked.to_dict())
                    self.assertIn("outside", symlink_blocked.message)
                self.assertIn('"tool": "resolve_local_ref"', auto_ref)
                self.assertEqual(cross_task.status, "error", cross_task.to_dict())
                self.assertIn("not found in this session", cross_task.message)
                self.assertEqual(gateway_ref["status"], "ok")
                self.assertNotIn("foreign resolver task", resolver_blob)

                serialized = json.dumps(result.to_dict()) + markdown + resolver_blob
                self.assertNotIn("supersecret", serialized)
                self.assertNotIn("curl -X POST", serialized)
                self.assertTrue(result.data["no_target_activity"])
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_lcm_context_reflect_cross_session_delegation_and_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 4)
                runtime.handle_message("LCM marker acme-lcm-node source context")
                compacted = runtime.handle_message('/lcm-compact title="LCM parity marker" limit=20 parent=true')
                self.assertIn("Context node", compacted)
                described = runtime.handle_message('/lcm-describe')
                self.assertIn("LCM parity marker", described)
                expanded = runtime.handle_message('/lcm-expand id=1')
                self.assertIn("acme-lcm-node", expanded)
                other_context = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="other-context"))
                try:
                    other_message_id = other_context.store.append_message(other_context.session_id, "user", "foreign-context-node-secret")
                    other_node_id = other_context.store.create_context_node(
                        other_context.session_id,
                        "Other session LCM",
                        "foreign-context-node-secret",
                        sources=[{"type": "message", "id": other_message_id}],
                    )
                    other_context.store.create_context_node(
                        other_context.session_id,
                        "Foreign child under local parent id",
                        "foreign-child-context-secret",
                        parent_id=1,
                        depth=1,
                    )
                    other_delegation_id = other_context.store.create_delegation(
                        other_context.session_id,
                        "foreign delegation detail secret token=supersecret",
                        [{"role": "scope", "prompt": "foreign delegation detail secret token=supersecret"}],
                    )
                    other_context.store.complete_delegation(
                        other_delegation_id,
                        "ok",
                        [{"role": "scope", "content": "foreign delegation detail secret token=supersecret"}],
                        {"note": "foreign delegation artifact token=supersecret", "api_key": "foreign-delegation-key"},
                        session_id=other_context.session_id,
                    )
                finally:
                    other_context.close()
                cross_complete = runtime.store.complete_delegation(
                    other_delegation_id,
                    "error",
                    [{"role": "scope", "content": "cross-session mutation token=supersecret"}],
                    {"note": "cross-session artifact token=supersecret"},
                    session_id=runtime.session_id,
                )
                raw_delegation_row = runtime.store.conn.execute(
                    "SELECT status, prompt, tasks_json, results_json, artifacts_json FROM delegations WHERE id=?",
                    (other_delegation_id,),
                ).fetchone()
                raw_delegation_text = "".join(str(raw_delegation_row[key] or "") for key in ["prompt", "tasks_json", "results_json", "artifacts_json"]) if raw_delegation_row else ""
                self.assertIsNone(cross_complete)
                self.assertIsNotNone(raw_delegation_row)
                self.assertEqual(raw_delegation_row["status"], "ok")
                self.assertNotIn("supersecret", raw_delegation_text)
                self.assertNotIn("cross-session mutation", raw_delegation_text)
                self.assertIn("<REDACTED>", raw_delegation_text)
                cross_describe = runtime.registry.run("context_describe", {"id": other_node_id})
                cross_expand = runtime.registry.run("context_expand", {"id": other_node_id})
                current_describe = runtime.registry.run("context_describe", {"id": 1})
                self.assertEqual(cross_describe.status, "error")
                self.assertEqual(cross_expand.status, "error")
                self.assertIn("not found in this session", cross_describe.message)
                serialized_scope = json.dumps({
                    "cross_describe": cross_describe.to_dict(),
                    "cross_expand": cross_expand.to_dict(),
                    "current_describe": current_describe.to_dict(),
                })
                self.assertNotIn("foreign-context-node-secret", serialized_scope)
                self.assertNotIn("foreign-child-context-secret", serialized_scope)
                queried = runtime.handle_message('/reflect query=acme-lcm-node')
                self.assertIn("Context query answered", queried)
                retained = runtime.handle_message('/hindsight-retain content="ACME hindsight marker" context=unit tags=hindsight')
                self.assertIn("Retained Hindsight-style memory", retained)
                hindsight = runtime.handle_message('/hindsight-recall query=ACME')
                self.assertIn("ACME hindsight marker", hindsight)
                reflected = runtime.handle_message('/hindsight query=acme-lcm-node')
                self.assertIn("Context query answered", reflected)
                self.assertIn("lcm_compact", runtime.handle_message('/schemas name=lcm_compact'))

                delegated_result = runtime.registry.run("delegate_tasks", {"prompt": "review lcm parity evidence", "roles": "scope,safety"})
                self.assertEqual(delegated_result.status, "ok", delegated_result.to_dict())
                delegation_id = delegated_result.data["delegation"]["id"]
                results = delegated_result.data["delegation"]["results"]
                self.assertEqual(len(results), 2)
                child_ids = {item["child_session_id"] for item in results}
                self.assertEqual(len(child_ids), 2)
                self.assertNotIn(runtime.session_id, child_ids)
                delegation_detail = runtime.registry.run("get_delegation", {"id": delegation_id})
                cross_delegation_detail = runtime.registry.run("get_delegation", {"id": other_delegation_id})
                self.assertEqual(delegation_detail.status, "ok", delegation_detail.to_dict())
                self.assertEqual(cross_delegation_detail.status, "error", cross_delegation_detail.to_dict())
                self.assertIn("not found in this session", cross_delegation_detail.message)
                self.assertNotIn("supersecret", json.dumps(cross_delegation_detail.to_dict()))
                delegations = runtime.handle_message('/delegations')
                delegation_slash = runtime.handle_message(f'/delegation id={delegation_id}')
                self.assertIn("review lcm parity evidence", delegations)
                self.assertIn("Delegation", delegation_slash)
                sessions = runtime.store.list_sessions(limit=20)
                self.assertTrue(any(str(row["name"]).startswith("delegation-") for row in sessions))
                child_search = runtime.store.search_all_messages("review lcm parity evidence", limit=10)
                self.assertTrue(any(row.get("session_id") in child_ids for row in child_search))

                process_schema = runtime.registry.run("tool_schemas", {"name": "delegate_tasks"})
                schema_props = process_schema.data["tools"][0]["schema"]["properties"]
                self.assertEqual(schema_props["sandbox"]["enum"], ["thread", "process"])
                self.assertEqual(schema_props["timeout"]["maximum"], 300)
                process_delegated = runtime.registry.run("delegate_tasks", {"prompt": "process isolated delegation token=process-secret", "roles": "scope,safety", "sandbox": "process", "timeout": 20})
                self.assertEqual(process_delegated.status, "ok", process_delegated.to_dict())
                process_delegation_id = process_delegated.data["delegation"]["id"]
                process_results = process_delegated.data["delegation"]["results"]
                self.assertEqual(len(process_results), 2)
                self.assertTrue(all(item.get("sandbox") == "process" for item in process_results))
                self.assertTrue(all(item.get("worker", {}).get("process_isolated") is True for item in process_results))
                self.assertTrue(all(item.get("worker", {}).get("no_target_activity") is True for item in process_results))
                self.assertTrue(all(Path(str(item.get("worker", {}).get("output", ""))).is_file() for item in process_results))
                self.assertTrue(all(Path(str(item.get("child_workspace", ""))).is_dir() for item in process_results))
                process_child_ids = {item["child_session_id"] for item in process_results}
                self.assertEqual(len(process_child_ids), 2)
                self.assertNotIn(runtime.session_id, process_child_ids)
                process_blob = json.dumps(process_delegated.to_dict())
                self.assertNotIn("process-secret", process_blob)
                process_artifact_text = Path(process_delegated.artifacts["summary"]).read_text(encoding="utf-8")
                self.assertIn("Sandbox: process", process_artifact_text)
                self.assertNotIn("process-secret", process_artifact_text)
                for item in process_results:
                    worker = item.get("worker", {})
                    worker_blob = ""
                    for key in ("input", "output"):
                        worker_path = Path(str(worker.get(key, "")))
                        self.assertTrue(worker_path.is_file(), worker)
                        worker_blob += worker_path.read_text(encoding="utf-8")
                    self.assertNotIn("process-secret", worker_blob)
                    self.assertIn("<REDACTED>", worker_blob)
                process_raw = runtime.store.conn.execute(
                    "SELECT prompt, tasks_json, results_json, artifacts_json FROM delegations WHERE id=?",
                    (process_delegation_id,),
                ).fetchone()
                process_raw_text = "".join(str(process_raw[key] or "") for key in process_raw.keys()) if process_raw else ""
                self.assertNotIn("process-secret", process_raw_text)
                self.assertIn("<REDACTED>", process_raw_text)
                status = runtime.registry.run("runtime_status", {})
                self.assertIn("process", status.data.get("delegation_sandboxing", {}).get("supported", []))
                self.assertTrue(status.data.get("delegation_sandboxing", {}).get("process_worker_no_target_activity"), status.to_dict())

                started = runtime.registry.run("start_process", {
                    "target": "app.example.test",
                    "type": "host",
                    "purpose": "wait process smoke",
                    "command": "printf wait-ok",
                    "execute": True,
                })
                waited = runtime.registry.run("wait_process", {"id": started.data["process_id"], "timeout": 5})
                self.assertEqual(waited.status, "completed", waited.to_dict())
                self.assertIn("wait-ok", waited.data["stdout"])
            finally:
                runtime.close()

            other = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="other"))
            try:
                other.handle_message("cross-session marker crosssession-acme")
            finally:
                other.close()
            runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="unit"))
            try:
                searched = runtime.handle_message('/search-all query=crosssession-acme')
                self.assertIn("crosssession-acme", searched)
            finally:
                runtime.close()

    def test_model_plan_validates_tool_names_and_schema_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Plan Validation",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-validation",
                    auto_model_planning=True,
                    confirm_tools=("remember",),
                ),
                adapter=FakeToolCallValidationAdapter(),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="mixed fake model plan token=plan-secret"')
                payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(payload["mode"], "plan_only")
                self.assertTrue(payload["transcript_artifact_written"])
                self.assertTrue(payload["no_tools_executed"])
                self.assertEqual(payload["execution_ledger"], [])
                self.assertEqual(payload.get("planner_trace_count"), 1)
                self.assertEqual(len(payload.get("planner_trace", [])), 1)
                self.assertEqual(payload["planner_trace"][0].get("provider"), "fake-tool-call-validation")
                self.assertEqual(payload["planner_trace"][0].get("tool_call_count"), 2)
                self.assertEqual(payload["planner_trace"][0].get("rejected_tool_call_count"), 2)
                plan_artifacts = payload.get("artifacts", {})
                plan_json_path = Path(plan_artifacts.get("json", ""))
                plan_md_path = Path(plan_artifacts.get("markdown", ""))
                self.assertTrue(plan_json_path.exists())
                self.assertTrue(plan_md_path.exists())
                plan_transcript = plan_json_path.read_text(encoding="utf-8") + plan_md_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Native Tool-Calling Auto Plan", plan_transcript)
                self.assertIn("Mode: `plan_only`", plan_transcript)
                self.assertIn("Planner trace", plan_transcript)
                self.assertIn("provider=`fake-tool-call-validation`", plan_transcript)
                self.assertIn("No registry results were recorded", plan_transcript)
                self.assertNotIn("plan-secret", planned + plan_transcript)
                self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["list_tasks", "run_command"])
                self.assertEqual(payload["tool_calls"][0]["args"]["limit"], 2)
                self.assertTrue(payload["tool_calls"][0]["validation"]["schema_validated"])
                self.assertEqual(payload["tool_calls"][1]["args"]["execute"], False)
                rejected_blob = json.dumps(payload["rejected_tool_calls"])
                self.assertIn("Unknown tool: missing_tool", rejected_blob)
                self.assertIn("value is required", rejected_blob)
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                audit_events = [row["event"] for row in runtime.store.list_audit(runtime.session_id, limit=20)]
                self.assertIn("auto_plan_preview", audit_events)
                raw_audit = "\n".join(row[0] or "" for row in runtime.store.conn.execute("SELECT event FROM audit_log").fetchall())
                self.assertNotIn("tool_call", raw_audit)
                plan_rel_json = plan_json_path.relative_to(runtime.registry.harness.store.root).as_posix()
                plan_detail = runtime.registry.run("get_auto_transcript", {"path": plan_rel_json, "max_ledger": 5})
                self.assertEqual(plan_detail.status, "ok", plan_detail.to_dict())
                self.assertEqual(plan_detail.data["summary"].get("planner_trace_count"), 1)
                self.assertEqual(plan_detail.data["summary"].get("planner_trace", [{}])[0].get("provider"), "fake-tool-call-validation")

                applied = runtime.handle_message('/auto apply=true model=true prompt="mixed fake model plan token=plan-secret"')
                applied_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(applied_payload["mode"], "applied")
                result_statuses = [item["result"]["status"] for item in applied_payload["results"]]
                self.assertIn("ok", result_statuses)
                self.assertIn("dry_run", result_statuses)
                ledger = applied_payload.get("execution_ledger", [])
                self.assertEqual(applied_payload.get("planner_trace_count"), 1)
                self.assertEqual(applied_payload.get("planner_trace", [{}])[0].get("provider"), "fake-tool-call-validation")
                self.assertEqual([item["tool"] for item in ledger], ["list_tasks", "run_command"])
                self.assertEqual(ledger[1]["execution_state"], "dry_run_not_executed")
                self.assertFalse(ledger[1]["actual_command_or_process_activity"])
                self.assertFalse(ledger[1]["safe_to_claim_command_executed"])
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                self.assertFalse((tmp_path / "should-not-run").exists())
            finally:
                runtime.close()

    def test_model_plan_enforces_per_step_tool_call_budget_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Tool Call Budget",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)

            class FakeOverBudgetToolPlanAdapter(BaseModelAdapter):
                provider = "fake-tool-call-budget"

                def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
                    calls = [
                        {
                            "tool": "remember",
                            "args": {"key": f"native-budget-{index:02d}", "value": f"accepted budget call {index}"},
                            "reason": "prove bounded native planner dispatch",
                        }
                        for index in range(22)
                    ]
                    calls[-1]["args"]["value"] = "over-budget sentinel token=native-budget-secret"
                    return ModelResponse(
                        provider=self.provider,
                        role="impact",
                        content=json.dumps({"summary": "over-budget native model plan", "tool_calls": calls, "warnings": []}),
                        raw={"model": "fake-budget-model", "native_tool_calls": True, "native_tool_call_count": len(calls), "rejected_native_tool_call_count": 0},
                    )

                def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
                    return ModelResponse(provider=self.provider, role=role, content="fake response")

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-tool-call-budget",
                    auto_model_planning=True,
                ),
                adapter=FakeOverBudgetToolPlanAdapter(),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="native tool budget token=native-budget-secret"')
                payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(payload["mode"], "plan_only")
                self.assertTrue(payload["no_tools_executed"])
                self.assertEqual(len(payload.get("tool_calls", [])), 20)
                self.assertEqual(len(payload.get("rejected_tool_calls", [])), 2)
                metadata = payload.get("metadata", {})
                self.assertEqual(metadata.get("max_model_tool_calls_per_step"), 20)
                self.assertEqual(metadata.get("raw_model_tool_call_count"), 22)
                self.assertEqual(metadata.get("tool_call_budget_excess_count"), 2)
                self.assertTrue(metadata.get("tool_call_budget_exhausted"))
                trace = payload.get("planner_trace", [{}])[0]
                self.assertEqual(trace.get("tool_call_count"), 20)
                self.assertEqual(trace.get("rejected_tool_call_count"), 2)
                self.assertEqual(trace.get("tool_call_budget_excess_count"), 2)
                self.assertTrue(trace.get("tool_call_budget_exhausted"))
                self.assertIn("only the first 20", json.dumps(payload.get("warnings", [])))

                applied = runtime.handle_message('/auto apply=true model=true prompt="native tool budget token=native-budget-secret"')
                applied_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(applied_payload["mode"], "applied")
                self.assertEqual(len(applied_payload.get("results", [])), 20)
                self.assertEqual([item.get("result", {}).get("status") for item in applied_payload.get("results", [])], ["ok"] * 20)
                self.assertIsNotNone(runtime.store.get_memory(key="native-budget-00"))
                self.assertIsNotNone(runtime.store.get_memory(key="native-budget-19"))
                self.assertIsNone(runtime.store.get_memory(key="native-budget-20"))
                self.assertIsNone(runtime.store.get_memory(key="native-budget-21"))
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("per_step_model_tool_call_budget_enforced"), status)
                self.assertEqual(status.get("max_model_tool_calls_per_step"), 20)
                self.assertTrue(status.get("milestone_contract", {}).get("per_step_model_tool_call_budget"), status)
                self.assertNotIn("native-budget-secret", planned + applied + json.dumps(payload) + json.dumps(applied_payload) + json.dumps(status))
            finally:
                runtime.close()

    def test_model_plan_extracts_wrapped_or_fenced_json_before_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Wrapped JSON Native Plan",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "wrapped-json-should-not-run.txt"
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="wrapped-json-native-plan",
                    auto_model_planning=True,
                ),
                adapter=FakeWrappedJsonToolPlanAdapter(marker),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="wrapped JSON model plan token=wrapped-plan-secret"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                self.assertEqual(plan_payload.get("planner_trace", [{}])[0].get("provider"), "fake-wrapped-json-tool-plan")
                self.assertTrue(plan_payload["tool_calls"][0]["validation"]["schema_validated"])

                applied = runtime.handle_message('/auto apply=true model=true prompt="wrapped JSON model plan token=wrapped-plan-secret"')
                applied_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(applied_payload["mode"], "applied")
                self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                self.assertFalse(marker.exists())
                recall = runtime.handle_message('/recall query=native-wrapped-json')
                self.assertIn("wrapped JSON model plan accepted", recall)
                native_status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(native_status.get("wrapped_json_plan_extraction"), native_status)
                self.assertTrue(native_status.get("milestone_contract", {}).get("wrapped_json_plan_extraction"), native_status)
                serialized = planned + applied + recall + json.dumps(plan_payload) + json.dumps(applied_payload)
                self.assertNotIn("wrapped-plan-secret", serialized)
                self.assertNotIn("wrapped-json-secret", serialized)
            finally:
                runtime.close()

    def test_openai_native_tool_calls_are_translated_and_runtime_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native OpenAI Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-openai-should-not-execute.txt"

            class FakeHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "native provider selected safe local memory plus a command dry-run",
                                    "tool_calls": [
                                        {
                                            "id": "call_memory",
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-openai", "value": "openai-compatible native tool call translated"}),
                                            },
                                        },
                                        {
                                            "id": "call_dry_run",
                                            "type": "function",
                                            "function": {
                                                "name": "run_command",
                                                "arguments": json.dumps({
                                                    "target": "app.example.test",
                                                    "purpose": "native tool call dry-run validation",
                                                    "command": f"printf native-openai-dry-run > {dry_run_marker}",
                                                    "execute": True,
                                                }),
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-openai-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native provider tool call request"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(plan_payload["tool_calls"][0]["args"]["key"], "native-openai")
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    self.assertTrue(plan_payload["tool_calls"][1]["validation"].get("schema_validated"))
                    self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native provider tool call request"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual(applied_payload["mode"], "applied")
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    applied_artifacts = applied_payload.get("artifacts", {}) if isinstance(applied_payload.get("artifacts"), dict) else {}
                    applied_json_path = Path(applied_artifacts.get("json", ""))
                    applied_md_path = Path(applied_artifacts.get("markdown", ""))
                    self.assertTrue(applied_json_path.is_file())
                    self.assertTrue(applied_md_path.is_file())
                    applied_rel_json = applied_json_path.relative_to(runtime.registry.harness.store.root).as_posix()
                    transcript_detail = runtime.registry.run("get_auto_transcript", {"path": applied_rel_json, "max_ledger": 5}).to_dict()
                    self.assertEqual(transcript_detail.get("status"), "ok", transcript_detail)
                    transcript_summary = transcript_detail.get("data", {}).get("summary", {})
                    transcript_calls = transcript_summary.get("tool_calls", [])
                    transcript_results = transcript_summary.get("result_summaries", [])
                    applied_markdown = applied_md_path.read_text(encoding="utf-8")
                recall = runtime.handle_message('/recall query=native-openai')
                self.assertIn("openai-compatible native tool call translated", recall)
                self.assertEqual([item.get("provider_tool_call_id") for item in transcript_calls], ["call_memory", "call_dry_run"])
                self.assertEqual(transcript_calls[1].get("native_tool_call_source"), "native provider tool_call")
                self.assertEqual(transcript_calls[1].get("native_tool_call_index"), 2)
                self.assertEqual([item.get("provider_tool_call_id") for item in transcript_results], ["call_memory", "call_dry_run"])
                self.assertIn("provider_call_id=`call_memory`", applied_markdown)
                self.assertIn("provider_call_id=`call_dry_run`", applied_markdown)
                self.assertIn("source=`native provider tool_call`", applied_markdown)
                self.assertTrue(captured_payloads)
                self.assertIn("tools", captured_payloads[0])
                self.assertEqual(captured_payloads[0]["tool_choice"], "auto")
                tool_names = [item["function"]["name"] for item in captured_payloads[0]["tools"]]
                self.assertIn("remember", tool_names)
                self.assertNotIn("approve", tool_names)
                self.assertNotIn("deny", tool_names)
                self.assertFalse(dry_run_marker.exists())
            finally:
                runtime.close()

    def test_native_provider_call_ids_are_redacted_bounded_and_single_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Provider Call ID Boundary",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            raw_call_id = "provider-id token=provider-call-id-secret\n" + ("A" * 260)

            class FakeCallIdHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "native provider call-id boundary",
                                    "tool_calls": [
                                        {
                                            "id": raw_call_id,
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-call-id-boundary", "value": "bounded provider call id accepted"}),
                                            },
                                        }
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                return FakeCallIdHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-call-id-boundary",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-call-id-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native provider call id boundary"')
                payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(payload.get("mode"), "plan_only")
                call_metadata = payload.get("tool_calls", [{}])[0].get("metadata", {})
                provider_call_id = call_metadata.get("provider_tool_call_id", "")
                self.assertLessEqual(len(provider_call_id), 200)
                self.assertNotIn("\n", provider_call_id)
                self.assertIn("token=<REDACTED>", provider_call_id)
                self.assertIn("...[truncated]", provider_call_id)
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("provider_call_id_redaction_bounds"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("provider_call_id_redaction_bounds"), status)
                artifact_paths = payload.get("artifacts", {}) if isinstance(payload.get("artifacts"), dict) else {}
                transcript_text = ""
                for artifact in artifact_paths.values():
                    path = Path(str(artifact))
                    if path.is_file():
                        transcript_text += path.read_text(encoding="utf-8")
                transcript_rel = Path(artifact_paths.get("json", "")).relative_to(runtime.registry.harness.store.root).as_posix()
                transcript_detail = runtime.registry.run("get_auto_transcript", {"path": transcript_rel, "max_ledger": 5}).to_dict()
                transcript_call_id = transcript_detail.get("data", {}).get("summary", {}).get("tool_calls", [{}])[0].get("provider_tool_call_id", "")
                combined = planned + json.dumps(payload) + transcript_text + json.dumps(transcript_detail) + json.dumps(status)
                self.assertEqual(transcript_call_id, provider_call_id)
                self.assertNotIn("provider-call-id-secret", combined)
                self.assertNotIn("A" * 210, combined)
                self.assertNotIn("\nAAAAAAAAAA", combined)
            finally:
                runtime.close()

    def test_model_plan_rejects_duplicate_provider_call_ids_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Provider Call ID Uniqueness",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "duplicate-provider-call-id-should-not-run.txt"
            raw_call_id = "duplicate-native-id token=duplicate-provider-secret\n" + ("D" * 260)

            class FakeDuplicateProviderCallIdAdapter(BaseModelAdapter):
                provider = "fake-duplicate-provider-call-id"

                def generate_tool_plan(self, prompt: str, tool_specs: list[dict], *, allow_command_execution: bool = False, context: str = "") -> ModelResponse:
                    command = f"python -c \"from pathlib import Path; Path({str(marker)!r}).write_text('should-not-run', encoding='utf-8')\""
                    return ModelResponse(
                        provider=self.provider,
                        role="impact",
                        content=json.dumps({
                            "summary": "fake native planner reused a provider call id",
                            "tool_calls": [
                                {
                                    "tool": "remember",
                                    "args": {"key": "duplicate-call-id", "value": "first duplicate id call accepted"},
                                    "reason": "first use of a provider call id is allowed",
                                    "metadata": {"provider_tool_call_id": raw_call_id, "native_tool_call_source": "fake native metadata"},
                                },
                                {
                                    "tool": "run_command",
                                    "args": {"target": "app.example.test", "purpose": "duplicate provider call id boundary", "command": command, "execute": True},
                                    "reason": "duplicate provider call id must be rejected before dispatch",
                                    "metadata": {"provider_tool_call_id": raw_call_id, "native_tool_call_source": "fake native metadata"},
                                },
                                {
                                    "tool": "list_tasks",
                                    "args": {"status": "all", "limit": "1"},
                                    "reason": "unique call id should still be accepted",
                                    "metadata": {"provider_tool_call_id": "unique-native-id", "native_tool_call_source": "fake native metadata"},
                                },
                            ],
                            "warnings": [],
                        }),
                        raw={"model": "fake-duplicate-provider-call-id", "native_tool_calls": True, "native_tool_call_count": 3, "rejected_native_tool_call_count": 0},
                    )

                def generate(self, role: str, prompt: str, context: str = "") -> ModelResponse:
                    return ModelResponse(provider=self.provider, role=role, content=f"fake {role} response")

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-provider-call-id-uniqueness",
                    auto_model_planning=True,
                ),
                adapter=FakeDuplicateProviderCallIdAdapter(),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="native duplicate provider call id boundary"')
                payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(payload.get("mode"), "plan_only")
                self.assertEqual([call["tool"] for call in payload.get("tool_calls", [])], ["remember", "list_tasks"])
                call_metadata = [call.get("metadata", {}) for call in payload.get("tool_calls", [])]
                provider_call_id = call_metadata[0].get("provider_tool_call_id", "")
                self.assertLessEqual(len(provider_call_id), 200)
                self.assertNotIn("\n", provider_call_id)
                self.assertIn("token=<REDACTED>", provider_call_id)
                self.assertIn("...[truncated]", provider_call_id)
                self.assertEqual(call_metadata[1].get("provider_tool_call_id"), "unique-native-id")
                rejected_blob = json.dumps(payload.get("rejected_tool_calls", []))
                self.assertIn("Duplicate provider tool call id skipped before dispatch", rejected_blob)
                self.assertEqual(payload.get("metadata", {}).get("duplicate_provider_tool_call_id_count"), 1)
                self.assertTrue(payload.get("metadata", {}).get("provider_tool_call_id_uniqueness_enforced"))

                applied = runtime.handle_message('/auto apply=true model=true prompt="native duplicate provider call id boundary"')
                apply_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual([item["result"]["status"] for item in apply_payload.get("results", [])], ["ok", "ok"])
                ledger = apply_payload.get("execution_ledger", [])
                self.assertEqual([item.get("provider_tool_call_id") for item in ledger], [provider_call_id, "unique-native-id"])
                self.assertFalse(marker.exists())
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("provider_call_id_uniqueness_enforced"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("provider_call_id_uniqueness"), status)
                combined = planned + applied + rejected_blob + json.dumps(payload) + json.dumps(apply_payload) + json.dumps(status)
                self.assertNotIn("duplicate-provider-secret", combined)
                self.assertNotIn("D" * 210, combined)
                self.assertNotIn("\nDDDDDD", combined)
            finally:
                runtime.close()

    def test_openai_responses_adapter_native_tool_plan_uses_responses_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native OpenAI Responses Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_requests = []
            dry_run_marker = tmp_path / "native-openai-responses-should-not-execute.txt"
            result_marker = "RESPONSES_ENDPOINT_RESULT_SHOULD_NOT_SURFACE"
            result_alias_marker = "RESPONSES_CAMEL_RESULT_SHOULD_NOT_SURFACE"
            hosted_marker = "RESPONSES_HOSTED_TOOL_INPUT_SHOULD_NOT_SURFACE"

            class FakeResponsesHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "native Responses endpoint plan token=responses-endpoint-secret",
                        "output": [
                            {
                                "type": "function_call",
                                "call_id": "responses_endpoint_memory",
                                "name": "remember",
                                "arguments": json.dumps({"key": "native-openai-responses", "value": "Responses endpoint native tool call translated"}),
                            },
                            {
                                "type": "function_call",
                                "call_id": "responses_endpoint_dry",
                                "name": "run_command",
                                "arguments": json.dumps({
                                    "target": "app.example.test",
                                    "purpose": "Responses endpoint dry-run validation",
                                    "command": f"printf native-openai-responses > {dry_run_marker}",
                                    "execute": True,
                                }),
                            },
                            {
                                "type": "file_search_call",
                                "id": "responses_endpoint_file_search",
                                "name": "file_search",
                                "queries": [hosted_marker + " token=responses-hosted-secret"],
                            },
                            {
                                "type": "mcp_call",
                                "id": "responses_endpoint_mcp",
                                "name": "remote_mcp_tool",
                                "arguments": {"query": hosted_marker + " nested token=responses-hosted-secret"},
                            },
                            {"type": "function_call_output", "call_id": "responses_endpoint_result", "output": result_marker + " token=responses-endpoint-secret"},
                            {"type": "functionCallOutput", "callId": "responses_endpoint_result_camel", "output": result_alias_marker + " token=responses-endpoint-secret"},
                            {"toolCallResult": {"content": result_alias_marker + " token=responses-endpoint-secret"}},
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_requests.append({
                    "url": request.full_url,
                    "payload": json.loads(request.data.decode("utf-8")),
                    "headers": dict(request.header_items()),
                })
                return FakeResponsesHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-openai-responses-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAIResponsesAdapter(model="fake-native-responses-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native Responses endpoint token=responses-endpoint-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    metadata = plan_payload.get("metadata", {})
                    self.assertEqual(metadata.get("provider"), "openai-responses")
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)
                    self.assertEqual(metadata.get("rejected_native_tool_call_count"), 2)
                    rejected_blob = json.dumps(plan_payload.get("rejected_tool_calls", []))
                    self.assertIn("file_search_call", rejected_blob)
                    self.assertIn("mcp_call", rejected_blob)
                    self.assertIn("provider-hosted tools must be exposed", rejected_blob)
                    self.assertNotIn(hosted_marker, planned + rejected_blob + json.dumps(plan_payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native Responses endpoint token=responses-endpoint-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "dry_run"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                recall = runtime.handle_message('/recall query=native-openai-responses')
                self.assertIn("Responses endpoint native tool call translated", recall)
                self.assertTrue(captured_requests)
                first = captured_requests[0]
                self.assertTrue(first["url"].endswith("/responses"), first["url"])
                self.assertNotIn("/chat/completions", first["url"])
                self.assertIn("input", first["payload"])
                self.assertNotIn("messages", first["payload"])
                self.assertEqual(first["payload"].get("tool_choice"), "auto")
                self.assertNotIn("Authorization", first["headers"])
                tool_names = [item.get("name") for item in first["payload"].get("tools", [])]
                self.assertIn("remember", tool_names)
                self.assertNotIn("approve", tool_names)
                self.assertNotIn("deny", tool_names)
                self.assertTrue(all("function" not in item for item in first["payload"].get("tools", [])))
                self.assertEqual([item.get("provider_tool_call_id") for item in apply_ledger], ["responses_endpoint_memory", "responses_endpoint_dry"])
                self.assertEqual(apply_ledger[1].get("native_tool_call_source"), "native provider responses output function_call")
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("milestone_contract", {}).get("responses_api_endpoint_planning"), status)
                self.assertIn("openai_responses_api", status.get("provider_native_tool_call_variants", []))
                self.assertIn("file_search_call", status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("mcp_call", status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("functionCallOutput", status.get("provider_tool_result_block_types_ignored", []))
                self.assertIn("toolCallResult", status.get("provider_tool_result_block_types_ignored", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn(result_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn(result_alias_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn(hosted_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("responses-endpoint-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("responses-hosted-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
            finally:
                runtime.close()

    def test_openai_responses_stream_events_are_assembled_before_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native OpenAI Responses Stream Events",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_requests = []
            dry_run_marker = tmp_path / "native-openai-responses-stream-should-not-execute.txt"
            result_marker = "RESPONSES_STREAM_RESULT_SHOULD_NOT_SURFACE"

            class FakeResponsesStreamHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    memory_args = json.dumps({"key": "native-openai-responses-stream", "value": "Responses stream events assembled"})
                    run_args = json.dumps({
                        "target": "app.example.test",
                        "purpose": "Responses stream dry-run validation",
                        "command": f"printf native-openai-responses-stream > {dry_run_marker}",
                        "execute": True,
                    })
                    return json.dumps({
                        "events": [
                            {"type": "response.output_text.delta", "delta": "native Responses stream plan token=responses-stream-secret"},
                            {
                                "type": "response.output_item.added",
                                "item": {
                                    "id": "stream_memory_item",
                                    "type": "function_call",
                                    "call_id": "responses_stream_memory",
                                    "name": "remember",
                                    "arguments": memory_args[:30],
                                },
                            },
                            {"type": "response.function_call_arguments.delta", "item_id": "stream_memory_item", "delta": memory_args[30:]},
                            {
                                "type": "response.output_item.added",
                                "item": {
                                    "id": "stream_dry_item",
                                    "type": "function_call",
                                    "call_id": "responses_stream_dry",
                                    "name": "run_command",
                                    "arguments": "",
                                },
                            },
                            {"type": "response.function_call_arguments.done", "item_id": "stream_dry_item", "arguments": run_args},
                            {"type": "response.output_item.done", "item": {"id": "stream_result", "type": "function_call_output", "output": result_marker + " token=responses-stream-secret"}},
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_requests.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesStreamHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-openai-responses-stream-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAIResponsesAdapter(model="fake-native-responses-stream-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native Responses stream token=responses-stream-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(plan_payload["tool_calls"][0]["args"]["value"], "Responses stream events assembled")
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    self.assertTrue(all("native provider responses stream function_call" in call.get("reason", "") for call in plan_payload["tool_calls"]))
                    self.assertIn("tool_result", json.dumps(plan_payload.get("warnings", [])).lower())

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native Responses stream token=responses-stream-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "dry_run"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                recall = runtime.handle_message('/recall query=native-openai-responses-stream')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses stream events assembled", recall)
                self.assertEqual([item.get("provider_tool_call_id") for item in apply_ledger], ["responses_stream_memory", "responses_stream_dry"])
                self.assertEqual([item.get("native_tool_call_source") for item in apply_ledger], ["native provider responses stream function_call", "native provider responses stream function_call"])
                self.assertTrue(status.get("milestone_contract", {}).get("responses_stream_event_function_call_translation"), status)
                self.assertIn("responses_stream_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_requests)
                self.assertEqual(captured_requests[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn(result_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("responses-stream-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload) + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_responses_raw_sse_stream_events_are_assembled_before_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native OpenAI Responses Raw SSE Stream Events",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_requests = []
            dry_run_marker = tmp_path / "native-openai-responses-sse-should-not-execute.txt"
            result_marker = "RESPONSES_SSE_RESULT_SHOULD_NOT_SURFACE"

            class FakeResponsesRawSSEHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    memory_args = json.dumps({"key": "native-openai-responses-sse", "value": "Responses raw SSE events assembled"})
                    run_args = json.dumps({
                        "target": "app.example.test",
                        "purpose": "Responses raw SSE dry-run validation",
                        "command": f"printf native-openai-responses-sse > {dry_run_marker}",
                        "execute": True,
                    })
                    frames = [
                        ("response.output_text.delta", {"type": "response.output_text.delta", "delta": "native Responses raw SSE plan token=responses-sse-secret"}),
                        (
                            "response.output_item.added",
                            {
                                "type": "response.output_item.added",
                                "item": {
                                    "id": "sse_memory_item",
                                    "type": "function_call",
                                    "call_id": "responses_sse_memory",
                                    "name": "remember",
                                    "arguments": memory_args[:32],
                                },
                            },
                        ),
                        ("response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "item_id": "sse_memory_item", "delta": memory_args[32:]}),
                        (
                            "response.output_item.added",
                            {
                                "type": "response.output_item.added",
                                "item": {
                                    "id": "sse_dry_item",
                                    "type": "function_call",
                                    "call_id": "responses_sse_dry",
                                    "name": "run_command",
                                    "arguments": "",
                                },
                            },
                        ),
                        ("response.function_call_arguments.done", {"type": "response.function_call_arguments.done", "item_id": "sse_dry_item", "arguments": run_args}),
                        (
                            "response.output_item.done",
                            {
                                "type": "response.output_item.done",
                                "item": {
                                    "id": "sse_result",
                                    "type": "function_call_output",
                                    "call_id": "responses_sse_result",
                                    "output": result_marker + " token=responses-sse-secret",
                                },
                            },
                        ),
                    ]
                    body = "".join(
                        f"event: {event_name}\nid: sse-{index}\ndata: {json.dumps(data)}\n\n"
                        for index, (event_name, data) in enumerate(frames, start=1)
                    ) + "data: [DONE]\n\n"
                    return body.encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_requests.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesRawSSEHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-openai-responses-sse-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAIResponsesAdapter(model="fake-native-responses-sse-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native Responses raw SSE token=responses-sse-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(plan_payload["tool_calls"][0]["args"]["value"], "Responses raw SSE events assembled")
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    self.assertTrue(all("native provider responses stream function_call" in call.get("reason", "") for call in plan_payload["tool_calls"]))
                    self.assertIn("tool_result", json.dumps(plan_payload.get("warnings", [])).lower())

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native Responses raw SSE token=responses-sse-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "dry_run"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                recall = runtime.handle_message('/recall query=native-openai-responses-sse')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses raw SSE events assembled", recall)
                self.assertEqual([item.get("provider_tool_call_id") for item in apply_ledger], ["responses_sse_memory", "responses_sse_dry"])
                self.assertEqual([item.get("native_tool_call_source") for item in apply_ledger], ["native provider responses stream function_call", "native provider responses stream function_call"])
                self.assertTrue(status.get("milestone_contract", {}).get("responses_stream_sse_capture_translation"), status)
                self.assertIn("responses_stream_sse_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_requests)
                self.assertEqual(captured_requests[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn(result_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("responses-sse-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload) + json.dumps(status))
            finally:
                runtime.close()

    def test_gemini_adapter_native_tool_plan_uses_generate_content_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Gemini Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_requests = []
            dry_run_marker = tmp_path / "native-gemini-should-not-execute.txt"
            result_marker = "GEMINI_FUNCTION_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeGeminiHTTPResponse:
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
                                        {"text": "native Gemini plan token=gemini-endpoint-secret"},
                                        {
                                            "functionCall": {
                                                "name": "remember",
                                                "args": {"key": "native-gemini", "value": "Gemini GenerateContent native functionCall translated"},
                                            },
                                        },
                                        {
                                            "functionCall": {
                                                "name": "run_command",
                                                "args": {
                                                    "target": "app.example.test",
                                                    "purpose": "Gemini GenerateContent dry-run validation",
                                                    "command": f"printf native-gemini > {dry_run_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                        {"functionResponse": {"name": "run_command", "response": {"content": result_marker + " token=gemini-endpoint-secret"}}},
                                    ]
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_requests.append({
                    "url": request.full_url,
                    "payload": json.loads(request.data.decode("utf-8")),
                    "headers": dict(request.header_items()),
                })
                return FakeGeminiHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-gemini-runtime",
                    auto_model_planning=True,
                ),
                adapter=GeminiAdapter(model="fake-gemini-model", base_url="http://127.0.0.1:9/v1beta"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native Gemini endpoint token=gemini-endpoint-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    self.assertTrue(plan_payload["tool_calls"][1]["validation"].get("schema_validated"))
                    metadata = plan_payload.get("metadata", {})
                    self.assertEqual(metadata.get("provider"), "gemini")
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native Gemini endpoint token=gemini-endpoint-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "dry_run"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                recall = runtime.handle_message('/recall query=native-gemini')
                self.assertIn("Gemini GenerateContent native functionCall translated", recall)
                self.assertTrue(captured_requests)
                first = captured_requests[0]
                self.assertTrue(first["url"].endswith("/models/fake-gemini-model:generateContent"), first["url"])
                self.assertNotIn("key=", first["url"])
                self.assertIn("contents", first["payload"])
                self.assertIn("systemInstruction", first["payload"])
                self.assertNotIn("messages", first["payload"])
                self.assertNotIn("input", first["payload"])
                declarations = first["payload"].get("tools", [{}])[0].get("functionDeclarations", [])
                declaration_names = [item.get("name") for item in declarations if isinstance(item, dict)]
                self.assertIn("remember", declaration_names)
                self.assertNotIn("approve", declaration_names)
                self.assertNotIn("deny", declaration_names)
                self.assertEqual(first["payload"].get("toolConfig", {}).get("functionCallingConfig", {}).get("mode"), "AUTO")
                self.assertNotIn("Authorization", first["headers"])
                self.assertEqual([item.get("native_tool_call_source") for item in apply_ledger], ["native provider candidate functionCall", "native provider candidate functionCall"])
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("milestone_contract", {}).get("gemini_generate_content_planning"), status)
                self.assertIn("gemini_generate_content", status.get("provider_native_tool_call_variants", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn(result_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("gemini-endpoint-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
            finally:
                runtime.close()

    def test_anthropic_messages_adapter_native_tool_plan_uses_messages_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Anthropic Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_requests = []
            dry_run_marker = tmp_path / "native-anthropic-should-not-execute.txt"
            result_marker = "ANTHROPIC_TOOL_RESULT_SHOULD_NOT_SURFACE"

            class FakeAnthropicHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "type": "message",
                        "content": [
                            {"type": "text", "text": "native Anthropic plan token=anthropic-endpoint-secret"},
                            {
                                "type": "tool_use",
                                "id": "anthropic_memory",
                                "name": "remember",
                                "input": {"key": "native-anthropic", "value": "Anthropic Messages native tool_use translated"},
                            },
                            {
                                "type": "tool_use",
                                "id": "anthropic_dry",
                                "name": "run_command",
                                "input": {
                                    "target": "app.example.test",
                                    "purpose": "Anthropic Messages dry-run validation",
                                    "command": f"printf native-anthropic > {dry_run_marker}",
                                    "execute": True,
                                },
                            },
                            {"type": "tool_result", "tool_use_id": "anthropic_result", "content": result_marker + " token=anthropic-endpoint-secret"},
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_requests.append({
                    "url": request.full_url,
                    "payload": json.loads(request.data.decode("utf-8")),
                    "headers": dict(request.header_items()),
                })
                return FakeAnthropicHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-anthropic-runtime",
                    auto_model_planning=True,
                ),
                adapter=AnthropicMessagesAdapter(
                    model="fake-anthropic-model",
                    base_url="http://127.0.0.1:9/v1",
                    key_env="PHOBOS_TEST_NO_SUCH_ANTHROPIC_KEY",
                ),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native Anthropic endpoint token=anthropic-endpoint-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "run_command"])
                    self.assertFalse(plan_payload["tool_calls"][1]["args"]["execute"])
                    metadata = plan_payload.get("metadata", {})
                    self.assertEqual(metadata.get("provider"), "anthropic")
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native Anthropic endpoint token=anthropic-endpoint-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "dry_run"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                recall = runtime.handle_message('/recall query=native-anthropic')
                self.assertIn("Anthropic Messages native tool_use translated", recall)
                self.assertTrue(captured_requests)
                first = captured_requests[0]
                first_headers = {str(key).lower(): value for key, value in first["headers"].items()}
                self.assertTrue(first["url"].endswith("/messages"), first["url"])
                self.assertIn("messages", first["payload"])
                self.assertIn("system", first["payload"])
                self.assertNotIn("input", first["payload"])
                self.assertEqual(first["payload"].get("tool_choice"), {"type": "auto"})
                self.assertIn("anthropic-version", first_headers)
                self.assertNotIn("x-api-key", first_headers)
                tools = first["payload"].get("tools", [])
                tool_names = [item.get("name") for item in tools if isinstance(item, dict)]
                self.assertIn("remember", tool_names)
                self.assertNotIn("approve", tool_names)
                self.assertNotIn("deny", tool_names)
                self.assertTrue(all("input_schema" in item for item in tools if isinstance(item, dict)))
                self.assertTrue(all("parameters" not in item for item in tools if isinstance(item, dict)))
                self.assertEqual([item.get("provider_tool_call_id") for item in apply_ledger], ["anthropic_memory", "anthropic_dry"])
                self.assertEqual([item.get("native_tool_call_source") for item in apply_ledger], ["native provider anthropic messages content tool_use", "native provider anthropic messages content tool_use"])
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("milestone_contract", {}).get("anthropic_messages_api_planning"), status)
                self.assertIn("anthropic_messages_api", status.get("provider_native_tool_call_variants", []))
                self.assertIn("anthropic_messages_tool_use", status.get("provider_native_tool_call_variants", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn(result_marker, planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
                self.assertNotIn("anthropic-endpoint-secret", planned + applied + recall + json.dumps(plan_payload) + json.dumps(apply_payload))
            finally:
                runtime.close()

    def test_openai_native_tool_call_edge_cases_keep_rejected_calls_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native OpenAI Tool Call Edges",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            custom_input_marker = "CUSTOM_NATIVE_TOOL_INPUT_SHOULD_NOT_SURFACE"
            result_alias_marker = "PROVIDER_CAMEL_RESULT_CONTENT_SHOULD_NOT_SURFACE"

            class FakeEdgeHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "native provider edge response token=edge-secret",
                                    "tool_calls": [
                                        "not-an-object",
                                        {"id": "call_non_function", "type": "file_search", "function": {"name": "remember", "arguments": "{}"}},
                                        {"id": "call_bad_json", "type": "function", "function": {"name": "remember", "arguments": "{not json token=edge-secret}"}},
                                        {"id": "call_non_object", "type": "function", "function": {"name": "remember", "arguments": json.dumps(["not", "object"])}},
                                        {"id": "call_tool_result", "type": "tool_result", "content": "PROVIDER_RESULT_CONTENT_SHOULD_NOT_SURFACE"},
                                        {"id": "call_tool_result_camel", "type": "toolResult", "content": result_alias_marker + " token=edge-secret"},
                                        {"id": "call_function_result_alias", "functionResult": {"content": result_alias_marker + " token=edge-secret"}},
                                        {"id": "call_custom_freeform", "type": "custom_tool_call", "name": "run_command", "input": custom_input_marker + " token=edge-secret"},
                                        {
                                            "id": "call_valid_memory",
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-edge", "value": "legacy/native edge case accepted"}),
                                            },
                                        },
                                    ],
                                    "function_call": {"name": "list_tasks", "arguments": json.dumps({"status": "all", "limit": "1"})},
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeEdgeHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-openai-edge-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-edge-model", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native provider edge cases token=edge-secret"')
                    plan_payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(plan_payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertIn("native provider tool_call", plan_payload["tool_calls"][0]["reason"])
                    self.assertIn("legacy native function_call", plan_payload["tool_calls"][1]["reason"])
                    self.assertTrue(plan_payload["tool_calls"][1]["validation"].get("schema_validated"))
                    call_metadata = [call.get("metadata", {}) for call in plan_payload["tool_calls"]]
                    self.assertEqual(call_metadata[1].get("native_tool_call_source"), "legacy native function_call")
                    self.assertEqual(call_metadata[1].get("native_tool_call_index"), 7)
                    rejected_blob = json.dumps(plan_payload.get("rejected_tool_calls", []))
                    self.assertIn("Native tool call must be an object", rejected_blob)
                    self.assertIn("Only function tool calls are supported", rejected_blob)
                    self.assertIn("Native tool arguments were not valid JSON", rejected_blob)
                    self.assertIn("Native tool arguments must decode to a JSON object", rejected_blob)
                    self.assertIn("Custom/freeform native tool calls are not supported", rejected_blob)
                    self.assertIn("tool_result", json.dumps(plan_payload.get("warnings", [])).lower())
                    self.assertIn("custom/freeform", json.dumps(plan_payload.get("warnings", [])).lower())
                    self.assertNotIn("PROVIDER_RESULT_CONTENT_SHOULD_NOT_SURFACE", planned + rejected_blob + json.dumps(plan_payload))
                    self.assertNotIn(result_alias_marker, planned + rejected_blob + json.dumps(plan_payload))
                    self.assertNotIn(custom_input_marker, planned + rejected_blob + json.dumps(plan_payload))
                    metadata = plan_payload.get("metadata", {})
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)
                    self.assertGreaterEqual(metadata.get("rejected_native_tool_call_count", 0), 5)
                    self.assertNotIn("edge-secret", planned)
                    self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native provider edge cases token=edge-secret"')
                    apply_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["ok", "ok"])
                    apply_ledger = apply_payload.get("execution_ledger", [])
                    self.assertEqual(apply_ledger[1].get("native_tool_call_source"), "legacy native function_call")
                recall = runtime.handle_message('/recall query=native-edge')
                self.assertIn("legacy/native edge case accepted", recall)
                self.assertNotIn("edge-secret", applied + recall)
                self.assertNotIn(result_alias_marker, applied + recall)
                self.assertTrue(captured_payloads)
                self.assertIn("tools", captured_payloads[0])
                self.assertNotIn("approve", [item["function"]["name"] for item in captured_payloads[0].get("tools", [])])
                self.assertNotIn("deny", [item["function"]["name"] for item in captured_payloads[0].get("tools", [])])
            finally:
                runtime.close()

    def test_openai_native_hosted_tool_calls_are_rejected_without_leaking_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Hosted Tool Call Rejection",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            hosted_input_marker = "HOSTED_NATIVE_TOOL_INPUT_SHOULD_NOT_SURFACE"

            class FakeHostedHTTPResponse:
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
                                        {"type": "text", "text": "native hosted tool plan token=hosted-secret"},
                                        {
                                            "type": "server_tool_use",
                                            "tool_use_id": "hosted_search",
                                            "name": "web_search",
                                            "input": hosted_input_marker + " token=hosted-secret",
                                        },
                                        {
                                            "type": "mcp_tool_use",
                                            "tool_use_id": "hosted_mcp",
                                            "name": "mcp_browser",
                                            "input": {"query": hosted_input_marker + " nested token=hosted-secret"},
                                        },
                                        {
                                            "type": "file_search_call",
                                            "id": "hosted_file_search",
                                            "name": "file_search",
                                            "queries": [hosted_input_marker + " file token=hosted-secret"],
                                        },
                                        {
                                            "type": "image_generation_call",
                                            "id": "hosted_image_generation",
                                            "name": "image_generation",
                                            "prompt": hosted_input_marker + " image token=hosted-secret",
                                        },
                                        {
                                            "type": "local_shell_call",
                                            "id": "hosted_local_shell",
                                            "name": "local_shell",
                                            "input": {"command": "printf " + hosted_input_marker + " token=hosted-secret"},
                                        },
                                        {
                                            "type": "mcp_call",
                                            "id": "hosted_mcp_call",
                                            "name": "remote_mcp_tool",
                                            "arguments": {"query": hosted_input_marker + " mcp token=hosted-secret"},
                                        },
                                        {
                                            "type": "tool_use",
                                            "tool_call_id": "hosted_valid_memory",
                                            "name": "remember",
                                            "input": {"key": "native-hosted-reject", "value": "hosted rejection boundary kept valid registered calls"},
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeHostedHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-hosted-rejection",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-hosted", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native hosted tool calls token=hosted-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-hosted-reject")
                    rejected_blob = json.dumps(payload.get("rejected_tool_calls", []))
                    warning_blob = json.dumps(payload.get("warnings", []))
                    self.assertIn("provider-hosted tools must be exposed", rejected_blob)
                    for native_type in ("server_tool_use", "mcp_tool_use", "file_search_call", "image_generation_call", "local_shell_call", "mcp_call"):
                        self.assertIn(native_type, rejected_blob)
                    self.assertIn("custom/freeform/hosted", warning_blob)
                    self.assertNotIn(hosted_input_marker, planned + rejected_blob + json.dumps(payload))
                    self.assertNotIn("hosted-secret", planned)
                    self.assertEqual(payload.get("metadata", {}).get("rejected_native_tool_call_count"), 6)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native hosted tool calls token=hosted-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                recall = runtime.handle_message('/recall query=native-hosted-reject')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("hosted rejection boundary kept valid registered calls", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("provider_hosted_tool_calls_rejected"), status)
                for native_type in ("server_tool_use", "mcp_tool_use", "file_search_call", "image_generation_call", "local_shell_call", "mcp_call"):
                    self.assertIn(native_type, status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("hosted-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_tool_role_messages_are_result_echoes_not_plans(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Tool Role Result Echo",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            role_result_marker = "ROLE_TOOL_RESULT_SHOULD_NOT_SURFACE"
            captured_payloads = []

            class FakeRoleResultHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "role": "tool",
                                    "tool_call_id": "role_result_echo",
                                    "content": role_result_marker + " token=role-result-secret",
                                    "tool_calls": [
                                        {
                                            "id": "role_echo_should_not_dispatch",
                                            "type": "tool_call",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "role-result-echo", "value": "should not store"}),
                                            },
                                        }
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRoleResultHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-role-result-echo",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-role-result", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native role result echo token=role-result-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual(payload["tool_calls"], [])
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertFalse(payload.get("metadata", {}).get("native_tool_calls"), payload.get("metadata"))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native role result echo token=role-result-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual(applied_payload.get("results"), [])
                    self.assertEqual(applied_payload.get("execution_ledger"), [])
                recall = runtime.handle_message('/recall query=role-result-echo')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Found 0 memory entries", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("provider_result_role_messages_ignored"), status)
                self.assertIn("tool", status.get("provider_tool_result_message_roles_ignored", []))
                self.assertTrue(captured_payloads)
                self.assertNotIn(role_result_marker, planned + applied + recall + json.dumps(payload) + json.dumps(applied_payload) + json.dumps(status))
                self.assertNotIn("role-result-secret", planned + applied + recall + json.dumps(payload) + json.dumps(applied_payload) + json.dumps(status))
            finally:
                runtime.close()

            root_role_result_marker = "ROOT_ROLE_FUNCTION_RESULT_SHOULD_NOT_SURFACE"
            root_captured_payloads = []

            class FakeRootRoleResultHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "role": "function",
                        "name": "remember",
                        "content": root_role_result_marker + " token=root-role-result-secret",
                        "tool_calls": [
                            {
                                "id": "root_role_echo_should_not_dispatch",
                                "type": "tool_call",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "root-role-result-echo", "value": "should not store"}),
                                },
                            }
                        ],
                    }).encode("utf-8")

            def fake_root_urlopen(request, timeout=0):
                root_captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootRoleResultHTTPResponse()

            root_runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "root-role-agent.db"),
                    session_name="native-root-role-result-echo",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-role-result", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_root_urlopen):
                    root_planned = root_runtime.handle_message('/auto model=true prompt="native root role result echo token=root-role-result-secret"')
                    root_payload = json.loads(root_planned.split("\n", 1)[1])
                    self.assertEqual(root_payload["mode"], "plan_only")
                    self.assertEqual(root_payload["tool_calls"], [])
                    self.assertIn("tool_result", json.dumps(root_payload.get("warnings", [])).lower())
                    self.assertFalse(root_payload.get("metadata", {}).get("native_tool_calls"), root_payload.get("metadata"))

                    root_applied = root_runtime.handle_message('/auto apply=true model=true prompt="native root role result echo token=root-role-result-secret"')
                    root_applied_payload = json.loads(root_applied.split("\n", 1)[1])
                    self.assertEqual(root_applied_payload.get("results"), [])
                    self.assertEqual(root_applied_payload.get("execution_ledger"), [])
                root_recall = root_runtime.handle_message('/recall query=root-role-result-echo')
                root_status = root_runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Found 0 memory entries", root_recall)
                self.assertIn("function", root_status.get("provider_tool_result_message_roles_ignored", []))
                self.assertTrue(root_captured_payloads)
                root_output_blob = root_planned + root_applied + root_recall + json.dumps(root_payload) + json.dumps(root_applied_payload) + json.dumps(root_status)
                self.assertNotIn(root_role_result_marker, root_output_blob)
                self.assertNotIn("root-role-result-secret", root_output_blob)
            finally:
                root_runtime.close()

    def test_openai_native_flat_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Flat Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-flat-should-not-run.txt"

            class FakeFlatHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "native flat provider plan token=flat-secret",
                                    "tool_calls": [
                                        {
                                            "id": "flat_memory",
                                            "type": "tool_call",
                                            "name": "remember",
                                            "arguments": {"key": "native-flat", "value": "flat native tool call accepted"},
                                        },
                                        {
                                            "call_id": "flat_dry_run",
                                            "type": "function",
                                            "function": "run_command",
                                            "args": {
                                                "target": "app.example.test",
                                                "purpose": "flat native dry-run boundary",
                                                "command": f"printf native-flat > {dry_run_marker}",
                                                "execute": True,
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeFlatHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-flat-tool-calls",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-flat", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native flat tool call token=flat-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertIn("native provider flat tool_call", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider flat tool_call", payload["tool_calls"][1]["reason"])
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["flat_memory", "flat_dry_run"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider flat tool_call", "native provider flat tool_call"])
                    metadata = payload.get("metadata", {})
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)
                    self.assertEqual(metadata.get("rejected_native_tool_call_count", 0), 0)
                    self.assertNotIn("flat-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native flat tool call token=flat-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual(ledger[1]["execution_state"], "dry_run_not_executed")
                    self.assertFalse(ledger[1]["actual_command_or_process_activity"])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["flat_memory", "flat_dry_run"])
                    self.assertEqual(ledger[1].get("native_tool_call_source"), "native provider flat tool_call")
                recall = runtime.handle_message('/recall query=native-flat')
                self.assertIn("flat native tool call accepted", recall)
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertIn("tools", captured_payloads[0])
                self.assertNotIn("flat-secret", applied + recall)
            finally:
                runtime.close()

    def test_openai_native_tool_calls_nested_functioncall_and_tooluse_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Nested Tool Call Aliases",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-nested-tool-calls-should-not-run.txt"

            class FakeNestedAliasHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "native nested provider tool_calls plan token=nested-tool-call-secret",
                                    "tool_calls": [
                                        {
                                            "id": "nested_functioncall_memory",
                                            "type": "functionCall",
                                            "functionCall": {
                                                "toolName": "remember",
                                                "args": {"key": "native-nested-functioncall", "value": "nested functionCall in tool_calls accepted"},
                                            },
                                        },
                                        {
                                            "toolUseId": "nested_tooluse_tasks",
                                            "type": "toolUse",
                                            "toolUse": {
                                                "functionName": "list_tasks",
                                                "inputJson": {"status": "all", "limit": "1"},
                                            },
                                        },
                                        {
                                            "callId": "nested_tooluse_dry",
                                            "type": "tool_call",
                                            "toolUse": {
                                                "name": "run_command",
                                                "input": {
                                                    "target": "app.example.test",
                                                    "purpose": "nested toolUse dry-run boundary",
                                                    "command": f"printf native-nested-tool-call > {dry_run_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeNestedAliasHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-nested-tool-call-aliases",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-nested-tool-calls", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native nested tool_calls token=nested-tool-call-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "run_command"])
                    self.assertIn("native provider tool_call nested functionCall", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider tool_call nested toolUse", payload["tool_calls"][1]["reason"])
                    self.assertFalse(payload["tool_calls"][2]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["nested_functioncall_memory", "nested_tooluse_tasks", "nested_tooluse_dry"])
                    self.assertEqual(
                        [item.get("native_tool_call_source") for item in call_metadata],
                        ["native provider tool_call nested functionCall", "native provider tool_call nested toolUse", "native provider tool_call nested toolUse"],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertNotIn("nested-tool-call-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native nested tool_calls token=nested-tool-call-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["nested_functioncall_memory", "nested_tooluse_tasks", "nested_tooluse_dry"])
                    self.assertFalse(ledger[2].get("actual_command_or_process_activity"))
                    self.assertEqual(ledger[2].get("native_tool_call_source"), "native provider tool_call nested toolUse")
                recall = runtime.handle_message('/recall query=native-nested-functioncall')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("nested functionCall in tool_calls accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("tool_calls_nested_alias_translation"), status)
                self.assertIn("tool_calls_nested_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("tool_calls_nested_toolUse", status.get("provider_native_tool_call_variants", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("nested-tool-call-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_argument_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Argument Alias Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeArgumentAliasHTTPResponse:
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
                                        {"type": "text", "text": "native argument alias plan token=alias-secret"},
                                        {
                                            "type": "tool_use",
                                            "tool_use_id": "alias_content_tasks",
                                            "toolName": "list_tasks",
                                            "inputJson": {"status": "all", "limit": "1"},
                                        },
                                    ],
                                    "tool_calls": [
                                        {
                                            "id": "alias_memory",
                                            "type": "function",
                                            "function": {
                                                "functionName": "remember",
                                                "arguments_json": {"key": "native-argument-alias", "value": "argument alias native tool call accepted"},
                                            },
                                        }
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeArgumentAliasHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-argument-aliases",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-argument-aliases", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native argument alias token=alias-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-argument-alias")
                    self.assertEqual(payload["tool_calls"][1]["args"]["status"], "all")
                    self.assertEqual(payload["tool_calls"][1]["args"]["limit"], 1)
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["alias_memory", "alias_content_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider tool_call", "native content-block tool_use"])
                    self.assertNotIn("alias-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native argument alias token=alias-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["alias_memory", "alias_content_tasks"])
                recall = runtime.handle_message('/recall query=native-argument-alias')
                self.assertIn("argument alias native tool call accepted", recall)
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertTrue(status.get("milestone_contract", {}).get("provider_argument_alias_translation"), status)
                self.assertIn("arguments_json", status.get("provider_argument_aliases", []))
                self.assertIn("inputJson", status.get("provider_argument_aliases", []))
                self.assertTrue(status.get("milestone_contract", {}).get("provider_tool_name_alias_translation"), status)
                self.assertIn("toolName", status.get("provider_tool_name_aliases", []))
                self.assertIn("functionName", status.get("provider_tool_name_aliases", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("alias-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_choice_delta_native_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Choice Delta Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "choice-delta-should-not-run.txt"

            class FakeChoiceDeltaHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "delta": {
                                    "content": "native choice delta plan token=choice-delta-secret",
                                    "tool_calls": [
                                        {
                                            "id": "choice_delta_memory",
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-choice-delta", "value": "choice delta native tool call translated"}),
                                            },
                                        },
                                        {
                                            "callId": "choice_delta_dry",
                                            "type": "function",
                                            "function": {
                                                "toolName": "run_command",
                                                "argumentsJson": {
                                                    "target": "app.example.test",
                                                    "purpose": "choice delta native dry-run validation",
                                                    "command": f"printf choice-delta > {dry_run_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeChoiceDeltaHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-choice-delta-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-choice-delta", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native choice delta token=choice-delta-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["choice_delta_memory", "choice_delta_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider choice delta tool_calls", "native provider choice delta tool_calls"])
                    self.assertNotIn("choice-delta-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native choice delta token=choice-delta-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["choice_delta_memory", "choice_delta_dry"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-choice-delta')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("choice delta native tool call translated", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("choice_delta_tool_call_translation"), status)
                self.assertIn("choice_delta_tool_calls", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn("choice-delta-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_choice_delta_fragmented_native_tool_calls_are_assembled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Choice Delta Fragment Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "choice-delta-fragment-should-not-run.txt"

            class FakeChoiceDeltaFragmentHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    memory_args = json.dumps({"key": "native-choice-delta-fragment", "value": "fragmented choice delta native tool call assembled"})
                    run_args = json.dumps({
                        "target": "app.example.test",
                        "purpose": "fragmented choice delta dry-run validation",
                        "command": f"printf choice-delta-fragment > {dry_run_marker}",
                        "execute": True,
                    })
                    memory_chunks = [memory_args[:18], memory_args[18:63], memory_args[63:]]
                    run_chunks = [run_args[:31], run_args[31:104], run_args[104:]]
                    return json.dumps({
                        "choices": [
                            {
                                "delta": {
                                    "content": "native choice delta fragment plan token=choice-fragment-secret",
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "choice_delta_fragment_memory",
                                            "type": "function",
                                            "function": {"name": "remember", "arguments": memory_chunks[0]},
                                        },
                                        {
                                            "index": 1,
                                            "callId": "choice_delta_fragment_dry",
                                            "type": "function",
                                            "function": {"toolName": "run_command", "arguments": run_chunks[0]},
                                        },
                                    ],
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "function": {"arguments": memory_chunks[1]}},
                                        {"index": 1, "function": {"arguments": run_chunks[1]}},
                                    ]
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "function": {"arguments": memory_chunks[2]}},
                                        {"index": 1, "function": {"arguments": run_chunks[2]}},
                                    ]
                                }
                            },
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeChoiceDeltaFragmentHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-choice-delta-fragment-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-choice-delta-fragment", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native choice delta fragment token=choice-fragment-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-choice-delta-fragment")
                    self.assertEqual(payload["tool_calls"][0]["args"]["value"], "fragmented choice delta native tool call assembled")
                    self.assertEqual(payload["tool_calls"][1]["args"]["purpose"], "fragmented choice delta dry-run validation")
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["choice_delta_fragment_memory", "choice_delta_fragment_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider choice delta tool_calls", "native provider choice delta tool_calls"])
                    self.assertNotIn("choice-fragment-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native choice delta fragment token=choice-fragment-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["choice_delta_fragment_memory", "choice_delta_fragment_dry"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-choice-delta-fragment')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("fragmented choice delta native tool call assembled", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("choice_delta_fragment_assembly"), status)
                self.assertIn("choice_delta_tool_call_fragments", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn("choice-fragment-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_choice_delta_fragmented_function_call_aliases_are_assembled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Choice Delta FunctionCall Fragment Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "choice-delta-functioncall-fragment-should-not-run.txt"

            class FakeChoiceDeltaFunctionCallFragmentHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    memory_args = json.dumps({"key": "native-choice-delta-functioncall-fragment", "value": "fragmented choice delta functionCall native call assembled"})
                    run_args = json.dumps({
                        "target": "app.example.test",
                        "purpose": "fragmented choice delta functionCall dry-run validation",
                        "command": f"printf choice-delta-functioncall-fragment > {dry_run_marker}",
                        "execute": True,
                    })
                    memory_chunks = [memory_args[:24], memory_args[24:82], memory_args[82:]]
                    run_chunks = [run_args[:39], run_args[39:122], run_args[122:]]
                    return json.dumps({
                        "choices": [
                            {
                                "delta": {
                                    "content": "native choice delta functionCall fragment plan token=choice-functioncall-fragment-secret",
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "type": "functionCall",
                                            "functionCall": {"functionName": "remember", "callId": "choice_delta_functioncall_fragment_memory", "argsJson": memory_chunks[0]},
                                        },
                                        {
                                            "index": 1,
                                            "type": "function_call",
                                            "function_call": {"toolName": "run_command", "toolCallId": "choice_delta_functioncall_fragment_dry", "argumentsJson": run_chunks[0]},
                                        },
                                    ],
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "functionCall": {"argsJson": memory_chunks[1]}},
                                        {"index": 1, "function_call": {"argumentsJson": run_chunks[1]}},
                                    ]
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "functionCall": {"argsJson": memory_chunks[2]}},
                                        {"index": 1, "function_call": {"argumentsJson": run_chunks[2]}},
                                    ],
                                    "content": [{"type": "tool_result", "content": "FUNCTIONCALL_RESULT_SHOULD_NOT_SURFACE"}],
                                }
                            },
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeChoiceDeltaFunctionCallFragmentHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-choice-delta-functioncall-fragment-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-choice-delta-functioncall-fragment", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native choice delta functionCall fragment token=choice-functioncall-fragment-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-choice-delta-functioncall-fragment")
                    self.assertEqual(payload["tool_calls"][0]["args"]["value"], "fragmented choice delta functionCall native call assembled")
                    self.assertEqual(payload["tool_calls"][1]["args"]["purpose"], "fragmented choice delta functionCall dry-run validation")
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["choice_delta_functioncall_fragment_memory", "choice_delta_functioncall_fragment_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider choice delta tool_calls nested functionCall", "native provider choice delta tool_calls nested function_call"])
                    self.assertNotIn("choice-functioncall-fragment-secret", planned)
                    self.assertNotIn("FUNCTIONCALL_RESULT_SHOULD_NOT_SURFACE", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native choice delta functionCall fragment token=choice-functioncall-fragment-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["choice_delta_functioncall_fragment_memory", "choice_delta_functioncall_fragment_dry"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-choice-delta-functioncall-fragment')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("fragmented choice delta functionCall native call assembled", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("choice_delta_function_call_fragment_assembly"), status)
                self.assertIn("choice_delta_function_call_fragments", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn("choice-functioncall-fragment-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_choice_delta_fragmented_tool_use_aliases_are_assembled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Choice Delta ToolUse Fragment Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "choice-delta-tooluse-fragment-should-not-run.txt"

            class FakeChoiceDeltaToolUseFragmentHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    memory_args = json.dumps({"key": "native-choice-delta-tooluse-fragment", "value": "fragmented choice delta toolUse native call assembled"})
                    run_args = json.dumps({
                        "target": "app.example.test",
                        "purpose": "fragmented choice delta toolUse dry-run validation",
                        "command": f"printf choice-delta-tooluse-fragment > {dry_run_marker}",
                        "execute": True,
                    })
                    memory_chunks = [memory_args[:20], memory_args[20:71], memory_args[71:]]
                    run_chunks = [run_args[:35], run_args[35:110], run_args[110:]]
                    return json.dumps({
                        "choices": [
                            {
                                "delta": {
                                    "content": "native choice delta toolUse fragment plan token=choice-tooluse-fragment-secret",
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "type": "toolUse",
                                            "toolUse": {"toolName": "remember", "toolUseId": "choice_delta_tooluse_fragment_memory", "inputJson": memory_chunks[0]},
                                        },
                                        {
                                            "index": 1,
                                            "type": "tool_use",
                                            "tool_use": {"functionName": "run_command", "tool_use_id": "choice_delta_tooluse_fragment_dry", "argsJson": run_chunks[0]},
                                        },
                                    ],
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "toolUse": {"inputJson": memory_chunks[1]}},
                                        {"index": 1, "tool_use": {"argsJson": run_chunks[1]}},
                                    ]
                                }
                            },
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "toolUse": {"inputJson": memory_chunks[2]}},
                                        {"index": 1, "tool_use": {"argsJson": run_chunks[2]}},
                                    ],
                                    "content": [{"type": "tool_result", "content": "PROVIDER_RESULT_SHOULD_NOT_SURFACE"}],
                                }
                            },
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeChoiceDeltaToolUseFragmentHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-choice-delta-tooluse-fragment-runtime",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-choice-delta-tooluse-fragment", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native choice delta toolUse fragment token=choice-tooluse-fragment-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-choice-delta-tooluse-fragment")
                    self.assertEqual(payload["tool_calls"][0]["args"]["value"], "fragmented choice delta toolUse native call assembled")
                    self.assertEqual(payload["tool_calls"][1]["args"]["purpose"], "fragmented choice delta toolUse dry-run validation")
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["choice_delta_tooluse_fragment_memory", "choice_delta_tooluse_fragment_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider choice delta tool_calls nested toolUse", "native provider choice delta tool_calls nested tool_use"])
                    self.assertNotIn("PROVIDER_RESULT_SHOULD_NOT_SURFACE", planned)
                    self.assertNotIn("choice-tooluse-fragment-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native choice delta toolUse fragment token=choice-tooluse-fragment-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["choice_delta_tooluse_fragment_memory", "choice_delta_tooluse_fragment_dry"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-choice-delta-tooluse-fragment')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("fragmented choice delta toolUse native call assembled", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("choice_delta_tool_use_fragment_assembly"), status)
                self.assertIn("choice_delta_tool_use_fragments", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn("choice-tooluse-fragment-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_content_block_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Content Block Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            custom_input_marker = "CONTENT_BLOCK_CUSTOM_INPUT_SHOULD_NOT_SURFACE"
            function_response_marker = "CONTENT_BLOCK_FUNCTION_RESPONSE_SHOULD_NOT_SURFACE"
            result_alias_marker = "CONTENT_BLOCK_CAMEL_RESULT_SHOULD_NOT_SURFACE"

            class FakeContentBlockHTTPResponse:
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
                                        {"type": "text", "text": "native content-block plan token=content-secret"},
                                        {
                                            "type": "tool_use",
                                            "tool_call_id": "content_tool_alias",
                                            "name": "remember",
                                            "input": {"key": "native-content-block", "value": "content block native tool call accepted"},
                                        },
                                        {
                                            "type": "function_call",
                                            "function": {
                                                "name": "list_tasks",
                                                "arguments": json.dumps({"status": "all", "limit": "1"}),
                                                "tool_call_id": "content_function_inner_alias",
                                            },
                                        },
                                        {"type": "tool_use", "tool_use_id": "toolu_bad_args", "name": "remember", "input": ["not", "object"]},
                                        {"type": "custom_tool_call", "id": "toolu_custom", "name": "run_command", "input": custom_input_marker + " token=content-secret"},
                                        {"type": "tool_result", "content": "PROVIDER_RESULT_CONTENT_SHOULD_NOT_SURFACE"},
                                        {"type": "toolResult", "content": result_alias_marker + " token=content-secret"},
                                        {"functionResult": {"content": result_alias_marker + " token=content-secret"}},
                                        {"type": "functionResponse", "content": function_response_marker + " token=content-secret"},
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeContentBlockHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-content-blocks",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-content-blocks", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native content block token=content-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertIn("native content-block tool_use", payload["tool_calls"][0]["reason"])
                    self.assertIn("native content-block function_call", payload["tool_calls"][1]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["content_tool_alias", "content_function_inner_alias"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native content-block tool_use", "native content-block function_call"])
                    self.assertEqual([item.get("native_tool_call_index") for item in call_metadata], [1, 2])
                    rejected_blob = json.dumps(payload.get("rejected_tool_calls", []))
                    self.assertIn("Native tool arguments must be a JSON object", rejected_blob)
                    self.assertIn("Custom/freeform native tool calls are not supported", rejected_blob)
                    warnings_blob = json.dumps(payload.get("warnings", [])).lower()
                    self.assertIn("tool_result", warnings_blob)
                    self.assertIn("custom/freeform", warnings_blob)
                    self.assertNotIn("PROVIDER_RESULT_CONTENT_SHOULD_NOT_SURFACE", planned + rejected_blob + json.dumps(payload))
                    self.assertNotIn(function_response_marker, planned + rejected_blob + json.dumps(payload))
                    self.assertNotIn(result_alias_marker, planned + rejected_blob + json.dumps(payload))
                    self.assertNotIn(custom_input_marker, planned + rejected_blob + json.dumps(payload))
                    metadata = payload.get("metadata", {})
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)
                    self.assertGreaterEqual(metadata.get("rejected_native_tool_call_count", 0), 2)
                    self.assertNotIn("content-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native content block token=content-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["content_tool_alias", "content_function_inner_alias"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native content-block tool_use", "native content-block function_call"])
                recall = runtime.handle_message('/recall query=native-content-block')
                self.assertIn("content block native tool call accepted", recall)
                self.assertNotIn("content-secret", applied + recall)
                self.assertNotIn(result_alias_marker, applied + recall)
                self.assertTrue(captured_payloads)
                self.assertIn("tools", captured_payloads[0])
            finally:
                runtime.close()

    def test_openai_native_content_block_function_call_alias_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Content Block FunctionCall Alias",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            function_response_marker = "CONTENT_BLOCK_FUNCTIONCALL_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeContentBlockFunctionCallHTTPResponse:
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
                                        {"type": "text", "text": "native content-block functionCall plan token=content-function-secret"},
                                        {
                                            "functionCall": {
                                                "toolUseId": "content_function_alias_memory",
                                                "name": "remember",
                                                "args": {"key": "native-content-functioncall", "value": "content-block functionCall alias accepted"},
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
                                                "response": {"content": function_response_marker + " token=content-function-secret"},
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeContentBlockFunctionCallHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-content-block-functioncall-alias",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-content-functioncall", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native content functionCall token=content-function-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertTrue(all("native content-block functionCall" in call.get("reason", "") for call in payload["tool_calls"]))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["content_function_alias_memory", "content_function_alias_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native content-block functionCall", "native content-block functionCall"])
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertNotIn(function_response_marker, planned + json.dumps(payload))
                    self.assertNotIn("content-function-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native content functionCall token=content-function-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["content_function_alias_memory", "content_function_alias_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native content-block functionCall", "native content-block functionCall"])
                recall = runtime.handle_message('/recall query=native-content-functioncall')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("content-block functionCall alias accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("content_block_function_call_alias_translation"), status)
                self.assertIn("content_block_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("content-function-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_content_block_tool_use_object_alias_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Content Block ToolUse Alias",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            function_response_marker = "CONTENT_BLOCK_TOOLUSE_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeContentBlockToolUseHTTPResponse:
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
                                        {"type": "text", "text": "native content-block toolUse plan token=content-tooluse-secret"},
                                        {
                                            "toolUse": {
                                                "toolUseId": "content_tooluse_memory",
                                                "toolName": "remember",
                                                "inputJson": {"key": "native-content-tooluse", "value": "content-block toolUse alias accepted"},
                                            }
                                        },
                                        {
                                            "type": "toolUse",
                                            "toolUse": {
                                                "id": "content_tooluse_tasks",
                                                "functionName": "list_tasks",
                                                "argsJson": {"status": "all", "limit": "1"},
                                            },
                                        },
                                        {
                                            "type": "toolUse",
                                            "toolUseId": "content_tooluse_direct",
                                            "name": "remember",
                                            "input": {"key": "native-content-tooluse-direct", "value": "content-block direct toolUse type accepted"},
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": function_response_marker + " token=content-tooluse-secret"},
                                            },
                                        },
                                    ],
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeContentBlockToolUseHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-content-block-tooluse-alias",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-content-tooluse", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native content toolUse token=content-tooluse-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["content_tooluse_memory", "content_tooluse_tasks", "content_tooluse_direct"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native content-block toolUse", "native content-block toolUse", "native content-block toolUse"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn(function_response_marker, planned + json.dumps(payload))
                    self.assertNotIn("content-tooluse-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native content toolUse token=content-tooluse-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["content_tooluse_memory", "content_tooluse_tasks", "content_tooluse_direct"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native content-block toolUse", "native content-block toolUse", "native content-block toolUse"])
                recall = runtime.handle_message('/recall query=native-content-tooluse')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("content-block toolUse alias accepted", recall)
                self.assertIn("content-block direct toolUse type accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("content_block_tool_use_alias_translation"), status)
                self.assertIn("content_block_toolUse", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("content-tooluse-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_content_parts_tool_use_object_alias_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Content Parts ToolUse Alias",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-content-parts-tooluse-should-not-run.txt"
            function_response_marker = "CONTENT_PARTS_TOOLUSE_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeContentPartsToolUseHTTPResponse:
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
                                            {"text": "native content parts toolUse plan token=content-parts-tooluse-secret"},
                                            {
                                                "toolUse": {
                                                    "toolUseId": "content_parts_tooluse_memory",
                                                    "name": "remember",
                                                    "input": {"key": "native-content-parts-tooluse", "value": "content parts toolUse alias accepted"},
                                                }
                                            },
                                            {
                                                "type": "toolUse",
                                                "toolUse": {
                                                    "toolUseId": "content_parts_tooluse_dry",
                                                    "name": "run_command",
                                                    "inputJson": {
                                                        "target": "app.example.test",
                                                        "purpose": "content parts toolUse dry-run boundary",
                                                        "command": f"printf native-content-parts-tooluse > {dry_run_marker}",
                                                        "execute": True,
                                                    },
                                                },
                                            },
                                            {
                                                "functionResponse": {
                                                    "name": "remember",
                                                    "response": {"content": function_response_marker + " token=content-parts-tooluse-secret"},
                                                },
                                            },
                                        ]
                                    }
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeContentPartsToolUseHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-content-parts-tooluse-alias",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-content-parts-tooluse", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native content parts toolUse token=content-parts-tooluse-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertFalse(payload["tool_calls"][1]["args"].get("execute"))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["content_parts_tooluse_memory", "content_parts_tooluse_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider content parts toolUse", "native provider content parts toolUse"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn(function_response_marker, planned + json.dumps(payload))
                    self.assertNotIn("content-parts-tooluse-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native content parts toolUse token=content-parts-tooluse-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["content_parts_tooluse_memory", "content_parts_tooluse_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider content parts toolUse", "native provider content parts toolUse"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-content-parts-tooluse')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("content parts toolUse alias accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("content_block_tool_use_alias_translation"), status)
                self.assertIn("content_parts_toolUse", status.get("provider_native_tool_call_variants", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("content-parts-tooluse-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_content_parts_function_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Content Parts Function Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-content-parts-should-not-run.txt"
            function_response_marker = "CONTENT_PARTS_FUNCTION_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeContentPartsHTTPResponse:
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
                                            {"text": "native content parts plan token=content-parts-secret"},
                                            {
                                                "functionCall": {
                                                    "callId": "content_parts_memory",
                                                    "name": "remember",
                                                    "args": {"key": "native-content-parts", "value": "content parts functionCall accepted"},
                                                },
                                            },
                                            {
                                                "functionCall": {
                                                    "toolUseId": "content_parts_dry_run",
                                                    "name": "run_command",
                                                    "parameters": {
                                                        "target": "app.example.test",
                                                        "purpose": "content parts native dry-run boundary",
                                                        "command": f"printf native-content-parts > {dry_run_marker}",
                                                        "execute": True,
                                                    },
                                                },
                                            },
                                            {
                                                "functionResponse": {
                                                    "name": "remember",
                                                    "response": {"content": function_response_marker + " token=content-parts-secret"},
                                                },
                                            },
                                        ]
                                    }
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeContentPartsHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-content-parts-functioncall",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-content-parts", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native content parts token=content-parts-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertTrue(all("native provider content parts functionCall" in call.get("reason", "") for call in payload["tool_calls"]))
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["content_parts_memory", "content_parts_dry_run"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider content parts functionCall", "native provider content parts functionCall"])
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertNotIn(function_response_marker, planned + json.dumps(payload))
                    self.assertNotIn("content-parts-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native content parts token=content-parts-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["content_parts_memory", "content_parts_dry_run"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider content parts functionCall", "native provider content parts functionCall"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-content-parts')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("content parts functionCall accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("content_parts_function_call_translation"), status)
                self.assertIn("content_parts_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("content-parts-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_top_level_content_blocks_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Top-Level Content Blocks",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "TOP_LEVEL_PROVIDER_RESULT_SHOULD_NOT_SURFACE"

            class FakeTopLevelContentHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "id": "msg_top_level_native",
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "native top-level content plan token=top-level-secret"},
                            {
                                "type": "tool_use",
                                "tool_use_id": "top_level_memory",
                                "name": "remember",
                                "input": {"key": "native-top-level-content", "value": "top-level content-block native tool call accepted"},
                            },
                            {
                                "type": "function_call",
                                "call_id": "top_level_tasks",
                                "name": "list_tasks",
                                "argumentsJson": {"status": "all", "limit": "1"},
                            },
                            {"type": "tool_result", "content": provider_result_marker + " token=top-level-secret"},
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeTopLevelContentHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-top-level-content-blocks",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-top-level-content", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native top-level content token=top-level-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertIn("native content-block tool_use", payload["tool_calls"][0]["reason"])
                    self.assertIn("native content-block function_call", payload["tool_calls"][1]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["top_level_memory", "top_level_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native content-block tool_use", "native content-block function_call"])
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))
                    self.assertNotIn("top-level-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native top-level content token=top-level-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["top_level_memory", "top_level_tasks"])
                recall = runtime.handle_message('/recall query=native-top-level-content')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("top-level content-block native tool call accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("top_level_content_block_tool_call_translation"), status)
                self.assertIn("top_level_content_block_tool_use", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("top-level-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_native_single_content_block_tool_call_and_result_echo_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Single Content Block Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            call_counter = {"count": 0}
            provider_result_marker = "SINGLE_CONTENT_RESULT_SHOULD_NOT_SURFACE"

            class FakeSingleContentHTTPResponse:
                def __init__(self, payload: dict):
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                call_counter["count"] += 1
                if call_counter["count"] <= 2:
                    return FakeSingleContentHTTPResponse({
                        "choices": [
                            {
                                "message": {
                                    "content": {
                                        "type": "tool_use",
                                        "id": "single_memory",
                                        "name": "remember",
                                        "input": {"key": "native-single-content", "value": "single content block accepted"},
                                    }
                                }
                            }
                        ]
                    })
                return FakeSingleContentHTTPResponse({
                    "choices": [
                        {
                            "message": {
                                "content": {
                                    "type": "tool_result",
                                    "content": provider_result_marker + " token=single-result-secret",
                                }
                            }
                        }
                    ]
                })

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-single-content-block",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-single-content", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native single content block token=single-content-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-single-content")
                    self.assertIn("native content-block tool_use", payload["tool_calls"][0]["reason"])
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "single_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native content-block tool_use")
                    self.assertEqual(call_metadata.get("native_tool_call_index"), 1)
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertNotIn("single-content-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native single content block token=single-content-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual(ledger[0].get("provider_tool_call_id"), "single_memory")
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native content-block tool_use")

                    result_echo_plan = runtime.handle_message('/auto model=true prompt="provider emitted only prior result echo token=single-result-secret"')
                    result_payload = json.loads(result_echo_plan.split("\n", 1)[1])
                    self.assertEqual(result_payload["mode"], "plan_only")
                    self.assertEqual(result_payload.get("tool_calls"), [])
                    self.assertIn("tool_result", json.dumps(result_payload.get("warnings", [])).lower())
                    self.assertTrue(result_payload.get("no_tools_executed"))
                    self.assertNotIn(provider_result_marker, result_echo_plan + json.dumps(result_payload))
                    self.assertNotIn("single-result-secret", result_echo_plan + json.dumps(result_payload))
                recall = runtime.handle_message('/recall query=native-single-content')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("single content block accepted", recall)
                self.assertIn("single_content_block_tool_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("single_content_block_tool_call_translation"))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("single-content-secret", applied + recall)
            finally:
                runtime.close()

    def test_openai_single_top_level_tool_call_object_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Single Top-Level Tool Call",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeSingleTopLevelHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "single top-level native tool_call token=single-top-secret",
                                    "tool_calls": {
                                        "id": "single_top_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-single-top", "value": "single top-level tool_call accepted"}),
                                        },
                                    },
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeSingleTopLevelHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-single-top-level-tool-call",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-single-top", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native single top-level token=single-top-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertIn("native provider single top-level tool_call", payload["tool_calls"][0]["reason"])
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "single_top_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native provider single top-level tool_call")
                    self.assertEqual(call_metadata.get("native_tool_call_index"), 1)
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertNotIn("single-top-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native single top-level token=single-top-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual(ledger[0].get("provider_tool_call_id"), "single_top_memory")
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native provider single top-level tool_call")
                recall = runtime.handle_message('/recall query=native-single-top')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("single top-level tool_call accepted", recall)
                self.assertIn("single_top_level_tool_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("single_top_level_tool_call_translation"))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("single-top-secret", applied + recall)
            finally:
                runtime.close()

    def test_openai_native_singular_tool_call_alias_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Singular Tool Call Alias",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeSingularToolCallHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "singular native tool_call alias token=singular-secret",
                                    "tool_call": {
                                        "id": "singular_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-singular-tool-call", "value": "singular tool_call alias accepted"}),
                                        },
                                    },
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeSingularToolCallHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-singular-tool-call-alias",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-singular-tool-call", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native singular tool call token=singular-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertIn("native provider singular tool_call", payload["tool_calls"][0]["reason"])
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "singular_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native provider singular tool_call")
                    self.assertEqual(call_metadata.get("native_tool_call_index"), 1)
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertNotIn("singular-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native singular tool call token=singular-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual(ledger[0].get("provider_tool_call_id"), "singular_memory")
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native provider singular tool_call")
                recall = runtime.handle_message('/recall query=native-singular-tool-call')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("singular tool_call alias accepted", recall)
                self.assertIn("singular_tool_call_alias", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("singular_tool_call_alias_translation"))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("singular-secret", applied + recall)
            finally:
                runtime.close()

    def test_openai_native_camel_case_tool_call_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native CamelCase Tool Call Aliases",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeCamelCaseToolCallHTTPResponse:
                def __init__(self, *, singular: bool = False):
                    self.singular = singular

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    if self.singular:
                        message = {
                            "content": "singular camelCase native toolCall token=camel-secret",
                            "toolCall": {
                                "toolUseId": "camel_singular_memory",
                                "type": "function",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-camel-singular", "value": "singular camelCase toolCall accepted"}),
                                },
                            },
                        }
                    else:
                        message = {
                            "content": "camelCase native toolCalls token=camel-secret",
                            "toolCalls": [
                                {
                                    "toolCallId": "camel_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-camel-case", "value": "camelCase toolCalls accepted"}),
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

            def fake_urlopen(request, timeout=0):
                request_payload = json.loads(request.data.decode("utf-8"))
                captured_payloads.append(request_payload)
                user_content = "\n".join(
                    str(item.get("content") or "")
                    for item in request_payload.get("messages", [])
                    if isinstance(item, dict)
                )
                return FakeCamelCaseToolCallHTTPResponse(singular="singular camelCase" in user_content)

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-camel-case-tool-call-aliases",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-camel-case-tool-call", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native camelCase toolCalls token=camel-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertTrue(all("native provider camelCase toolCall" in call.get("reason", "") for call in payload["tool_calls"]))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["camel_memory", "camel_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider camelCase toolCall", "native provider camelCase toolCall"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertNotIn("camel-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native camelCase toolCalls token=camel-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["camel_memory", "camel_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider camelCase toolCall", "native provider camelCase toolCall"])

                    singular_plan = runtime.handle_message('/auto model=true prompt="native singular camelCase toolCall token=camel-secret"')
                    singular_payload = json.loads(singular_plan.split("\n", 1)[1])
                    self.assertEqual([call["tool"] for call in singular_payload["tool_calls"]], ["remember"])
                    singular_metadata = singular_payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(singular_metadata.get("provider_tool_call_id"), "camel_singular_memory")
                    self.assertEqual(singular_metadata.get("native_tool_call_source"), "native provider camelCase toolCall")

                    singular_apply = runtime.handle_message('/auto apply=true model=true prompt="native singular camelCase toolCall token=camel-secret"')
                    singular_apply_payload = json.loads(singular_apply.split("\n", 1)[1])
                    singular_ledger = singular_apply_payload.get("execution_ledger", [])
                    self.assertEqual(singular_ledger[0].get("provider_tool_call_id"), "camel_singular_memory")
                recall = runtime.handle_message('/recall query=native-camel')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("camelCase toolCalls accepted", recall)
                self.assertIn("singular camelCase toolCall accepted", recall)
                self.assertIn("camel_case_tool_call_alias", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("camel_case_tool_call_alias_translation"))
                self.assertIn("callId", status.get("provider_tool_call_id_aliases", []))
                self.assertIn("toolCallId", status.get("provider_tool_call_id_aliases", []))
                self.assertIn("toolUseId", status.get("provider_tool_call_id_aliases", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("camel-secret", applied + singular_plan + singular_apply + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_responses_output_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Output Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-responses-should-not-run.txt"
            provider_result_marker = "PROVIDER_RESPONSES_RESULT_SHOULD_NOT_SURFACE"
            custom_input_marker = "RESPONSES_CUSTOM_TOOL_INPUT_SHOULD_NOT_SURFACE"

            class FakeResponsesOutputHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "responses provider selected tool calls token=responses-secret",
                        "output": [
                            {
                                "type": "message",
                                "content": [
                                    {"type": "output_text", "text": "responses provider selected tool calls token=responses-secret"},
                                ],
                            },
                            {
                                "type": "function_call",
                                "call_id": "resp_memory",
                                "name": "remember",
                                "arguments": json.dumps({"key": "native-responses", "value": "responses output native tool call accepted"}),
                            },
                            {
                                "type": "function_call",
                                "call_id": "resp_dry_run",
                                "name": "run_command",
                                "arguments": json.dumps({
                                    "target": "app.example.test",
                                    "purpose": "responses output native dry-run boundary",
                                    "command": f"printf native-responses > {dry_run_marker}",
                                    "execute": True,
                                }),
                            },
                            {"type": "custom_tool_call", "call_id": "resp_custom", "name": "run_command", "input": custom_input_marker + " token=responses-secret"},
                            {"type": "function_call_output", "call_id": "resp_result", "output": provider_result_marker},
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesOutputHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-output",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses output token=responses-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertIn("native provider responses output function_call", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses output function_call", payload["tool_calls"][1]["reason"])
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["resp_memory", "resp_dry_run"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider responses output function_call", "native provider responses output function_call"])
                    rejected_blob = json.dumps(payload.get("rejected_tool_calls", []))
                    self.assertIn("Custom/freeform native tool calls are not supported", rejected_blob)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertIn("custom/freeform", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))
                    self.assertNotIn(custom_input_marker, planned + rejected_blob + json.dumps(payload))
                    metadata = payload.get("metadata", {})
                    self.assertTrue(metadata.get("native_tool_calls"), metadata)
                    self.assertEqual(metadata.get("native_tool_call_count"), 2)
                    self.assertGreaterEqual(metadata.get("rejected_native_tool_call_count", 0), 1)
                    self.assertNotIn("responses-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses output token=responses-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["resp_memory", "resp_dry_run"])
                    self.assertEqual(ledger[1].get("native_tool_call_source"), "native provider responses output function_call")
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-responses')
                self.assertIn("responses output native tool call accepted", recall)
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("responses-secret", applied + recall)
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_nested_output_function_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Nested Output Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "PROVIDER_RESPONSES_NESTED_RESULT_SHOULD_NOT_SURFACE"

            class FakeNestedResponsesOutputHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "nested responses output token=responses-nested-secret",
                        "output": [
                            {"type": "message", "content": [{"type": "output_text", "text": "nested responses output token=responses-nested-secret"}]},
                            {
                                "type": "function_call",
                                "call_id": "resp_nested_function_memory",
                                "function": {
                                    "name": "remember",
                                    "arguments": json.dumps({"key": "native-responses-nested-function", "value": "Responses nested function tool call accepted"}),
                                },
                            },
                            {
                                "type": "tool_call",
                                "toolUseId": "resp_nested_function_call_tasks",
                                "functionCall": {
                                    "name": "list_tasks",
                                    "parameters": {"status": "all", "limit": 1},
                                },
                            },
                            {"type": "function_call_output", "call_id": "resp_nested_result", "output": provider_result_marker + " token=responses-nested-secret"},
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeNestedResponsesOutputHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-nested-output",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses-nested", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses nested output token=responses-nested-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks"])
                    self.assertIn("native provider responses output nested function", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses output nested functionCall", payload["tool_calls"][1]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["resp_nested_function_memory", "resp_nested_function_call_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider responses output nested function", "native provider responses output nested functionCall"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn("responses-nested-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses nested output token=responses-nested-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["resp_nested_function_memory", "resp_nested_function_call_tasks"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider responses output nested function", "native provider responses output nested functionCall"])
                recall = runtime.handle_message('/recall query=native-responses-nested-function')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses nested function tool call accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_output_nested_function_call_translation"), status)
                self.assertIn("responses_output_nested_function", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_nested_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("responses-nested-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_message_content_tool_calls_keep_provider_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Message Content Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "PROVIDER_RESPONSES_MESSAGE_CONTENT_RESULT_SHOULD_NOT_SURFACE"

            class FakeResponsesMessageContentHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "responses message content token=responses-message-secret",
                        "output": [
                            {
                                "type": "message",
                                "content": [
                                    {"type": "output_text", "text": "responses message content token=responses-message-secret"},
                                    {
                                        "type": "function_call",
                                        "call_id": "resp_message_content_memory",
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-responses-message-content", "value": "Responses message content function_call accepted"}),
                                    },
                                    {
                                        "type": "tool_use",
                                        "toolUseId": "resp_message_content_tasks",
                                        "name": "list_tasks",
                                        "input": {"status": "all", "limit": 1},
                                    },
                                    {
                                        "type": "functionCall",
                                        "callId": "resp_message_content_function_alias",
                                        "functionCall": {
                                            "name": "remember",
                                            "argumentsJson": {"key": "native-responses-message-content-functioncall", "value": "Responses message content functionCall accepted"},
                                        },
                                    },
                                    {"type": "function_call_output", "call_id": "resp_message_content_result", "output": provider_result_marker + " token=responses-message-secret"},
                                    {
                                        "type": "functionResponse",
                                        "functionResponse": {
                                            "name": "remember",
                                            "response": {"content": provider_result_marker + " token=responses-message-secret"},
                                        },
                                    },
                                ],
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesMessageContentHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-message-content",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-content", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses message content token=responses-message-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember"])
                    self.assertIn("native provider responses message content function_call", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses message content tool_use", payload["tool_calls"][1]["reason"])
                    self.assertIn("native provider responses message content functionCall", payload["tool_calls"][2]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["resp_message_content_memory", "resp_message_content_tasks", "resp_message_content_function_alias"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider responses message content function_call", "native provider responses message content tool_use", "native provider responses message content functionCall"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn("responses-message-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses message content token=responses-message-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["resp_message_content_memory", "resp_message_content_tasks", "resp_message_content_function_alias"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider responses message content function_call", "native provider responses message content tool_use", "native provider responses message content functionCall"])
                recall = runtime.handle_message('/recall query=native-responses-message-content')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses message content function_call accepted", recall)
                self.assertIn("Responses message content functionCall accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_content_tool_call_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_content_function_call_alias_translation"), status)
                self.assertIn("responses_message_content_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_content_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_content_tool_use", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("responses-message-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_message_level_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Message Tool Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeResponsesMessageToolCallHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "responses message tool calls token=responses-message-tool-secret",
                        "output": [
                            {
                                "type": "message",
                                "content": [{"type": "output_text", "text": "responses message tool calls token=responses-message-tool-secret"}],
                                "tool_calls": [
                                    {
                                        "id": "resp_message_tool_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-responses-message-tool-calls", "value": "Responses message-level tool_calls accepted"}),
                                        },
                                    },
                                    {
                                        "id": "resp_message_tool_tasks",
                                        "type": "function",
                                        "function": {
                                            "name": "list_tasks",
                                            "argumentsJson": {"status": "all", "limit": 1},
                                        },
                                    },
                                ],
                                "toolCalls": [
                                    {
                                        "toolUseId": "resp_message_toolcalls_plural",
                                        "function": {
                                            "name": "remember",
                                            "argumentsJson": {"key": "native-responses-message-toolcalls", "value": "Responses message-level toolCalls accepted"},
                                        },
                                    }
                                ],
                                "tool_call": {
                                    "tool_call_id": "resp_message_tool_call_singular",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-responses-message-tool-call", "value": "Responses message-level tool_call accepted"}),
                                    },
                                },
                                "toolCall": {
                                    "toolCallId": "resp_message_tool_camel",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-responses-message-tool-camel", "value": "Responses message-level toolCall accepted"}),
                                    },
                                },
                                "functionCall": {
                                    "callId": "resp_message_function_alias",
                                    "name": "remember",
                                    "parameters": {"key": "native-responses-message-functioncall", "value": "Responses message-level functionCall accepted"},
                                },
                                "functionCalls": [
                                    {
                                        "callId": "resp_message_function_calls_plural",
                                        "name": "remember",
                                        "args": {"key": "native-responses-message-functioncalls", "value": "Responses message-level functionCalls accepted"},
                                    }
                                ],
                                "function_calls": {
                                    "call_id": "resp_message_function_calls_snake",
                                    "function_call": {
                                        "name": "remember",
                                        "parameters": {"key": "native-responses-message-function-calls-snake", "value": "Responses message-level function_calls accepted"},
                                    },
                                },
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesMessageToolCallHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-message-tool-calls",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-tool-calls", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses message tool calls token=responses-message-tool-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember", "remember", "remember", "remember", "remember", "remember"])
                    self.assertIn("native provider responses message tool_calls", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses message toolCalls", payload["tool_calls"][2]["reason"])
                    self.assertIn("native provider responses message tool_call", payload["tool_calls"][3]["reason"])
                    self.assertIn("native provider responses message toolCall", payload["tool_calls"][4]["reason"])
                    self.assertIn("native provider responses message functionCall", payload["tool_calls"][5]["reason"])
                    self.assertIn("native provider responses message functionCalls", payload["tool_calls"][6]["reason"])
                    self.assertIn("native provider responses message function_calls", payload["tool_calls"][7]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["resp_message_tool_memory", "resp_message_tool_tasks", "resp_message_toolcalls_plural", "resp_message_tool_call_singular", "resp_message_tool_camel", "resp_message_function_alias", "resp_message_function_calls_plural", "resp_message_function_calls_snake"])
                    self.assertEqual(
                        [item.get("native_tool_call_source") for item in call_metadata],
                        [
                            "native provider responses message tool_calls",
                            "native provider responses message tool_calls",
                            "native provider responses message toolCalls",
                            "native provider responses message tool_call",
                            "native provider responses message toolCall",
                            "native provider responses message functionCall",
                            "native provider responses message functionCalls",
                            "native provider responses message function_calls",
                        ],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 8)
                    self.assertNotIn("responses-message-tool-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses message tool calls token=responses-message-tool-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["resp_message_tool_memory", "resp_message_tool_tasks", "resp_message_toolcalls_plural", "resp_message_tool_call_singular", "resp_message_tool_camel", "resp_message_function_alias", "resp_message_function_calls_plural", "resp_message_function_calls_snake"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], [item.get("native_tool_call_source") for item in call_metadata])
                recall = runtime.handle_message('/recall query=native-responses-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses message-level tool_calls accepted", recall)
                self.assertIn("Responses message-level toolCalls accepted", recall)
                self.assertIn("Responses message-level tool_call accepted", recall)
                self.assertIn("Responses message-level toolCall accepted", recall)
                self.assertIn("Responses message-level functionCall accepted", recall)
                self.assertIn("Responses message-level functionCalls accepted", recall)
                self.assertIn("Responses message-level function_calls accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_tool_call_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_tool_calls_camel_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_tool_call_singular_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_function_calls_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_function_calls_snake_alias_translation"), status)
                self.assertIn("responses_message_tool_calls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_toolCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_tool_call", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_toolCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_functionCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_function_calls", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("responses-message-tool-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_responses_output_nested_message_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Output Nested Message Aliases",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "RESPONSES_OUTPUT_MESSAGE_RESULT_SHOULD_NOT_SURFACE"

            class FakeResponsesOutputNestedMessageHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "responses output nested message token=responses-output-message-secret",
                        "output": [
                            {
                                "type": "message",
                                "message": {
                                    "content": {
                                        "parts": [
                                            {"text": "responses output nested message text token=responses-output-message-secret"},
                                            {
                                                "functionCall": {
                                                    "callId": "resp_output_message_parts_memory",
                                                    "name": "remember",
                                                    "args": {"key": "native-responses-output-message-parts", "value": "Responses output nested message content parts accepted"},
                                                }
                                            },
                                            {
                                                "functionResponse": {
                                                    "name": "remember",
                                                    "response": {"content": provider_result_marker + " token=responses-output-message-secret"},
                                                }
                                            },
                                        ]
                                    },
                                    "tool_calls": [
                                        {
                                            "id": "resp_output_message_tool_calls_memory",
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-responses-output-message-tool-calls", "value": "Responses output nested message tool_calls accepted"}),
                                            },
                                        }
                                    ],
                                    "toolCalls": {
                                        "toolUseId": "resp_output_message_toolcalls_tasks",
                                        "function": {
                                            "name": "list_tasks",
                                            "argumentsJson": {"status": "all", "limit": 1},
                                        },
                                    },
                                    "tool_call": {
                                        "tool_call_id": "resp_output_message_tool_call_memory",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-responses-output-message-tool-call", "value": "Responses output nested message tool_call accepted"}),
                                        },
                                    },
                                    "toolCall": {
                                        "toolCallId": "resp_output_message_tool_camel_memory",
                                        "name": "remember",
                                        "args": {"key": "native-responses-output-message-tool-camel", "value": "Responses output nested message toolCall accepted"},
                                    },
                                    "functionCall": {
                                        "callId": "resp_output_message_function_alias_memory",
                                        "name": "remember",
                                        "parameters": {"key": "native-responses-output-message-functioncall", "value": "Responses output nested message functionCall accepted"},
                                    },
                                    "functionCalls": [
                                        {
                                            "callId": "resp_output_message_function_calls_memory",
                                            "name": "remember",
                                            "args": {"key": "native-responses-output-message-functioncalls", "value": "Responses output nested message functionCalls accepted"},
                                        }
                                    ],
                                    "function_calls": {
                                        "call_id": "resp_output_message_function_calls_snake_memory",
                                        "function_call": {
                                            "name": "remember",
                                            "args": {"key": "native-responses-output-message-function-calls-snake", "value": "Responses output nested message function_calls accepted"},
                                        },
                                    },
                                },
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesOutputNestedMessageHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-output-nested-message",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses-output-nested-message", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses output nested message token=responses-output-message-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember", "remember", "remember", "remember", "remember", "remember"])
                    self.assertIn("native provider responses output message tool_calls", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses output message toolCalls", payload["tool_calls"][1]["reason"])
                    self.assertIn("native provider responses output message tool_call", payload["tool_calls"][2]["reason"])
                    self.assertIn("native provider responses output message toolCall", payload["tool_calls"][3]["reason"])
                    self.assertIn("native provider responses output message functionCall", payload["tool_calls"][4]["reason"])
                    self.assertIn("native provider responses output message functionCalls", payload["tool_calls"][5]["reason"])
                    self.assertIn("native provider responses output message function_calls", payload["tool_calls"][6]["reason"])
                    self.assertIn("native provider responses output message content parts functionCall", payload["tool_calls"][7]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual(
                        [item.get("provider_tool_call_id") for item in call_metadata],
                        [
                            "resp_output_message_tool_calls_memory",
                            "resp_output_message_toolcalls_tasks",
                            "resp_output_message_tool_call_memory",
                            "resp_output_message_tool_camel_memory",
                            "resp_output_message_function_alias_memory",
                            "resp_output_message_function_calls_memory",
                            "resp_output_message_function_calls_snake_memory",
                            "resp_output_message_parts_memory",
                        ],
                    )
                    self.assertEqual(
                        [item.get("native_tool_call_source") for item in call_metadata],
                        [
                            "native provider responses output message tool_calls",
                            "native provider responses output message toolCalls",
                            "native provider responses output message tool_call",
                            "native provider responses output message toolCall",
                            "native provider responses output message functionCall",
                            "native provider responses output message functionCalls",
                            "native provider responses output message function_calls",
                            "native provider responses output message content parts functionCall",
                        ],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 8)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn("responses-output-message-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses output nested message token=responses-output-message-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], [item.get("provider_tool_call_id") for item in call_metadata])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], [item.get("native_tool_call_source") for item in call_metadata])
                recall = runtime.handle_message('/recall query=native-responses-output-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses output nested message tool_calls accepted", recall)
                self.assertIn("Responses output nested message toolCall accepted", recall)
                self.assertIn("Responses output nested message function_calls accepted", recall)
                self.assertIn("Responses output nested message content parts accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_output_message_alias_translation"), status)
                self.assertIn("responses_output_message_tool_calls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_toolCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_tool_call", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_toolCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_functionCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_function_calls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_content_parts_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("responses-output-message-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_output_typeless_nested_message_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Typeless Responses Output Message",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "TYPELESS_RESPONSES_OUTPUT_RESULT_SHOULD_NOT_SURFACE"

            class FakeTypelessResponsesOutputMessageHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "typeless responses output message token=typeless-output-message-secret",
                        "output": [
                            {
                                "message": {
                                    "content": {
                                        "parts": [
                                            {"text": "typeless nested message text token=typeless-output-message-secret"},
                                            {
                                                "functionCall": {
                                                    "callId": "typeless_output_message_parts_memory",
                                                    "name": "remember",
                                                    "args": {"key": "native-typeless-output-message-parts", "value": "typeless Responses output message content parts accepted"},
                                                }
                                            },
                                            {
                                                "functionResponse": {
                                                    "name": "remember",
                                                    "response": {"content": provider_result_marker + " token=typeless-output-message-secret"},
                                                }
                                            },
                                        ]
                                    },
                                    "tool_calls": [
                                        {
                                            "id": "typeless_output_message_tool_calls_memory",
                                            "type": "function",
                                            "function": {
                                                "name": "remember",
                                                "arguments": json.dumps({"key": "native-typeless-output-message-tool-calls", "value": "typeless Responses output message tool_calls accepted"}),
                                            },
                                        }
                                    ],
                                    "functionCalls": {
                                        "callId": "typeless_output_message_function_calls_memory",
                                        "name": "remember",
                                        "args": {"key": "native-typeless-output-message-functioncalls", "value": "typeless Responses output message functionCalls accepted"},
                                    },
                                }
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeTypelessResponsesOutputMessageHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-typeless-responses-output-message",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-typeless-responses-output-message", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native typeless responses output message token=typeless-output-message-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "remember", "remember"])
                    self.assertIn("native provider responses output message tool_calls", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider responses output message functionCalls", payload["tool_calls"][1]["reason"])
                    self.assertIn("native provider responses output message content parts functionCall", payload["tool_calls"][2]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual(
                        [item.get("provider_tool_call_id") for item in call_metadata],
                        [
                            "typeless_output_message_tool_calls_memory",
                            "typeless_output_message_function_calls_memory",
                            "typeless_output_message_parts_memory",
                        ],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn("typeless-output-message-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native typeless responses output message token=typeless-output-message-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], [item.get("provider_tool_call_id") for item in call_metadata])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], [item.get("native_tool_call_source") for item in call_metadata])
                recall = runtime.handle_message('/recall query=native-typeless-output-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("typeless Responses output message tool_calls accepted", recall)
                self.assertIn("typeless Responses output message functionCalls accepted", recall)
                self.assertIn("typeless Responses output message content parts accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_output_message_typeless_wrapper_translation"), status)
                self.assertIn("responses_output_message_typeless_wrapper", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("typeless-output-message-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_output_typeless_direct_message_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Typeless Direct Responses Output Message",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "TYPELESS_DIRECT_RESPONSES_OUTPUT_RESULT_SHOULD_NOT_SURFACE"

            class FakeTypelessDirectResponsesOutputMessageHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "typeless direct responses output message token=typeless-direct-output-message-secret",
                        "output": [
                            {
                                "content": {
                                    "parts": [
                                        {"text": "typeless direct output message text token=typeless-direct-output-message-secret"},
                                        {
                                            "functionCall": {
                                                "callId": "typeless_direct_output_message_parts_memory",
                                                "name": "remember",
                                                "args": {"key": "native-typeless-direct-output-message-parts", "value": "typeless direct Responses output message content parts accepted"},
                                            }
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": provider_result_marker + " token=typeless-direct-output-message-secret"},
                                            }
                                        },
                                    ]
                                },
                                "tool_calls": [
                                    {
                                        "id": "typeless_direct_output_message_tool_calls_memory",
                                        "type": "function",
                                        "function": {
                                            "name": "remember",
                                            "arguments": json.dumps({"key": "native-typeless-direct-output-message-tool-calls", "value": "typeless direct Responses output message tool_calls accepted"}),
                                        },
                                    }
                                ],
                                "toolCalls": [
                                    {
                                        "toolUseId": "typeless_direct_output_message_toolcalls_memory",
                                        "function": {
                                            "name": "remember",
                                            "argumentsJson": {"key": "native-typeless-direct-output-message-toolcalls", "value": "typeless direct Responses output message toolCalls accepted"},
                                        },
                                    }
                                ],
                                "tool_call": {
                                    "tool_call_id": "typeless_direct_output_message_tool_call_memory",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-typeless-direct-output-message-tool-call", "value": "typeless direct Responses output message tool_call accepted"}),
                                    },
                                },
                                "toolCall": {
                                    "toolCallId": "typeless_direct_output_message_tool_camel_memory",
                                    "name": "remember",
                                    "args": {"key": "native-typeless-direct-output-message-tool-camel", "value": "typeless direct Responses output message toolCall accepted"},
                                },
                                "functionCall": {
                                    "callId": "typeless_direct_output_message_function_alias_memory",
                                    "name": "remember",
                                    "parameters": {"key": "native-typeless-direct-output-message-functioncall", "value": "typeless direct Responses output message functionCall accepted"},
                                },
                                "function_call": {
                                    "call_id": "typeless_direct_output_message_function_call_memory",
                                    "name": "remember",
                                    "parameters": {"key": "native-typeless-direct-output-message-function-call", "value": "typeless direct Responses output message function_call accepted"},
                                },
                                "functionCalls": {
                                    "callId": "typeless_direct_output_message_function_calls_memory",
                                    "name": "remember",
                                    "args": {"key": "native-typeless-direct-output-message-functioncalls", "value": "typeless direct Responses output message functionCalls accepted"},
                                },
                                "function_calls": [
                                    {
                                        "call_id": "typeless_direct_output_message_function_calls_snake_memory",
                                        "function_call": {
                                            "name": "remember",
                                            "parameters": {"key": "native-typeless-direct-output-message-function-calls-snake", "value": "typeless direct Responses output message function_calls accepted"},
                                        },
                                    }
                                ],
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeTypelessDirectResponsesOutputMessageHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-typeless-direct-responses-output-message",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-typeless-direct-responses-output-message", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native typeless direct responses output message token=typeless-direct-output-message-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"] * 9)
                    self.assertIn("native provider typeless responses output message tool_calls", payload["tool_calls"][0]["reason"])
                    self.assertIn("native provider typeless responses output message toolCalls", payload["tool_calls"][1]["reason"])
                    self.assertIn("native provider typeless responses output message tool_call", payload["tool_calls"][2]["reason"])
                    self.assertIn("native provider typeless responses output message toolCall", payload["tool_calls"][3]["reason"])
                    self.assertIn("native provider typeless responses output message functionCall", payload["tool_calls"][4]["reason"])
                    self.assertIn("native provider typeless responses output message function_call", payload["tool_calls"][5]["reason"])
                    self.assertIn("native provider typeless responses output message functionCalls", payload["tool_calls"][6]["reason"])
                    self.assertIn("native provider typeless responses output message function_calls", payload["tool_calls"][7]["reason"])
                    self.assertIn("native provider typeless responses output message content parts functionCall", payload["tool_calls"][8]["reason"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual(
                        [item.get("provider_tool_call_id") for item in call_metadata],
                        [
                            "typeless_direct_output_message_tool_calls_memory",
                            "typeless_direct_output_message_toolcalls_memory",
                            "typeless_direct_output_message_tool_call_memory",
                            "typeless_direct_output_message_tool_camel_memory",
                            "typeless_direct_output_message_function_alias_memory",
                            "typeless_direct_output_message_function_call_memory",
                            "typeless_direct_output_message_function_calls_memory",
                            "typeless_direct_output_message_function_calls_snake_memory",
                            "typeless_direct_output_message_parts_memory",
                        ],
                    )
                    self.assertEqual(
                        [item.get("native_tool_call_source") for item in call_metadata],
                        [
                            "native provider typeless responses output message tool_calls",
                            "native provider typeless responses output message toolCalls",
                            "native provider typeless responses output message tool_call",
                            "native provider typeless responses output message toolCall",
                            "native provider typeless responses output message functionCall",
                            "native provider typeless responses output message function_call",
                            "native provider typeless responses output message functionCalls",
                            "native provider typeless responses output message function_calls",
                            "native provider typeless responses output message content parts functionCall",
                        ],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 9)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn("typeless-direct-output-message-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native typeless direct responses output message token=typeless-direct-output-message-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"] * 9)
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], [item.get("provider_tool_call_id") for item in call_metadata])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], [item.get("native_tool_call_source") for item in call_metadata])
                recall = runtime.handle_message('/recall query=native-typeless-direct-output-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("typeless direct Responses output message tool_calls accepted", recall)
                self.assertIn("typeless direct Responses output message toolCalls accepted", recall)
                self.assertIn("typeless direct Responses output message tool_call accepted", recall)
                self.assertIn("typeless direct Responses output message toolCall accepted", recall)
                self.assertIn("typeless direct Responses output message functionCall accepted", recall)
                self.assertIn("typeless direct Responses output message function_call accepted", recall)
                self.assertIn("typeless direct Responses output message functionCalls accepted", recall)
                self.assertIn("typeless direct Responses output message function_calls accepted", recall)
                self.assertIn("typeless direct Responses output message content parts accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_output_message_typeless_direct_translation"), status)
                for contract_key in (
                    "responses_output_message_typeless_direct_tool_calls_alias_translation",
                    "responses_output_message_typeless_direct_tool_calls_camel_alias_translation",
                    "responses_output_message_typeless_direct_tool_call_singular_alias_translation",
                    "responses_output_message_typeless_direct_tool_call_camel_alias_translation",
                    "responses_output_message_typeless_direct_function_call_alias_translation",
                    "responses_output_message_typeless_direct_function_calls_alias_translation",
                    "responses_output_message_typeless_direct_function_calls_snake_alias_translation",
                ):
                    self.assertTrue(status.get("milestone_contract", {}).get(contract_key), status)
                for variant in (
                    "responses_output_message_typeless_direct",
                    "responses_output_message_typeless_direct_tool_calls",
                    "responses_output_message_typeless_direct_toolCalls",
                    "responses_output_message_typeless_direct_tool_call",
                    "responses_output_message_typeless_direct_toolCall",
                    "responses_output_message_typeless_direct_function_call",
                    "responses_output_message_typeless_direct_functionCall",
                    "responses_output_message_typeless_direct_functionCalls",
                    "responses_output_message_typeless_direct_function_calls",
                    "responses_output_message_typeless_direct_content_parts_functionCall",
                ):
                    self.assertIn(variant, status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("typeless-direct-output-message-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_responses_message_content_parts_function_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Responses Message Content Parts",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-responses-message-parts-should-not-run.txt"
            provider_result_marker = "PROVIDER_RESPONSES_MESSAGE_PARTS_RESULT_SHOULD_NOT_SURFACE"

            class FakeResponsesMessageContentPartsHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "responses message content parts token=responses-message-parts-secret",
                        "output": [
                            {
                                "type": "message",
                                "content": {
                                    "parts": [
                                        {"text": "responses message content parts token=responses-message-parts-secret"},
                                        {
                                            "functionCall": {
                                                "callId": "resp_message_parts_memory",
                                                "name": "remember",
                                                "args": {"key": "native-responses-message-parts", "value": "Responses message content parts functionCall accepted"},
                                            },
                                        },
                                        {
                                            "functionCall": {
                                                "toolUseId": "resp_message_parts_dry",
                                                "name": "run_command",
                                                "parameters": {
                                                    "target": "app.example.test",
                                                    "purpose": "responses message content parts dry-run proof",
                                                    "command": f"printf native-responses-message-parts > {dry_run_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": provider_result_marker + " token=responses-message-parts-secret"},
                                            },
                                        },
                                    ]
                                },
                            }
                        ],
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeResponsesMessageContentPartsHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-responses-message-content-parts",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-responses-message-content-parts", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native responses message content parts token=responses-message-parts-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertTrue(all("native provider responses message content parts functionCall" in call.get("reason", "") for call in payload["tool_calls"]))
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["resp_message_parts_memory", "resp_message_parts_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider responses message content parts functionCall", "native provider responses message content parts functionCall"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn("responses-message-parts-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native responses message content parts token=responses-message-parts-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["resp_message_parts_memory", "resp_message_parts_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider responses message content parts functionCall", "native provider responses message content parts functionCall"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-responses-message-parts')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("Responses message content parts functionCall accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("responses_message_content_parts_function_call_translation"), status)
                self.assertIn("responses_message_content_parts_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertFalse(dry_run_marker.exists())
                self.assertNotIn("responses-message-parts-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_single_responses_output_tool_call_object_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Single Responses Output Tool Call",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeSingleResponsesOutputHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "output_text": "single responses output token=single-responses-secret",
                        "output": {
                            "type": "function_call",
                            "call_id": "single_resp_memory",
                            "name": "remember",
                            "arguments": json.dumps({"key": "native-single-responses", "value": "single Responses output tool call accepted"}),
                        },
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeSingleResponsesOutputHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-single-responses-output",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-single-responses", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native single responses output token=single-responses-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertIn("native provider single responses output function_call", payload["tool_calls"][0]["reason"])
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "single_resp_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native provider single responses output function_call")
                    self.assertEqual(call_metadata.get("native_tool_call_index"), 1)
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertNotIn("single-responses-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native single responses output token=single-responses-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual(ledger[0].get("provider_tool_call_id"), "single_resp_memory")
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native provider single responses output function_call")
                recall = runtime.handle_message('/recall query=native-single-responses')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("single Responses output tool call accepted", recall)
                self.assertTrue(status.get("milestone_contract", {}).get("single_responses_output_tool_call_translation"), status)
                self.assertIn("single_responses_output_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("single-responses-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_candidate_function_call_parts_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Candidate Function Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-candidate-should-not-run.txt"
            provider_result_marker = "PROVIDER_CANDIDATE_RESULT_SHOULD_NOT_SURFACE"

            class FakeCandidateHTTPResponse:
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
                                        {"text": "native candidate plan token=candidate-secret"},
                                        {
                                            "functionCall": {
                                                "id": "candidate_memory",
                                                "name": "remember",
                                                "parameters": {"key": "native-candidate", "value": "candidate functionCall accepted"},
                                            },
                                        },
                                        {
                                            "functionCall": {
                                                "call_id": "candidate_dry_run",
                                                "name": "run_command",
                                                "args": {
                                                    "target": "app.example.test",
                                                    "purpose": "candidate native dry-run boundary",
                                                    "command": f"printf native-candidate > {dry_run_marker}",
                                                    "execute": True,
                                                },
                                            },
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": provider_result_marker + " token=candidate-secret"},
                                            },
                                        },
                                    ]
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeCandidateHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-candidate-function-calls",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-candidate", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native candidate function call token=candidate-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertTrue(all("native provider candidate functionCall" in call.get("reason", "") for call in payload["tool_calls"]))
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-candidate")
                    self.assertFalse(payload["tool_calls"][1]["args"]["execute"])
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["candidate_memory", "candidate_dry_run"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider candidate functionCall", "native provider candidate functionCall"])
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertNotIn("candidate-secret", planned)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native candidate function call token=candidate-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["candidate_memory", "candidate_dry_run"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-candidate')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("candidate functionCall accepted", recall)
                self.assertIn("candidate_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("candidate_function_call_translation"))
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("candidate-secret", applied + recall)
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_candidate_single_part_function_call_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Single Candidate Function Call",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []

            class FakeSingleCandidateHTTPResponse:
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
                                            "tool_use_id": "candidate_single_memory",
                                            "name": "remember",
                                            "args": {"key": "native-single-candidate", "value": "single candidate functionCall accepted"},
                                        }
                                    }
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeSingleCandidateHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-single-candidate-function-call",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-single-candidate", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native single candidate function call token=single-candidate-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertIn("native provider candidate functionCall", payload["tool_calls"][0].get("reason", ""))
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-single-candidate")
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "candidate_single_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native provider candidate functionCall")
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertNotIn("single-candidate-secret", planned)

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native single candidate function call token=single-candidate-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["candidate_single_memory"])
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native provider candidate functionCall")
                recall = runtime.handle_message('/recall query=native-single-candidate')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("single candidate functionCall accepted", recall)
                self.assertIn("single_candidate_part_function_call", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("single_candidate_part_function_call_translation"))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("single-candidate-secret", applied + recall)
            finally:
                runtime.close()

    def test_openai_root_message_wrapper_tool_calls_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root Message Wrapper",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            dry_run_marker = tmp_path / "native-root-message-should-not-run.txt"
            provider_result_marker = "ROOT_MESSAGE_TOOL_RESULT_SHOULD_NOT_SURFACE"

            class FakeRootMessageHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "message": {
                            "role": "assistant",
                            "content": [
                                {"type": "text", "text": "root message wrapper token=root-message-secret"},
                                {"type": "tool_result", "content": provider_result_marker + " token=root-message-secret"},
                            ],
                            "tool_calls": [
                                {
                                    "id": "root_message_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-root-message", "value": "root message wrapper accepted"}),
                                    },
                                },
                                {
                                    "toolCallId": "root_message_dry",
                                    "type": "function",
                                    "function": {
                                        "name": "run_command",
                                        "arguments": json.dumps({
                                            "target": "app.example.test",
                                            "purpose": "root message native dry-run boundary",
                                            "command": f"printf native-root-message > {dry_run_marker}",
                                            "execute": True,
                                        }),
                                    },
                                },
                            ],
                        }
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootMessageHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-message-wrapper",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-message", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root message wrapper token=root-message-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                    self.assertTrue(all("native provider root message tool_calls" in call.get("reason", "") for call in payload["tool_calls"]))
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-root-message")
                    self.assertFalse(payload["tool_calls"][1]["args"].get("execute"))
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["root_message_memory", "root_message_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider root message tool_calls", "native provider root message tool_calls"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 2)
                    self.assertNotIn("root-message-secret", planned + json.dumps(payload))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root message wrapper token=root-message-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["root_message_memory", "root_message_dry"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider root message tool_calls", "native provider root message tool_calls"])
                    self.assertFalse(ledger[1].get("actual_command_or_process_activity"))
                recall = runtime.handle_message('/recall query=native-root-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("root message wrapper accepted", recall)
                self.assertIn("root_message_tool_calls", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("root_message_wrapper_translation"), status)
                self.assertFalse(dry_run_marker.exists())
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("root-message-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_root_message_wrapper_alias_matrix_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root Message Alias Matrix",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "ROOT_MESSAGE_ALIAS_RESULT_SHOULD_NOT_SURFACE"

            class FakeRootMessageAliasHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "message": {
                            "role": "assistant",
                            "content": [
                                {"type": "text", "text": "root message alias matrix token=root-message-alias-secret"},
                                {
                                    "functionCall": {
                                        "toolUseId": "root_message_content_memory",
                                        "name": "remember",
                                        "args": {"key": "native-root-message-content", "value": "root message content functionCall accepted"},
                                    }
                                },
                                {
                                    "type": "functionCall",
                                    "callId": "root_message_content_tasks",
                                    "functionCall": {"name": "list_tasks", "argumentsJson": {"status": "all", "limit": "1"}},
                                },
                                {
                                    "parts": [
                                        {
                                            "functionCall": {
                                                "toolUseId": "root_message_parts_memory",
                                                "name": "remember",
                                                "parameters": {"key": "native-root-message-parts", "value": "root message content parts functionCall accepted"},
                                            }
                                        },
                                        {
                                            "functionResponse": {
                                                "name": "remember",
                                                "response": {"content": provider_result_marker + " token=root-message-alias-secret"},
                                            }
                                        },
                                    ]
                                },
                            ],
                            "toolCalls": [
                                {
                                    "id": "root_message_toolcalls_memory",
                                    "type": "function",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-root-message-toolcalls", "value": "root message toolCalls alias accepted"}),
                                    },
                                }
                            ],
                            "tool_call": {
                                "id": "root_message_tool_call_tasks",
                                "type": "function",
                                "function": {"name": "list_tasks", "arguments": json.dumps({"status": "all", "limit": 1})},
                            },
                            "toolCall": {
                                "toolUseId": "root_message_toolcall_memory",
                                "name": "remember",
                                "args": {"key": "native-root-message-toolcall", "value": "root message toolCall alias accepted"},
                            },
                            "functionCall": {
                                "callId": "root_message_function_call_tasks",
                                "name": "list_tasks",
                                "args": {"status": "all", "limit": 1},
                            },
                            "functionCalls": [
                                {
                                    "call_id": "root_message_functioncalls_memory",
                                    "name": "remember",
                                    "args": {"key": "native-root-message-functioncalls", "value": "root message functionCalls alias accepted"},
                                },
                                {
                                    "toolUseId": "root_message_functioncalls_nested_tasks",
                                    "functionCall": {"name": "list_tasks", "parameters": {"status": "all", "limit": 1}},
                                },
                            ],
                            "function_calls": [
                                {
                                    "tool_call_id": "root_message_function_calls_memory",
                                    "function": {
                                        "name": "remember",
                                        "arguments": json.dumps({"key": "native-root-message-function-calls", "value": "root message function_calls alias accepted"}),
                                    },
                                }
                            ],
                            "functionResponse": {
                                "name": "remember",
                                "response": {"content": provider_result_marker + " token=root-message-alias-secret"},
                            },
                        }
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootMessageAliasHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-message-alias-matrix",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-message-alias", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root message alias matrix token=root-message-alias-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    calls = payload.get("tool_calls", [])
                    self.assertEqual(
                        [call["tool"] for call in calls],
                        ["remember", "list_tasks", "remember", "list_tasks", "remember", "list_tasks", "remember", "remember", "list_tasks", "remember"],
                    )
                    sources = [call.get("metadata", {}).get("native_tool_call_source") for call in calls]
                    self.assertEqual(
                        sources,
                        [
                            "native provider root message toolCalls",
                            "native provider root message tool_call",
                            "native provider root message toolCall",
                            "native provider root message functionCall",
                            "native provider root message functionCalls",
                            "native provider root message functionCalls",
                            "native provider root message function_calls",
                            "native provider root message content functionCall",
                            "native provider root message content functionCall",
                            "native provider root message content parts functionCall",
                        ],
                    )
                    self.assertEqual(
                        [call.get("metadata", {}).get("provider_tool_call_id") for call in calls],
                        [
                            "root_message_toolcalls_memory",
                            "root_message_tool_call_tasks",
                            "root_message_toolcall_memory",
                            "root_message_function_call_tasks",
                            "root_message_functioncalls_memory",
                            "root_message_functioncalls_nested_tasks",
                            "root_message_function_calls_memory",
                            "root_message_content_memory",
                            "root_message_content_tasks",
                            "root_message_parts_memory",
                        ],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 10)
                    self.assertIn("functionResponse", json.dumps(payload.get("warnings", [])))
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))
                    self.assertNotIn("root-message-alias-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root message alias matrix token=root-message-alias-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertTrue(all(item.get("result", {}).get("status") == "ok" for item in applied_payload.get("results", [])))
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], sources)
                recall = runtime.handle_message('/recall query=native-root-message')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                variants = status.get("provider_native_tool_call_variants", [])
                for variant in [
                    "root_message_toolCalls",
                    "root_message_tool_call",
                    "root_message_toolCall",
                    "root_message_functionCall",
                    "root_message_functionCalls",
                    "root_message_function_calls",
                    "root_message_content_functionCall",
                    "root_message_content_parts_functionCall",
                ]:
                    self.assertIn(variant, variants)
                milestone_contract = status.get("milestone_contract", {})
                self.assertTrue(milestone_contract.get("root_message_wrapper_translation"), status)
                self.assertTrue(milestone_contract.get("root_message_content_function_call_alias_translation"), status)
                self.assertIn("root message toolCalls alias accepted", recall)
                self.assertIn("root message content parts functionCall accepted", recall)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn(provider_result_marker, applied + recall + json.dumps(status))
                self.assertNotIn("root-message-alias-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_root_function_call_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root FunctionCall",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "ROOT_FUNCTION_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeRootFunctionCallHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "content": "root functionCall token=root-function-secret",
                        "functionCall": {
                            "tool_use_id": "root_function_memory",
                            "name": "remember",
                            "args": {"key": "native-root-function-call", "value": "root functionCall accepted"},
                        },
                        "functionResponse": {
                            "name": "remember",
                            "response": {"content": provider_result_marker + " token=root-function-secret"},
                        },
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootFunctionCallHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-function-call",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-function-call", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root functionCall token=root-function-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember"])
                    self.assertIn("native provider root functionCall", payload["tool_calls"][0].get("reason", ""))
                    self.assertEqual(payload["tool_calls"][0]["args"]["key"], "native-root-function-call")
                    call_metadata = payload["tool_calls"][0].get("metadata", {})
                    self.assertEqual(call_metadata.get("provider_tool_call_id"), "root_function_memory")
                    self.assertEqual(call_metadata.get("native_tool_call_source"), "native provider root functionCall")
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 1)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn("root-function-secret", planned)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root functionCall token=root-function-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["root_function_memory"])
                    self.assertEqual(ledger[0].get("native_tool_call_source"), "native provider root functionCall")
                recall = runtime.handle_message('/recall query=native-root-function-call')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("root functionCall accepted", recall)
                self.assertIn("root_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("root_function_call_translation"))
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("root-function-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_root_function_calls_array_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root FunctionCalls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "ROOT_FUNCTION_CALLS_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeRootFunctionCallsHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "content": "root functionCalls token=root-functions-secret",
                        "functionCalls": [
                            {
                                "callId": "root_functions_memory",
                                "name": "remember",
                                "args": {"key": "native-root-function-calls", "value": "root functionCalls array accepted"},
                            },
                            {
                                "toolCallId": "root_functions_tasks",
                                "function": {
                                    "name": "list_tasks",
                                    "arguments": json.dumps({"status": "all", "limit": 1}),
                                },
                            },
                            {
                                "toolUseId": "root_functions_nested_function_call",
                                "functionCall": {
                                    "name": "remember",
                                    "args": {"key": "native-root-function-calls-nested", "value": "root functionCalls nested functionCall accepted"},
                                },
                            },
                        ],
                        "functionResponse": {
                            "name": "remember",
                            "response": {"content": provider_result_marker + " token=root-functions-secret"},
                        },
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootFunctionCallsHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-function-calls",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-function-calls", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root functionCalls token=root-functions-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember"])
                    self.assertTrue(all("native provider root functionCalls" in call.get("reason", "") for call in payload["tool_calls"]))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["root_functions_memory", "root_functions_tasks", "root_functions_nested_function_call"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider root functionCalls", "native provider root functionCalls", "native provider root functionCalls"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn("root-functions-secret", planned)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root functionCalls token=root-functions-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["root_functions_memory", "root_functions_tasks", "root_functions_nested_function_call"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider root functionCalls", "native provider root functionCalls", "native provider root functionCalls"])
                recall = runtime.handle_message('/recall query=native-root-function-calls')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("root functionCalls array accepted", recall)
                self.assertIn("root functionCalls nested functionCall accepted", recall)
                self.assertIn("root_functionCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_functionCalls_nested_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("root_function_calls_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("root_function_calls_nested_function_call_translation"), status)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("root-functions-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_root_function_calls_snake_alias_is_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root Function Calls Snake Alias",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "ROOT_FUNCTION_CALLS_SNAKE_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeRootFunctionCallsSnakeHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "content": "root function_calls token=root-functions-snake-secret",
                        "function_calls": [
                            {
                                "call_id": "root_functions_snake_memory",
                                "name": "remember",
                                "args": {"key": "native-root-function-calls-snake", "value": "root function_calls array accepted"},
                            },
                            {
                                "toolUseId": "root_functions_snake_tasks",
                                "function": {
                                    "name": "list_tasks",
                                    "arguments": json.dumps({"status": "all", "limit": 1}),
                                },
                            },
                            {
                                "toolUseId": "root_functions_snake_nested_function_call",
                                "functionCall": {
                                    "name": "remember",
                                    "args": {"key": "native-root-function-calls-snake-nested", "value": "root function_calls nested functionCall accepted"},
                                },
                            },
                        ],
                        "function_response": {
                            "name": "remember",
                            "response": {"content": provider_result_marker + " token=root-functions-snake-secret"},
                        },
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootFunctionCallsSnakeHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-function-calls-snake",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-function-calls-snake", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root function_calls token=root-functions-snake-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "list_tasks", "remember"])
                    self.assertTrue(all("native provider root function_calls" in call.get("reason", "") for call in payload["tool_calls"][:3]))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["root_functions_snake_memory", "root_functions_snake_tasks", "root_functions_snake_nested_function_call"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider root function_calls", "native provider root function_calls", "native provider root function_calls"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 3)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn("root-functions-snake-secret", planned)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root function_calls token=root-functions-snake-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["root_functions_snake_memory", "root_functions_snake_tasks", "root_functions_snake_nested_function_call"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider root function_calls", "native provider root function_calls", "native provider root function_calls"])
                recall = runtime.handle_message('/recall query=native-root-function-calls-snake')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("root function_calls array accepted", recall)
                self.assertIn("root function_calls nested functionCall accepted", recall)
                self.assertIn("root_function_calls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_function_calls_nested_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("root_function_calls_snake_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("root_function_calls_snake_nested_function_call_translation"), status)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("root-functions-snake-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_openai_root_tool_use_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Root ToolUse Aliases",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "ROOT_TOOL_USE_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeRootToolUseHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "content": "root toolUse aliases token=root-tool-use-secret",
                        "tool_use": {
                            "tool_use_id": "root_tool_use_memory",
                            "name": "remember",
                            "input": {"key": "native-root-tool-use", "value": "root tool_use alias accepted"},
                        },
                        "toolUse": {
                            "toolUseId": "root_toolUse_tasks",
                            "toolName": "list_tasks",
                            "inputJson": {"status": "all", "limit": "1"},
                        },
                        "tool_uses": [
                            {
                                "tool_call_id": "root_tool_uses_memory",
                                "name": "remember",
                                "input": {"key": "native-root-tool-uses", "value": "root tool_uses alias accepted"},
                            }
                        ],
                        "toolUses": [
                            {
                                "id": "root_toolUses_tasks",
                                "functionName": "list_tasks",
                                "argsJson": {"status": "all", "limit": 1},
                            }
                        ],
                        "functionResponse": {
                            "name": "remember",
                            "response": {"content": provider_result_marker + " token=root-tool-use-secret"},
                        },
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeRootToolUseHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-root-tool-use-aliases",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-root-tool-use", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native root toolUse aliases token=root-tool-use-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    calls = payload.get("tool_calls", [])
                    self.assertEqual([call["tool"] for call in calls], ["remember", "list_tasks", "remember", "list_tasks"])
                    sources = [call.get("metadata", {}).get("native_tool_call_source") for call in calls]
                    self.assertEqual(
                        sources,
                        [
                            "native provider root tool_use",
                            "native provider root toolUse",
                            "native provider root tool_uses",
                            "native provider root toolUses",
                        ],
                    )
                    self.assertEqual(
                        [call.get("metadata", {}).get("provider_tool_call_id") for call in calls],
                        ["root_tool_use_memory", "root_toolUse_tasks", "root_tool_uses_memory", "root_toolUses_tasks"],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 4)
                    self.assertIn("tool_result", json.dumps(payload.get("warnings", [])).lower())
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))
                    self.assertNotIn("root-tool-use-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native root toolUse aliases token=root-tool-use-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertTrue(all(item.get("result", {}).get("status") == "ok" for item in applied_payload.get("results", [])))
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], sources)
                recall = runtime.handle_message('/recall query=native-root-tool')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                variants = status.get("provider_native_tool_call_variants", [])
                for variant in ["root_tool_use", "root_toolUse", "root_tool_uses", "root_toolUses"]:
                    self.assertIn(variant, variants)
                self.assertTrue(status.get("milestone_contract", {}).get("root_tool_use_alias_translation"), status)
                self.assertIn("root tool_use alias accepted", recall)
                self.assertIn("root tool_uses alias accepted", recall)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn(provider_result_marker, applied + recall + json.dumps(status))
                self.assertNotIn("root-tool-use-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_message_tool_use_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Message ToolUse Aliases",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "MESSAGE_TOOL_USE_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeMessageToolUseHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "message toolUse aliases token=message-tool-use-secret",
                                    "tool_use": {
                                        "tool_use_id": "message_tool_use_memory",
                                        "name": "remember",
                                        "input": {"key": "native-message-tool-use", "value": "message tool_use alias accepted"},
                                    },
                                    "toolUse": {
                                        "toolUseId": "message_toolUse_tasks",
                                        "toolName": "list_tasks",
                                        "inputJson": {"status": "all", "limit": "1"},
                                    },
                                    "tool_uses": [
                                        {
                                            "tool_call_id": "message_tool_uses_memory",
                                            "name": "remember",
                                            "input": {"key": "native-message-tool-uses", "value": "message tool_uses alias accepted"},
                                        }
                                    ],
                                    "toolUses": [
                                        {
                                            "id": "message_toolUses_tasks",
                                            "functionName": "list_tasks",
                                            "argsJson": {"status": "all", "limit": 1},
                                        }
                                    ],
                                    "functionResponse": {
                                        "name": "remember",
                                        "response": {"content": provider_result_marker + " token=message-tool-use-secret"},
                                    },
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeMessageToolUseHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-message-tool-use-aliases",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-message-tool-use", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native message toolUse aliases token=message-tool-use-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    calls = payload.get("tool_calls", [])
                    self.assertEqual([call["tool"] for call in calls], ["remember", "list_tasks", "remember", "list_tasks"])
                    sources = [call.get("metadata", {}).get("native_tool_call_source") for call in calls]
                    self.assertEqual(
                        sources,
                        [
                            "native provider message tool_use",
                            "native provider message toolUse",
                            "native provider message tool_uses",
                            "native provider message toolUses",
                        ],
                    )
                    self.assertEqual(
                        [call.get("metadata", {}).get("provider_tool_call_id") for call in calls],
                        ["message_tool_use_memory", "message_toolUse_tasks", "message_tool_uses_memory", "message_toolUses_tasks"],
                    )
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 4)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))
                    self.assertNotIn("message-tool-use-secret", planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native message toolUse aliases token=message-tool-use-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertTrue(all(item.get("result", {}).get("status") == "ok" for item in applied_payload.get("results", [])))
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], sources)
                recall = runtime.handle_message('/recall query=native-message-tool')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                variants = status.get("provider_native_tool_call_variants", [])
                for variant in ["message_tool_use", "message_toolUse", "message_tool_uses", "message_toolUses"]:
                    self.assertIn(variant, variants)
                self.assertTrue(status.get("milestone_contract", {}).get("message_tool_use_alias_translation"), status)
                self.assertIn("message tool_use alias accepted", recall)
                self.assertIn("message tool_uses alias accepted", recall)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn(provider_result_marker, applied + recall + json.dumps(status))
                self.assertNotIn("message-tool-use-secret", applied + recall + json.dumps(status))
            finally:
                runtime.close()

    def test_openai_message_function_calls_aliases_are_translated(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Message Function Calls",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            captured_payloads = []
            provider_result_marker = "MESSAGE_FUNCTION_CALLS_RESPONSE_SHOULD_NOT_SURFACE"

            class FakeMessageFunctionCallsHTTPResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def read(self) -> bytes:
                    return json.dumps({
                        "choices": [
                            {
                                "message": {
                                    "content": "message functionCalls token=message-functions-secret",
                                    "functionCall": {
                                        "callId": "message_function_call_memory",
                                        "name": "remember",
                                        "args": {"key": "native-message-function-call", "value": "message functionCall accepted"},
                                    },
                                    "functionCalls": [
                                        {
                                            "callId": "message_functions_memory",
                                            "name": "remember",
                                            "args": {"key": "native-message-function-calls", "value": "message functionCalls accepted"},
                                        },
                                        {
                                            "toolUseId": "message_functions_tasks",
                                            "function": {
                                                "name": "list_tasks",
                                                "arguments": json.dumps({"status": "all", "limit": 1}),
                                            },
                                        },
                                    ],
                                    "function_calls": {
                                        "call_id": "message_functions_snake_memory",
                                        "function_call": {
                                            "name": "remember",
                                            "args": {"key": "native-message-function-calls-snake", "value": "message function_calls accepted"},
                                        },
                                    },
                                    "functionResponse": {
                                        "name": "remember",
                                        "response": {"content": provider_result_marker + " token=message-functions-secret"},
                                    },
                                }
                            }
                        ]
                    }).encode("utf-8")

            def fake_urlopen(request, timeout=0):
                captured_payloads.append(json.loads(request.data.decode("utf-8")))
                return FakeMessageFunctionCallsHTTPResponse()

            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-message-function-calls",
                    auto_model_planning=True,
                ),
                adapter=OpenAICompatibleAdapter(model="fake-native-message-function-calls", base_url="http://127.0.0.1:9/v1"),
            )
            try:
                with mock.patch("offsec_agent_harness.model_adapters.urllib.request.urlopen", side_effect=fake_urlopen):
                    planned = runtime.handle_message('/auto model=true prompt="native message functionCalls token=message-functions-secret"')
                    payload = json.loads(planned.split("\n", 1)[1])
                    self.assertEqual(payload["mode"], "plan_only")
                    self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "remember", "list_tasks", "remember"])
                    self.assertIn("native provider message functionCall", payload["tool_calls"][0].get("reason", ""))
                    self.assertIn("native provider message functionCalls", payload["tool_calls"][1].get("reason", ""))
                    self.assertIn("native provider message functionCalls", payload["tool_calls"][2].get("reason", ""))
                    self.assertIn("native provider message function_calls", payload["tool_calls"][3].get("reason", ""))
                    call_metadata = [call.get("metadata", {}) for call in payload["tool_calls"]]
                    self.assertEqual([item.get("provider_tool_call_id") for item in call_metadata], ["message_function_call_memory", "message_functions_memory", "message_functions_tasks", "message_functions_snake_memory"])
                    self.assertEqual([item.get("native_tool_call_source") for item in call_metadata], ["native provider message functionCall", "native provider message functionCalls", "native provider message functionCalls", "native provider message function_calls"])
                    self.assertEqual(payload.get("metadata", {}).get("native_tool_call_count"), 4)
                    self.assertNotIn("message-functions-secret", planned)
                    self.assertNotIn(provider_result_marker, planned + json.dumps(payload))

                    applied = runtime.handle_message('/auto apply=true model=true prompt="native message functionCalls token=message-functions-secret"')
                    applied_payload = json.loads(applied.split("\n", 1)[1])
                    self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "ok", "ok", "ok"])
                    ledger = applied_payload.get("execution_ledger", [])
                    self.assertEqual([item.get("provider_tool_call_id") for item in ledger], ["message_function_call_memory", "message_functions_memory", "message_functions_tasks", "message_functions_snake_memory"])
                    self.assertEqual([item.get("native_tool_call_source") for item in ledger], ["native provider message functionCall", "native provider message functionCalls", "native provider message functionCalls", "native provider message function_calls"])
                recall = runtime.handle_message('/recall query=native-message-function-calls')
                status = runtime.registry.run("runtime_status", {}).data.get("native_tool_calling", {})
                self.assertIn("message functionCall accepted", runtime.handle_message('/recall query=native-message-function-call'))
                self.assertIn("message functionCalls accepted", recall)
                self.assertIn("message function_calls accepted", recall)
                self.assertIn("message_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_functionCalls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_function_calls", status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_function_calls_nested_functionCall", status.get("provider_native_tool_call_variants", []))
                self.assertTrue(status.get("milestone_contract", {}).get("message_function_call_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("message_function_calls_alias_translation"), status)
                self.assertTrue(status.get("milestone_contract", {}).get("message_function_calls_nested_function_call_translation"), status)
                self.assertTrue(captured_payloads)
                self.assertEqual(captured_payloads[0].get("tool_choice"), "auto")
                self.assertNotIn("message-functions-secret", applied + recall + json.dumps(status))
                self.assertNotIn(provider_result_marker, applied + recall)
            finally:
                runtime.close()

    def test_model_tool_call_planning_uses_provider_fallback_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Tool Fallback",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "fallback-should-not-run.txt"
            fallback_adapter = FakeFallbackToolPlanAdapter(marker)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-tool-fallback",
                    auto_model_planning=True,
                ),
                adapter=FallbackModelAdapter([FakeFailingToolPlanAdapter(), fallback_adapter]),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="fallback native tool planning token=fallback-secret"')
                payload = json.loads(planned.split("\n", 1)[1])
                metadata = payload.get("metadata", {})
                self.assertEqual(payload["mode"], "plan_only")
                self.assertEqual([call["tool"] for call in payload["tool_calls"]], ["remember", "run_command"])
                self.assertEqual(payload["tool_calls"][1]["args"]["execute"], False)
                self.assertEqual(metadata.get("provider"), "fallback:fake-tool-call-fallback")
                self.assertEqual(metadata.get("selected_provider"), "fake-tool-call-fallback")
                self.assertTrue(metadata.get("tool_plan_fallback"))
                self.assertTrue(metadata.get("native_tool_calls"))
                self.assertEqual(metadata.get("native_tool_call_count"), 2)
                self.assertEqual(len(metadata.get("fallback_attempts", [])), 1)
                self.assertIn("token=<REDACTED>", json.dumps(metadata.get("fallback_attempts")))
                self.assertNotIn("fallback-secret", planned)
                self.assertFalse(fallback_adapter.allow_seen)
                self.assertIn("remember", fallback_adapter.seen_tool_names)
                self.assertNotIn("approve", fallback_adapter.seen_tool_names)
                self.assertNotIn("deny", fallback_adapter.seen_tool_names)

                applied = runtime.handle_message('/auto apply=true model=true prompt="fallback native tool planning token=fallback-secret"')
                applied_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(applied_payload["mode"], "applied")
                self.assertEqual([item["result"]["status"] for item in applied_payload["results"]], ["ok", "dry_run"])
                self.assertEqual(applied_payload.get("metadata", {}).get("provider"), "fallback:fake-tool-call-fallback")
                self.assertFalse(marker.exists())
                recall = runtime.handle_message('/recall query=fallback-native')
                self.assertIn("fallback chain selected native tool plan", recall)
                self.assertNotIn("fallback-secret", applied + recall)
                looped = runtime.handle_message('/auto-loop model=true steps=1 prompt="fallback native loop trace token=fallback-secret"')
                loop_payload = json.loads(looped.split("\n", 1)[1])
                loop_trace = loop_payload.get("planner_trace", [])
                self.assertEqual(loop_payload["stop_reason"], "max_steps")
                self.assertEqual(len(loop_trace), 1)
                self.assertEqual(loop_trace[0].get("provider"), "fallback:fake-tool-call-fallback")
                self.assertEqual(loop_trace[0].get("selected_provider"), "fake-tool-call-fallback")
                self.assertTrue(loop_trace[0].get("tool_plan_fallback"))
                self.assertEqual(loop_trace[0].get("fallback_attempt_count"), 1)
                self.assertIn("token=<REDACTED>", json.dumps(loop_trace[0].get("fallback_attempts", [])))
                self.assertNotIn("fallback-secret", looped)
                self.assertFalse(marker.exists())
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
            finally:
                runtime.close()

    def test_natural_message_model_tool_calls_apply_with_provenance_and_dry_run_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Natural Native Auto",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "natural-auto-should-not-run.txt"
            adapter = FakeNaturalAutoToolPlanAdapter(marker)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-natural-auto",
                    auto_execute_natural=True,
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message("remember native-natural-auto and dry-run the safe command token=natural-auto-secret")
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["mode"], "applied")
                self.assertEqual(payload.get("trigger"), "natural_auto")
                self.assertTrue(payload.get("natural_auto_execute"))
                self.assertFalse(adapter.allow_seen)
                self.assertNotIn("approve", adapter.seen_tool_names)
                self.assertNotIn("deny", adapter.seen_tool_names)
                self.assertEqual([call["tool"] for call in payload.get("tool_calls", [])], ["remember", "run_command"])
                self.assertEqual(payload["tool_calls"][1]["args"]["execute"], False)
                self.assertEqual([item["result"]["status"] for item in payload.get("results", [])], ["ok", "dry_run"])
                ledger = payload.get("execution_ledger", [])
                self.assertEqual([item["execution_state"] for item in ledger], ["completed_without_command_execution", "dry_run_not_executed"])
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in ledger))
                self.assertFalse(ledger[1]["safe_to_claim_command_executed"])
                self.assertFalse(marker.exists())

                recall = runtime.handle_message('/recall query=native-natural-auto')
                self.assertIn("natural native auto model plan ran", recall)
                artifacts = payload.get("artifacts", {})
                json_path = Path(artifacts.get("json", ""))
                md_path = Path(artifacts.get("markdown", ""))
                self.assertTrue(json_path.is_file())
                self.assertTrue(md_path.is_file())
                transcript = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
                self.assertIn("Trigger: `natural_auto`", transcript)
                self.assertIn("Natural auto-execute: `True`", transcript)
                rel_json = json_path.relative_to(runtime.registry.harness.store.root).as_posix()
                transcript_list = runtime.registry.run("list_auto_transcripts", {"kind": "plan", "limit": 5})
                rows = transcript_list.data.get("transcripts", [])
                self.assertIn(rel_json, [item.get("path") for item in rows])
                natural_rows = [item for item in rows if item.get("path") == rel_json]
                self.assertTrue(natural_rows and natural_rows[0].get("natural_auto_execute"), transcript_list.to_dict())
                transcript_detail = runtime.registry.run("get_auto_transcript", {"path": rel_json, "max_ledger": 3})
                self.assertEqual(transcript_detail.data["summary"].get("trigger"), "natural_auto")
                self.assertTrue(transcript_detail.data["summary"].get("natural_auto_execute"))
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("natural_auto_execute_enabled"), status.to_dict())
                audit_blob = "\n".join(row[0] or "" for row in runtime.store.conn.execute("SELECT data_json FROM audit_log").fetchall())
                self.assertIn('"trigger": "natural_auto"', audit_blob)
                self.assertIn('"natural_auto_execute": true', audit_blob)
                self.assertNotIn("natural-auto-secret", response + recall + transcript + json.dumps(transcript_list.to_dict()) + json.dumps(transcript_detail.to_dict()) + audit_blob)
            finally:
                runtime.close()

    def test_model_plan_executes_allowed_command_only_with_explicit_execute_and_ledgers_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Allowed Execution",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "native-allowed-execution.txt"
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-allowed-execution",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallAllowedExecutionAdapter(marker),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="native allowed execution token=allowed-secret"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertFalse(plan_payload["tool_calls"][0]["args"]["execute"])
                self.assertEqual(plan_payload["tool_calls"][0]["validation"].get("guardrail_status"), "allow")
                self.assertEqual(plan_payload["execution_summary"]["ledger_entries"], 0)
                self.assertEqual(plan_payload["execution_summary"]["actual_command_or_process_activity"], 0)
                self.assertFalse(marker.exists())

                dry_applied = runtime.handle_message('/auto apply=true model=true prompt="native allowed execution token=allowed-secret"')
                dry_payload = json.loads(dry_applied.split("\n", 1)[1])
                dry_ledger = dry_payload.get("execution_ledger", [])
                self.assertEqual([item["result"]["status"] for item in dry_payload["results"]], ["dry_run"])
                self.assertEqual(dry_ledger[0]["execution_state"], "dry_run_not_executed")
                self.assertFalse(dry_ledger[0]["actual_command_or_process_activity"])
                self.assertFalse(dry_ledger[0]["safe_to_claim_tool_ran"])
                self.assertFalse(dry_ledger[0]["safe_to_claim_command_executed"])
                self.assertEqual(dry_payload["execution_summary"]["dry_run"], 1)
                self.assertEqual(dry_payload["execution_summary"]["claimable_tool_runs"], 0)
                self.assertEqual(dry_payload["execution_summary"]["claimable_command_executions"], 0)
                self.assertFalse(marker.exists())

                executed = runtime.handle_message('/auto apply=true model=true execute=true prompt="native allowed execution token=allowed-secret"')
                executed_payload = json.loads(executed.split("\n", 1)[1])
                ledger = executed_payload.get("execution_ledger", [])
                self.assertEqual([item["result"]["status"] for item in executed_payload["results"]], ["executed"])
                self.assertEqual(marker.read_text(encoding="utf-8"), "native-allowed-executed")
                self.assertEqual(ledger[0]["execution_state"], "executed_or_started")
                self.assertTrue(ledger[0]["actual_command_or_process_activity"])
                self.assertTrue(ledger[0]["safe_to_claim_tool_ran"])
                self.assertTrue(ledger[0]["safe_to_claim_command_executed"])
                self.assertEqual(ledger[0]["guardrail_status"], "allow")
                self.assertEqual(executed_payload["execution_summary"]["actual_command_or_process_activity"], 1)
                self.assertEqual(executed_payload["execution_summary"]["claimable_tool_runs"], 1)
                self.assertEqual(executed_payload["execution_summary"]["claimable_command_executions"], 1)
                self.assertEqual(executed_payload["execution_summary"]["non_claimable_results"], 0)
                self.assertTrue(Path(ledger[0]["artifacts"]["execution"]).exists())
                self.assertTrue(executed_payload["transcript_artifact_written"])
                artifact_paths = executed_payload.get("artifacts", {})
                json_path = Path(artifact_paths.get("json", ""))
                md_path = Path(artifact_paths.get("markdown", ""))
                self.assertTrue(json_path.exists())
                self.assertTrue(md_path.exists())
                transcript = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Native Tool-Calling Auto Plan", transcript)
                self.assertIn("Execution summary", transcript)
                self.assertIn("Execution ledger", transcript)
                self.assertIn("claimable command executions: `1`", transcript)
                self.assertIn("actual_command_or_process_activity=`True`", transcript)
                self.assertNotIn("allowed-secret", transcript)
                audit_events = [row["event"] for row in runtime.store.list_audit(runtime.session_id, limit=20)]
                self.assertIn("auto_plan_apply", audit_events)

                bridge = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text='!phobos /auto apply=true model=true execute=off prompt="native apply chat token=apply-secret"', channel_id="C-apply", user_id="U-apply", message_id="M-apply"),
                    BridgeConfig(platform="discord", allowed_channel_ids=("C-apply",), allowed_user_ids=("U-apply",), command_prefix="!phobos", max_response_chars=1200),
                )
                self.assertEqual(bridge.status, "handled")
                self.assertIn("Auto plan applied through the guarded registry boundary", bridge.response)
                self.assertIn("dry_run=1", bridge.response)
                self.assertIn("actual_command_or_process_activity=0", bridge.response)
                self.assertIn("claimable_command_executions=0", bridge.response)
                self.assertNotIn("apply-secret", json.dumps(bridge.to_dict()))
                self.assertNotIn("allowed-secret", planned + dry_applied + executed)
            finally:
                runtime.close()

    def test_model_planned_scanner_wrappers_dry_run_without_explicit_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Scanner Execute Boundary",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-scanner-execution-boundary",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallScannerExecutionAdapter(),
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="native scanner execute boundary token=scanner-secret"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual(plan_payload["tool_calls"][0]["tool"], "nmap_scan")
                self.assertFalse(plan_payload["tool_calls"][0]["args"]["execute"])
                self.assertEqual(plan_payload["tool_calls"][0]["validation"].get("guardrail_status"), "allow")
                self.assertIn("nmap_scan planned with execute=false", json.dumps(plan_payload["warnings"]))

                explicit_plan = runtime.handle_message('/auto model=true execute=true prompt="native scanner execute boundary token=scanner-secret"')
                explicit_payload = json.loads(explicit_plan.split("\n", 1)[1])
                self.assertTrue(explicit_payload["tool_calls"][0]["args"]["execute"])

                with mock.patch("offsec_agent_harness.agent_tools.subprocess.run", side_effect=AssertionError("scanner execution should stay dry-run")) as run_mock:
                    dry_applied = runtime.handle_message('/auto apply=true model=true prompt="native scanner execute boundary token=scanner-secret"')
                    dry_payload = json.loads(dry_applied.split("\n", 1)[1])
                    dry_ledger = dry_payload.get("execution_ledger", [])
                    self.assertEqual([item["result"]["status"] for item in dry_payload["results"]], ["dry_run"])
                    self.assertEqual(dry_ledger[0]["tool"], "nmap_scan")
                    self.assertEqual(dry_ledger[0]["execution_state"], "dry_run_not_executed")
                    self.assertFalse(dry_ledger[0]["command_execution_requested"])
                    self.assertFalse(dry_ledger[0]["actual_command_or_process_activity"])
                    self.assertFalse(dry_ledger[0]["safe_to_claim_command_executed"])

                    looped = runtime.handle_message('/auto-loop model=true steps=1 prompt="native scanner loop token=scanner-secret"')
                    loop_payload = json.loads(looped.split("\n", 1)[1])
                    loop_ledger = loop_payload.get("execution_ledger", [])
                    self.assertEqual(loop_payload["steps_executed"], 1)
                    self.assertEqual(loop_ledger[0]["tool"], "nmap_scan")
                    self.assertEqual(loop_ledger[0]["execution_state"], "dry_run_not_executed")
                    self.assertFalse(loop_ledger[0]["actual_command_or_process_activity"])
                    run_mock.assert_not_called()
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                self.assertNotIn("scanner-secret", planned + explicit_plan + dry_applied + looped)
            finally:
                runtime.close()

    def test_native_auto_slash_flags_parse_off_and_reject_ambiguous_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Slash Flag Safety",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "native-flag-should-not-execute.txt"
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-slash-flags",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallAllowedExecutionAdapter(marker),
            )
            try:
                self.assertEqual(
                    runtime.handle_message('/auto apply=maybe model=on prompt="native invalid apply flag"'),
                    "apply must be a boolean.",
                )
                self.assertEqual(
                    runtime.handle_message('/auto execute=maybe model=on prompt="native invalid execute flag"'),
                    "execute must be a boolean.",
                )
                self.assertEqual(
                    runtime.handle_message('/auto model=maybe prompt="native invalid model flag"'),
                    "model must be a boolean.",
                )
                self.assertEqual(
                    runtime.handle_message('/auto-loop steps=1.5 model=on prompt="native invalid steps flag"'),
                    "steps must be an integer.",
                )

                dry_applied = runtime.handle_message('/auto apply=on model=on execute=off prompt="native flag safety token=flag-secret"')
                dry_payload = json.loads(dry_applied.split("\n", 1)[1])
                self.assertEqual(dry_payload["mode"], "applied")
                self.assertFalse(dry_payload["execute"] if "execute" in dry_payload else dry_payload["tool_calls"][0]["args"].get("execute"))
                self.assertEqual(dry_payload["results"][0]["result"]["status"], "dry_run")
                self.assertFalse(dry_payload["execution_ledger"][0]["actual_command_or_process_activity"])
                self.assertFalse(marker.exists())

                looped = runtime.handle_message('/auto-loop steps=1 model=on execute=off prompt="native flag loop token=flag-secret"')
                loop_payload = json.loads(looped.split("\n", 1)[1])
                self.assertFalse(loop_payload["execute"])
                self.assertEqual(loop_payload["steps_executed"], 1)
                self.assertEqual(loop_payload["execution_ledger"][0]["execution_state"], "dry_run_not_executed")
                self.assertFalse(loop_payload["execution_ledger"][0]["actual_command_or_process_activity"])
                self.assertFalse(marker.exists())
                self.assertNotIn("flag-secret", dry_applied + looped)
            finally:
                runtime.close()

    def test_model_plan_previews_guardrails_and_apply_queues_confirm_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Guardrail Boundary",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            confirm_marker = tmp_path / "confirm-should-not-run.txt"
            block_marker = tmp_path / "block-should-not-run.txt"
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-guardrails",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallGuardrailAdapter(confirm_marker, block_marker),
            )
            try:
                planned = runtime.handle_message('/auto model=true execute=true prompt="native guardrail boundary plan"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual([call["validation"].get("guardrail_status") for call in plan_payload["tool_calls"]], ["confirm", "block"])
                for call in plan_payload["tool_calls"]:
                    preview = call["validation"].get("guardrail_preview", {})
                    self.assertTrue(preview.get("no_target_activity"))
                    self.assertFalse(preview.get("evidence_written"))
                    self.assertFalse(preview.get("approval_queued"))
                self.assertIn("will require guardrail approval", json.dumps(plan_payload["warnings"]))
                self.assertIn("will be blocked by guardrails", json.dumps(plan_payload["warnings"]))
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                plan_audit_events = [row["event"] for row in runtime.store.list_audit(runtime.session_id, limit=20)]
                self.assertNotIn("tool_call", plan_audit_events)

                applied = runtime.handle_message('/auto apply=true model=true execute=true prompt="native guardrail boundary plan"')
                apply_payload = json.loads(applied.split("\n", 1)[1])
                result_statuses = [item["result"]["status"] for item in apply_payload["results"]]
                self.assertEqual(result_statuses, ["needs_approval", "blocked"])
                apply_ledger = apply_payload.get("execution_ledger", [])
                self.assertEqual([item["execution_state"] for item in apply_ledger], ["queued_for_approval", "blocked"])
                self.assertTrue(apply_ledger[0]["approval_queued"])
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in apply_ledger))
                self.assertFalse(any(item["safe_to_claim_command_executed"] for item in apply_ledger))
                pending = runtime.store.list_approvals(runtime.session_id, status="pending")
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["tool_name"], "run_command")
                self.assertFalse(confirm_marker.exists())
                self.assertFalse(block_marker.exists())
            finally:
                runtime.close()

    def test_native_confirm_plan_requires_direct_operator_approve_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Operator Approval Replay",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            marker = tmp_path / "native-approval-replay.txt"
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-approval-replay",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallOperatorApprovalReplayAdapter(marker),
            )
            try:
                planned = runtime.handle_message('/auto model=true execute=true prompt="native approval replay token=approval-replay-secret"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual(plan_payload["tool_calls"][0]["tool"], "run_command")
                self.assertTrue(plan_payload["tool_calls"][0]["args"]["execute"])
                self.assertEqual(plan_payload["tool_calls"][0]["validation"].get("guardrail_status"), "confirm")
                preview = plan_payload["tool_calls"][0]["validation"].get("guardrail_preview", {})
                self.assertTrue(preview.get("no_target_activity"))
                self.assertFalse(preview.get("approval_queued"))
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                self.assertFalse(marker.exists())

                applied = runtime.handle_message('/auto apply=true model=true execute=true prompt="native approval replay token=approval-replay-secret"')
                apply_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(apply_payload["mode"], "applied")
                self.assertEqual(apply_payload["results"][0]["result"]["status"], "needs_approval")
                ledger = apply_payload.get("execution_ledger", [])
                self.assertEqual(ledger[0]["execution_state"], "queued_for_approval")
                self.assertTrue(ledger[0]["approval_queued"])
                self.assertFalse(ledger[0]["actual_command_or_process_activity"])
                self.assertFalse(ledger[0]["safe_to_claim_command_executed"])
                approval_id = int(ledger[0]["approval_id"])
                pending = runtime.store.list_approvals(runtime.session_id, status="pending")
                self.assertEqual([row["id"] for row in pending], [approval_id])
                self.assertFalse(marker.exists())

                transcript = Path(apply_payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(apply_payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("queued_for_approval", transcript)
                self.assertIn("actual_command_or_process_activity=`False`", transcript)
                self.assertNotIn("approval-replay-secret", planned + applied + transcript)

                detail_before = runtime.handle_message(f"/approval id={approval_id}")
                self.assertIn("native operator approval replay boundary", detail_before)
                approved = runtime.handle_message(f"/approve id={approval_id}")
                self.assertIn("[executed]", approved)
                self.assertEqual(marker.read_text(encoding="utf-8"), "native-approval-replayed")
                approval_row = runtime.store.get_approval(approval_id, session_id=runtime.session_id)
                self.assertIsNotNone(approval_row)
                self.assertEqual((approval_row or {}).get("status"), "approved_executed")
                detail_after = runtime.handle_message(f"/approval id={approval_id}")
                self.assertIn("approved_executed", detail_after)
                self.assertNotIn("approval-replay-secret", detail_before + approved + detail_after)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_after_approval_queue_without_feedback_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Loop Approval Stop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            confirm_marker = tmp_path / "loop-confirm-should-not-run.txt"
            adapter = FakeToolCallLoopApprovalStopAdapter(confirm_marker)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-loop-approval-stop",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true execute=true steps=4 prompt="native loop approval stop token=loop-stop-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "approval_required")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(payload.get("feedback_history_entries"), 1)
                self.assertEqual(len(adapter.prompts), 1)
                self.assertEqual(payload["steps"][0].get("terminal_result_statuses"), ["needs_approval"])
                self.assertEqual(payload["results"] if "results" in payload else [], [])
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(ledger[0]["execution_state"], "queued_for_approval")
                self.assertTrue(ledger[0]["approval_queued"])
                self.assertFalse(ledger[0]["actual_command_or_process_activity"])
                pending = runtime.store.list_approvals(runtime.session_id, status="pending")
                self.assertEqual(len(pending), 1)
                self.assertFalse(confirm_marker.exists())
                recall = runtime.handle_message('/recall query=approval-stop-bypass')
                self.assertNotIn("loop continued after approval", recall)
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("approval_required", transcript)
                self.assertIn("queued_for_approval", transcript)
                self.assertNotIn("loop-stop-secret", response + transcript)
            finally:
                runtime.close()

    def test_model_planner_cannot_approve_or_deny_queued_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Approval Action Boundary",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            approval_marker = tmp_path / "model-approval-should-not-run.txt"
            adapter = FakeToolCallApprovalActionAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-approval-actions",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                queued = runtime.registry.run(
                    "run_command",
                    {
                        "target": "app.example.test",
                        "purpose": "approval action guard fixture",
                        "command": f"curl -X POST http://127.0.0.1:1/native-approval ; printf approved > {approval_marker}",
                        "execute": True,
                    },
                )
                self.assertEqual(queued.status, "needs_approval", queued.to_dict())
                adapter.approval_id = int(queued.data["approval_id"])

                planned = runtime.handle_message('/auto model=true prompt="model tries to approve pending action"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual(plan_payload["tool_calls"], [])
                rejected = json.dumps(plan_payload.get("rejected_tool_calls", []))
                self.assertIn("Approval-control tools require an explicit direct operator command", rejected)
                self.assertNotIn("approve", adapter.seen_tool_names)
                self.assertNotIn("deny", adapter.seen_tool_names)

                applied = runtime.handle_message('/auto apply=true model=true prompt="model tries to approve pending action"')
                apply_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(apply_payload["mode"], "applied")
                self.assertEqual(apply_payload["results"], [])
                pending = runtime.store.list_approvals(runtime.session_id, status="pending")
                self.assertEqual([item["id"] for item in pending], [adapter.approval_id])
                self.assertFalse(approval_marker.exists())

                looped = runtime.handle_message('/auto-loop model=true steps=2 prompt="model tries to approve pending action"')
                loop_payload = json.loads(looped.split("\n", 1)[1])
                self.assertEqual(loop_payload["stop_reason"], "no_tool_calls")
                self.assertEqual(loop_payload["steps_executed"], 0)
                self.assertIn("Approval-control tools require an explicit direct operator command", json.dumps(loop_payload))
                self.assertFalse(approval_marker.exists())
                raw_audit = "\n".join(row[0] or "" for row in runtime.store.conn.execute("SELECT data_json FROM audit_log").fetchall())
                self.assertNotIn('"tool": "approve"', raw_audit)
                self.assertNotIn('"tool": "deny"', raw_audit)
            finally:
                runtime.close()

    def test_model_tool_call_runtime_policy_confirm_block_and_loop_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Runtime Policy Boundary",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallRuntimePolicyAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-runtime-policy",
                    auto_model_planning=True,
                    confirm_tools=("remember",),
                    blocked_tools=("workspace_read",),
                ),
                adapter=adapter,
            )
            try:
                planned = runtime.handle_message('/auto model=true prompt="native runtime policy token=policy-secret"')
                plan_payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(plan_payload["mode"], "plan_only")
                self.assertEqual([call["tool"] for call in plan_payload["tool_calls"]], ["remember", "workspace_read"])
                self.assertEqual([call["validation"].get("runtime_policy") for call in plan_payload["tool_calls"]], ["confirm_required", "blocked"])
                self.assertIn("will require approval by runtime policy", json.dumps(plan_payload.get("warnings", [])))
                self.assertIn("will be blocked by runtime policy", json.dumps(plan_payload.get("warnings", [])))
                self.assertEqual(runtime.store.list_approvals(runtime.session_id, status="pending"), [])
                self.assertNotIn("policy-secret", planned)

                applied = runtime.handle_message('/auto apply=true model=true prompt="native runtime policy token=policy-secret"')
                apply_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(apply_payload["mode"], "applied")
                self.assertEqual([item["result"]["status"] for item in apply_payload["results"]], ["needs_approval", "blocked"])
                ledger = apply_payload.get("execution_ledger", [])
                self.assertEqual([item["runtime_policy"] for item in ledger], ["confirm_required", "blocked"])
                self.assertEqual([item["execution_state"] for item in ledger], ["queued_for_approval", "blocked"])
                self.assertTrue(all(item["runtime_policy_enforced"] for item in ledger))
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in ledger))
                self.assertFalse(any(item["safe_to_claim_tool_ran"] for item in ledger))
                pending = runtime.store.list_approvals(runtime.session_id, status="pending")
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["tool_name"], "remember")
                self.assertNotIn("native runtime policy approval replayed", runtime.handle_message('/recall query=native-policy-confirm'))

                approved = runtime.handle_message(f'/approve id={pending[0]["id"]}')
                self.assertIn("native-policy-confirm", approved)
                recall = runtime.handle_message('/recall query=native-policy-confirm')
                self.assertIn("native runtime policy approval replayed", recall)
                self.assertNotIn("policy-secret", applied + approved + recall)
            finally:
                runtime.close()

            loop_adapter = FakeToolCallRuntimePolicyAdapter()
            loop_runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "loop-agent.db"),
                    session_name="native-runtime-policy-loop",
                    auto_model_planning=True,
                    confirm_tools=("remember",),
                    blocked_tools=("workspace_read",),
                ),
                adapter=loop_adapter,
            )
            try:
                looped = loop_runtime.handle_message('/auto-loop model=true steps=3 prompt="native runtime policy loop token=policy-secret"')
                loop_payload = json.loads(looped.split("\n", 1)[1])
                self.assertEqual(loop_payload["stop_reason"], "approval_or_blocked_result")
                self.assertEqual(loop_payload["steps_executed"], 1)
                self.assertEqual(len(loop_adapter.prompts), 1)
                self.assertEqual(loop_payload["steps"][0].get("terminal_result_statuses"), ["blocked", "needs_approval"])
                loop_ledger = loop_payload.get("execution_ledger", [])
                self.assertEqual([item["runtime_policy"] for item in loop_ledger], ["confirm_required", "blocked"])
                self.assertTrue(all(item["runtime_policy_enforced"] for item in loop_ledger))
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in loop_ledger))
                self.assertEqual(len(loop_runtime.store.list_approvals(loop_runtime.session_id, status="pending")), 1)
                self.assertNotIn("policy-secret", looped)
            finally:
                loop_runtime.close()

    def test_model_tool_planner_receives_bounded_redacted_runtime_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Context Handoff",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
                notes="ROE note token=context-roe-secret",
            ).save(engagement)
            adapter = FakeToolPlanContextAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-context",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                message_id = runtime.store.append_message(runtime.session_id, "user", "prior planning-context-marker note token=context-message-secret")
                runtime.registry.run(
                    "remember",
                    {"key": "planning-context-marker", "value": "memory detail token=context-memory-secret", "tags": "native-context"},
                )
                runtime.registry.run(
                    "add_task",
                    {"content": "follow up planning-context-marker task token=context-task-secret", "status": "pending"},
                )
                runtime.store.create_context_summary(
                    runtime.session_id,
                    message_id,
                    message_id,
                    "summary includes planning-context-marker token=context-summary-secret",
                )

                planned = runtime.handle_message('/auto model=true prompt="use runtime context for native planning"')
                payload = json.loads(planned.split("\n", 1)[1])
                self.assertEqual(payload["mode"], "plan_only")
                self.assertEqual(payload["tool_calls"][0]["tool"], "remember")
                metadata = payload.get("metadata", {})
                self.assertTrue(metadata.get("context_provided"), metadata)
                self.assertGreater(metadata.get("context_chars", 0), 100)
                self.assertTrue(adapter.contexts)
                context = adapter.contexts[-1]
                self.assertIn("Phobos model tool-call planning context", context)
                self.assertIn("planning-context-marker", context)
                self.assertIn("app.example.test", context)
                self.assertIn("approval_control_tools_omitted_from_model_specs", context)
                self.assertNotIn("approve", adapter.seen_tool_names)
                self.assertNotIn("deny", adapter.seen_tool_names)
                for leaked in [
                    "context-roe-secret",
                    "context-message-secret",
                    "context-memory-secret",
                    "context-task-secret",
                    "context-summary-secret",
                ]:
                    self.assertNotIn(leaked, context)
                    self.assertNotIn(leaked, json.dumps(payload))

                applied = runtime.handle_message('/auto apply=true model=true prompt="use runtime context for native planning"')
                applied_payload = json.loads(applied.split("\n", 1)[1])
                self.assertEqual(applied_payload["results"][0]["result"]["status"], "ok")
                recalled = runtime.handle_message('/recall query=native-context-handoff')
                self.assertIn("model saw redacted runtime context", recalled)
            finally:
                runtime.close()

    def test_model_auto_loop_feeds_back_tool_errors_and_writes_redacted_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Feedback Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallFeedbackAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-feedback",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native feedback loop token=feedback-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "no_tool_calls")
                self.assertEqual(payload["steps_executed"], 2)
                self.assertEqual(payload.get("feedback_history_mode"), "cumulative_redacted")
                self.assertEqual(payload.get("feedback_history_entries"), 2)
                planner_trace = payload.get("planner_trace", [])
                self.assertEqual([item.get("step") for item in planner_trace], [1, 2, 3])
                self.assertEqual([item.get("tool_call_count") for item in planner_trace], [1, 1, 0])
                self.assertTrue(all(item.get("provider") == "fake-tool-call-feedback" for item in planner_trace))
                self.assertTrue(all(item.get("context_provided") for item in planner_trace))
                self.assertGreater(planner_trace[0].get("context_chars", 0), 100)
                self.assertGreaterEqual(len(adapter.prompts), 3)
                self.assertIn("Previous Phobos tool results (cumulative, redacted", adapter.prompts[1])
                self.assertNotIn("feedback-secret", "\n".join(adapter.prompts[1:]))
                self.assertIn("token=<REDACTED>", adapter.prompts[1])
                self.assertIn("Workspace file not found", adapter.prompts[2])
                self.assertIn("Stored memory", adapter.prompts[2])
                self.assertTrue(payload["transcript_artifact_written"])
                statuses = [item["result"]["status"] for step in payload["steps"] for item in step.get("results", [])]
                self.assertEqual(statuses[:2], ["error", "ok"])
                ledger = payload.get("execution_ledger", [])
                self.assertEqual([item["execution_state"] for item in ledger[:2]], ["handler_error_no_target_execution_claimed", "completed_without_command_execution"])
                self.assertFalse(ledger[0]["safe_to_claim_tool_ran"])
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in ledger))
                execution_summary = payload.get("execution_summary", {})
                self.assertEqual(execution_summary.get("ledger_entries"), 2)
                self.assertEqual(execution_summary.get("handler_error"), 1)
                self.assertEqual(execution_summary.get("local_only_completion"), 1)
                self.assertEqual(execution_summary.get("claimable_tool_runs"), 1)
                self.assertEqual(execution_summary.get("claimable_command_executions"), 0)
                self.assertEqual(execution_summary.get("non_claimable_results"), 1)
                step_deltas = [step.get("execution_ledger_delta", []) for step in payload["steps"] if step.get("mode") == "applied"]
                self.assertEqual(len(step_deltas), 2)
                self.assertEqual([delta[0]["step"] for delta in step_deltas], [1, 2])
                self.assertEqual([delta[0]["execution_state"] for delta in step_deltas], ["handler_error_no_target_execution_claimed", "completed_without_command_execution"])
                self.assertEqual(step_deltas[0][0], ledger[0])
                status = runtime.registry.run("runtime_status", {})
                native_contract = status.data.get("native_tool_calling", {})
                self.assertTrue(native_contract.get("per_step_execution_ledger_delta"), status.to_dict())
                self.assertTrue(native_contract.get("per_step_planner_trace"), status.to_dict())
                self.assertTrue(native_contract.get("planner_trace_redacted"), status.to_dict())
                self.assertTrue(native_contract.get("followup_feedback_prompt_redacted"), status.to_dict())
                self.assertTrue(native_contract.get("milestone_contract", {}).get("followup_prompt_secret_redaction"), status.to_dict())
                self.assertTrue(native_contract.get("execution_summary_contract"), status.to_dict())
                self.assertNotIn("feedback-secret", json.dumps(payload))
                recalled = runtime.handle_message('/recall query=feedback-recovered')
                self.assertIn("model feedback loop recovered", recalled)
                json_path = Path(payload["artifacts"]["json"])
                md_path = Path(payload["artifacts"]["markdown"])
                self.assertTrue(json_path.exists())
                self.assertTrue(md_path.exists())
                transcript = json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
                self.assertIn("Planner trace", transcript)
                self.assertIn("Execution summary", transcript)
                self.assertIn("Claimable tool runs: `1`", transcript)
                self.assertIn("provider=`fake-tool-call-feedback`", transcript)
                self.assertIn("Execution ledger", transcript)
                self.assertIn("Execution ledger delta", transcript)
                self.assertIn("Workspace file not found", transcript)
                self.assertIn("feedback loop recovered", transcript)
                self.assertNotIn("feedback-secret", transcript)
                outside_transcript = tmp_path / "outside-auto-transcript.json"
                outside_transcript.write_text('{"prompt":"outside-auto-transcript-sentinel"}\n', encoding="utf-8")
                symlink_path = json_path.parent / "escape.json"
                symlink_created = False
                if hasattr(os, "symlink"):
                    try:
                        os.symlink(outside_transcript, symlink_path)
                        symlink_created = True
                    except OSError:
                        symlink_created = False
                transcript_list = runtime.registry.run("list_auto_transcripts", {"kind": "loop", "limit": 10})
                self.assertEqual(transcript_list.status, "ok", transcript_list.to_dict())
                self.assertTrue(transcript_list.data["no_target_activity"])
                self.assertFalse(transcript_list.data["raw_file_contents_emitted"])
                paths = [item["path"] for item in transcript_list.data["transcripts"]]
                rel_json = json_path.relative_to(runtime.registry.harness.store.root).as_posix()
                self.assertIn(rel_json, paths)
                if symlink_created:
                    self.assertIn("escape.json", json.dumps(transcript_list.data.get("skipped", [])))
                self.assertNotIn("outside-auto-transcript-sentinel", json.dumps(transcript_list.to_dict()))
                detail = runtime.registry.run("get_auto_transcript", {"path": rel_json, "max_ledger": 2})
                self.assertEqual(detail.status, "ok", detail.to_dict())
                self.assertFalse(detail.data["raw_file_contents_emitted"])
                self.assertEqual(detail.data["summary"]["execution_counts"]["handler_error"], 1)
                self.assertEqual(detail.data["summary"]["execution_summary"]["handler_error"], 1)
                self.assertEqual(detail.data["summary"]["execution_summary"]["claimable_tool_runs"], 1)
                self.assertEqual(detail.data["summary"]["result_count"], 2)
                self.assertEqual(detail.data["summary"].get("step_ledger_delta_count"), 2)
                self.assertEqual(detail.data["summary"].get("planner_trace_count"), 3)
                self.assertEqual([item.get("provider") for item in detail.data["summary"].get("planner_trace", [])], ["fake-tool-call-feedback", "fake-tool-call-feedback"])
                self.assertEqual([item.get("step") for item in detail.data["summary"].get("step_ledger_deltas", [])], [1, 2])
                self.assertNotIn("feedback-secret", json.dumps(detail.to_dict()))
                self.assertNotIn("outside-auto-transcript-sentinel", json.dumps(detail.to_dict()))
                ref_detail = runtime.registry.run("resolve_local_ref", {"ref": f"auto-transcript:{rel_json}"})
                self.assertEqual(ref_detail.status, "ok", ref_detail.to_dict())
                self.assertFalse(ref_detail.data["entity"]["raw_file_contents_emitted"])
                slash_detail = runtime.handle_message(f"/auto-transcript path={rel_json} max_ledger=2")
                self.assertIn("Native tool-calling transcript returned", slash_detail)
                blocked = runtime.registry.run("get_auto_transcript", {"path": "../outside-auto-transcript.json"})
                self.assertEqual(blocked.status, "blocked", blocked.to_dict())
                audit_events = [row["event"] for row in runtime.store.list_audit(runtime.session_id, limit=20)]
                self.assertIn("auto_loop", audit_events)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_on_model_error_after_feedback_without_deterministic_replan(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Model Error Stop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallModelErrorAfterFeedbackAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-model-error-stop",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native model error stop token=model-error-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "model_error")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(payload.get("feedback_history_entries"), 1)
                self.assertEqual(len(adapter.prompts), 2)
                self.assertIn("Model tool planning failed", payload.get("next_step", ""))
                steps = payload.get("steps", [])
                self.assertEqual(steps[-1].get("mode"), "model_error")
                self.assertTrue(steps[-1].get("no_tools_executed"))
                self.assertEqual(steps[-1].get("execution_ledger_delta"), [])
                model_error_plan = steps[-1].get("plan", {})
                metadata = model_error_plan.get("metadata", {})
                self.assertTrue(metadata.get("model_planner_failed"), metadata)
                self.assertTrue(metadata.get("deterministic_fallback_suppressed"), metadata)
                self.assertIn("token=<REDACTED>", json.dumps(metadata))
                self.assertIn("deterministic fallback suppressed", json.dumps(model_error_plan.get("warnings", [])))
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(len(ledger), 1)
                self.assertEqual(ledger[0]["execution_state"], "completed_without_command_execution")
                self.assertFalse(ledger[0]["actual_command_or_process_activity"])
                recalled = runtime.handle_message('/recall query=native-model-error-stop')
                self.assertIn("native model error first step ran", recalled)
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Stop reason: `model_error`", transcript)
                self.assertIn("Model planner failed after tool feedback", transcript)
                chat = runtime.render_chat_response(response, message='/auto-loop model=true prompt="native model error stop"', platform="discord")
                self.assertIn("Native tool loop stopped: `model_error`", chat)
                self.assertIn("Model tool planning failed", chat)
                self.assertNotIn("model-error-secret", response + transcript + chat + recalled)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_on_invalid_plan_after_feedback_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Invalid Plan Stop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallInvalidAfterFeedbackAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-invalid-plan-stop",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native invalid plan stop token=invalid-plan-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "invalid_plan")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(payload.get("feedback_history_entries"), 1)
                self.assertEqual(len(adapter.prompts), 2)
                steps = payload.get("steps", [])
                invalid_step = steps[-1]
                self.assertEqual(invalid_step.get("mode"), "invalid_plan")
                self.assertTrue(invalid_step.get("no_tools_executed"))
                self.assertEqual(invalid_step.get("execution_ledger_delta"), [])
                self.assertEqual(invalid_step.get("rejected_tool_call_count"), 2)
                invalid_plan = invalid_step.get("plan", {})
                self.assertEqual(invalid_plan.get("tool_calls"), [])
                self.assertEqual(len(invalid_plan.get("rejected_tool_calls", [])), 2)
                metadata = invalid_plan.get("metadata", {})
                self.assertTrue(metadata.get("all_tool_calls_rejected"), metadata)
                self.assertTrue(metadata.get("invalid_model_tool_plan"), metadata)
                self.assertTrue(metadata.get("deterministic_fallback_suppressed"), metadata)
                self.assertEqual(metadata.get("attempted_tool_call_count"), 2)
                self.assertEqual(metadata.get("accepted_tool_call_count"), 0)
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(len(ledger), 1)
                self.assertEqual(ledger[0]["execution_state"], "completed_without_command_execution")
                self.assertFalse(ledger[0]["actual_command_or_process_activity"])
                recalled = runtime.handle_message('/recall query=native-invalid-plan-stop')
                self.assertIn("native invalid plan first step ran", recalled)
                self.assertEqual(runtime.store.recall("invalid-plan-withheld", limit=5), [])
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Stop reason: `invalid_plan`", transcript)
                self.assertIn("Invalid plan stop", transcript)
                chat = runtime.render_chat_response(response, message='/auto-loop model=true prompt="native invalid plan stop"', platform="discord")
                self.assertIn("Native tool loop stopped: `invalid_plan`", chat)
                self.assertIn("invalid or rejected tool calls", chat)
                self.assertNotIn("invalid-plan-secret", response + transcript + chat + recalled)
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("invalid_plan_stop_enforced"), status.to_dict())
            finally:
                runtime.close()

    def test_model_auto_loop_respects_terminal_no_tool_response_after_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Terminal No Tool Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallTerminalNoToolAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-terminal-no-tool",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="remember terminal-stop-marker as token=terminal-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "no_tool_calls")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(len(adapter.prompts), 2)
                self.assertEqual(len(payload.get("execution_ledger", [])), 1)
                self.assertEqual(payload["execution_ledger"][0]["execution_state"], "completed_without_command_execution")
                self.assertFalse(payload["execution_ledger"][0]["actual_command_or_process_activity"])
                terminal_step = payload["steps"][-1]
                self.assertEqual(terminal_step["mode"], "no_plan")
                self.assertTrue(terminal_step["no_tools_executed"])
                self.assertEqual(terminal_step["execution_ledger_delta"], [])
                terminal_plan = terminal_step["plan"]
                self.assertEqual(terminal_plan["summary"], "model intentionally stopped after the successful native tool result")
                metadata = terminal_plan.get("metadata", {})
                self.assertTrue(metadata.get("terminal_no_tool_plan_respected"), metadata)
                self.assertTrue(metadata.get("deterministic_fallback_suppressed"), metadata)
                artifacts = payload.get("artifacts", {})
                json_path = Path(artifacts.get("json", ""))
                markdown_path = Path(artifacts.get("markdown", ""))
                transcript = json_path.read_text(encoding="utf-8") + markdown_path.read_text(encoding="utf-8")
                self.assertIn("No-dispatch step: no tools were dispatched for this step.", transcript)
                rel_json = json_path.relative_to(runtime.registry.harness.store.root).as_posix()
                detail = runtime.registry.run("get_auto_transcript", {"path": rel_json, "max_ledger": 5})
                self.assertEqual(detail.data["summary"].get("no_dispatch_step_count"), 1)
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("terminal_no_tool_no_dispatch_step"), status.to_dict())
                chat = runtime.render_chat_response(response, message='/auto-loop model=true prompt="terminal no tool"', platform="discord")
                self.assertIn("no-dispatch terminal step", chat)
                self.assertNotIn("terminal-secret", json.dumps(payload) + transcript + json.dumps(detail.to_dict()) + chat)
                recalled = runtime.handle_message('/recall query=terminal-stop-marker')
                self.assertIn("model ran exactly once", recalled)
                self.assertNotIn("terminal-secret", response + recalled)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_duplicate_plans_without_second_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Duplicate Plan Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallDuplicatePlanAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-duplicate-plan",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native duplicate loop token=duplicate-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "duplicate_plan")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(payload.get("feedback_history_entries"), 1)
                self.assertEqual(len(adapter.prompts), 2)
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(len(ledger), 1)
                self.assertEqual(ledger[0]["execution_state"], "completed_without_command_execution")
                self.assertFalse(ledger[0]["actual_command_or_process_activity"])
                duplicate_step = payload["steps"][-1]
                self.assertEqual(duplicate_step["mode"], "stopped_duplicate_plan")
                self.assertTrue(duplicate_step["no_tools_executed"])
                self.assertEqual(duplicate_step["execution_ledger_delta"], [])
                self.assertEqual(duplicate_step["duplicate_tool_call_count"], 1)
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Duplicate plan stop", transcript)
                self.assertNotIn("duplicate-secret", response + transcript)
                recalled = runtime.handle_message('/recall query=duplicate-loop-marker')
                self.assertIn("native duplicate loop ran once", recalled)
                self.assertNotIn("duplicate-secret", recalled)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_partial_duplicate_batch_without_partial_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Partial Duplicate Plan Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallPartialDuplicatePlanAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-partial-duplicate-plan",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native partial duplicate loop token=partial-duplicate-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "duplicate_plan")
                self.assertEqual(payload["steps_executed"], 1)
                self.assertEqual(len(adapter.prompts), 2)
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(len(ledger), 1)
                self.assertEqual(ledger[0]["tool"], "remember")
                self.assertEqual(ledger[0]["execution_state"], "completed_without_command_execution")
                duplicate_step = payload["steps"][-1]
                self.assertEqual(duplicate_step["mode"], "stopped_duplicate_plan")
                self.assertEqual(duplicate_step["duplicate_detection"], "tool_args_any_repeat")
                self.assertEqual(duplicate_step["duplicate_tool_call_count"], 1)
                self.assertEqual(duplicate_step["new_tool_call_count"], 1)
                self.assertTrue(duplicate_step["no_tools_executed"])
                self.assertEqual(duplicate_step["execution_ledger_delta"], [])
                self.assertIn("partial duplicate loop ran once", runtime.handle_message('/recall query=partial-duplicate-loop-marker'))
                withheld = runtime.handle_message('/recall query=partial-duplicate-new-call')
                self.assertNotIn("this call must be withheld", withheld)
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("new calls withheld=1", transcript)
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("partial_duplicate_plan_stop_enforced"), status.to_dict())
                self.assertNotIn("partial-duplicate-secret", response + transcript + withheld)
            finally:
                runtime.close()

    def test_model_auto_loop_stops_same_step_duplicate_batch_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Same Step Duplicate Plan Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallSameStepDuplicatePlanAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-same-step-duplicate-plan",
                    auto_model_planning=True,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true steps=4 prompt="native same-step duplicate loop token=same-step-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "duplicate_plan")
                self.assertEqual(payload["steps_executed"], 0)
                self.assertEqual(payload.get("feedback_history_entries"), 0)
                self.assertEqual(len(adapter.prompts), 1)
                self.assertEqual(payload.get("execution_ledger", []), [])
                duplicate_step = payload["steps"][-1]
                self.assertEqual(duplicate_step["mode"], "stopped_duplicate_plan")
                self.assertEqual(duplicate_step["duplicate_detection"], "tool_args_same_step_repeat")
                self.assertEqual(duplicate_step["duplicate_tool_call_count"], 1)
                self.assertEqual(duplicate_step["new_tool_call_count"], 1)
                self.assertTrue(duplicate_step["no_tools_executed"])
                self.assertEqual(duplicate_step["execution_ledger_delta"], [])
                withheld = runtime.handle_message('/recall query=same-step-duplicate-marker')
                self.assertNotIn("this duplicate batch must not dispatch", withheld)
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("tool_args_same_step_repeat", transcript)
                self.assertIn("new calls withheld=1", transcript)
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("same_step_duplicate_plan_stop_enforced"), status.to_dict())
                self.assertNotIn("same-step-secret", response + transcript + withheld)
            finally:
                runtime.close()

    def test_model_auto_loop_enforces_max_step_budget_with_clear_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Model Max Step Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            adapter = FakeToolCallMaxStepsAdapter()
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="model-max-steps",
                    auto_model_planning=True,
                    max_auto_steps=2,
                ),
                adapter=adapter,
            )
            try:
                response = runtime.handle_message('/auto-loop model=true prompt="native max steps token=maxstep-secret"')
                payload = json.loads(response.split("\n", 1)[1])
                self.assertEqual(payload["stop_reason"], "max_steps")
                self.assertEqual(payload["steps_requested"], 2)
                self.assertEqual(payload["max_steps_budget"], 2)
                self.assertTrue(payload["max_steps_budget_exhausted"])
                self.assertEqual(payload["steps_executed"], 2)
                self.assertEqual(payload.get("feedback_history_entries"), 2)
                self.assertEqual(len(adapter.prompts), 2)
                self.assertIn("Max-step budget reached", payload.get("next_step", ""))
                ledger = payload.get("execution_ledger", [])
                self.assertEqual(len(ledger), 2)
                self.assertEqual([item["step"] for item in ledger], [1, 2])
                self.assertEqual([item["execution_state"] for item in ledger], ["completed_without_command_execution", "completed_without_command_execution"])
                self.assertFalse(any(item["actual_command_or_process_activity"] for item in ledger))
                self.assertFalse(any(item["safe_to_claim_command_executed"] for item in ledger))
                self.assertEqual([step["mode"] for step in payload["steps"]], ["applied", "applied"])
                status = runtime.registry.run("runtime_status", {})
                self.assertTrue(status.data.get("native_tool_calling", {}).get("max_steps_budget_stop_enforced"), status.to_dict())
                self.assertTrue(status.data.get("native_tool_calling", {}).get("model_error_stop_enforced"), status.to_dict())
                transcript = Path(payload["artifacts"]["json"]).read_text(encoding="utf-8") + Path(payload["artifacts"]["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Stop reason: `max_steps`", transcript)
                self.assertIn("Max-step budget exhausted: `True`", transcript)
                self.assertIn("Max-step budget reached", transcript)
                self.assertNotIn("maxstep-secret", response + transcript)
                chat = runtime.render_chat_response(response, message='/auto-loop model=true prompt="native max steps"', platform="discord")
                self.assertIn("Max-step budget exhausted", chat)
                self.assertIn("actual_command_or_process_activity=0", chat)
            finally:
                runtime.close()

    def test_native_auto_gateway_endpoints_and_bridge_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Native Gateway Loop",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            runtime = OffSecAgentRuntime(
                AgentRuntimeConfig(
                    engagement_path=str(engagement),
                    db_path=str(tmp_path / "agent.db"),
                    session_name="native-gateway-loop",
                    auto_model_planning=True,
                ),
                adapter=FakeToolCallFeedbackAdapter(),
            )
            gateway = None
            try:
                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address

                def post(route: str, body: dict[str, object]) -> dict[str, object]:
                    req = urllib.request.Request(
                        f"http://{host}:{port}{route}",
                        data=json.dumps(body).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5) as response:
                        return json.loads(response.read().decode("utf-8"))

                with urllib.request.urlopen(f"http://{host}:{port}/routes", timeout=5) as response:
                    routes = json.loads(response.read().decode("utf-8"))
                self.assertIn("/auto", routes.get("paths", []))
                self.assertIn("/auto-loop", routes.get("paths", []))
                self.assertIn("/auto-transcripts", routes.get("paths", []))
                self.assertIn("/auto-transcript", routes.get("paths", []))
                with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
                    dashboard = response.read().decode("utf-8")
                self.assertIn("Native Tool Loop", dashboard)

                auto = post("/auto", {"prompt": "native gateway plan token=gateway-secret", "model": "true", "apply": "false"})
                self.assertIn("Auto plan (no tools executed)", str(auto.get("response", "")))
                self.assertNotIn("gateway-secret", json.dumps(auto))

                loop = post("/auto-loop", {"prompt": "native gateway loop token=loop-secret", "model": True, "steps": "4"})
                loop_payload = json.loads(str(loop["response"]).split("\n", 1)[1])
                self.assertEqual(loop_payload["stop_reason"], "no_tool_calls")
                self.assertEqual(loop_payload["steps_executed"], 2)
                self.assertTrue(loop_payload["transcript_artifact_written"])
                self.assertNotIn("loop-secret", json.dumps(loop))

                with urllib.request.urlopen(f"http://{host}:{port}/auto-transcripts?kind=loop&limit=5", timeout=5) as response:
                    transcript_index = json.loads(response.read().decode("utf-8"))
                self.assertEqual(transcript_index.get("status"), "ok", transcript_index)
                transcript_rows = transcript_index.get("data", {}).get("transcripts", [])
                self.assertTrue(transcript_rows)
                self.assertTrue(transcript_index.get("data", {}).get("no_target_activity"))
                self.assertFalse(transcript_index.get("data", {}).get("raw_file_contents_emitted"))
                transcript_path = transcript_rows[0]["path"]
                with urllib.request.urlopen(f"http://{host}:{port}/auto-transcript?" + urllib.parse.urlencode({"path": transcript_path, "max_ledger": "2"}), timeout=5) as response:
                    transcript_detail = json.loads(response.read().decode("utf-8"))
                self.assertEqual(transcript_detail.get("status"), "ok", transcript_detail)
                self.assertFalse(transcript_detail.get("data", {}).get("raw_file_contents_emitted"))
                self.assertIn("execution_counts", transcript_detail.get("data", {}).get("summary", {}))
                self.assertNotIn("loop-secret", json.dumps(transcript_index) + json.dumps(transcript_detail))

                runtime_status = runtime.registry.run("runtime_status", {})
                self.assertEqual(runtime_status.status, "ok", runtime_status.to_dict())
                native_status = runtime_status.data.get("native_tool_calling", {})
                milestone_contract = native_status.get("milestone_contract", {})
                self.assertEqual(native_status.get("milestone"), "native_model_tool_calling_loop", native_status)
                self.assertTrue(native_status.get("milestone_contract_complete"), native_status)
                self.assertTrue(milestone_contract, native_status)
                self.assertTrue(all(milestone_contract.values()), native_status)
                self.assertTrue(milestone_contract.get("schema_validation_before_dispatch"), native_status)
                self.assertTrue(milestone_contract.get("guardrail_preview_before_target_activity"), native_status)
                self.assertTrue(milestone_contract.get("approval_queue_direct_replay_boundary"), native_status)
                self.assertTrue(milestone_contract.get("execution_ledger_claim_contract"), native_status)
                self.assertTrue(milestone_contract.get("provider_tool_call_id_provenance"), native_status)
                self.assertTrue(milestone_contract.get("transcript_provider_call_provenance"), native_status)
                self.assertTrue(milestone_contract.get("single_top_level_tool_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("single_content_block_tool_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("top_level_content_block_tool_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("content_parts_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("single_responses_output_tool_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("responses_stream_event_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("responses_message_tool_call_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("responses_message_tool_calls_camel_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("responses_message_tool_call_singular_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("responses_output_message_typeless_wrapper_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_message_wrapper_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_function_calls_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_function_calls_snake_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_function_calls_nested_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("root_function_calls_snake_nested_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("message_function_call_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("message_function_calls_alias_translation"), native_status)
                self.assertTrue(milestone_contract.get("message_function_calls_nested_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("legacy_function_call_translation"), native_status)
                self.assertTrue(milestone_contract.get("custom_freeform_tool_calls_rejected"), native_status)
                self.assertTrue(milestone_contract.get("followup_prompt_secret_redaction"), native_status)
                self.assertTrue(milestone_contract.get("gateway_and_bridge_surfaces"), native_status)
                self.assertTrue(native_status.get("model_planning_enabled"), native_status)
                self.assertFalse(native_status.get("natural_auto_execute_enabled"), native_status)
                self.assertTrue(native_status.get("plan_only_default"), native_status)
                self.assertTrue(native_status.get("execution_requires_operator_execute_true"), native_status)
                self.assertTrue(native_status.get("per_step_execution_ledger_delta"), native_status)
                self.assertTrue(native_status.get("one_shot_planner_trace"), native_status)
                self.assertTrue(native_status.get("execution_summary_contract"), native_status)
                self.assertTrue(native_status.get("provider_tool_call_id_provenance"), native_status)
                self.assertTrue(native_status.get("transcript_provider_call_provenance"), native_status)
                self.assertTrue(native_status.get("followup_feedback_prompt_redacted"), native_status)
                self.assertTrue(native_status.get("max_steps_budget_stop_enforced"), native_status)
                self.assertTrue(native_status.get("partial_duplicate_plan_stop_enforced"), native_status)
                self.assertTrue(native_status.get("model_error_stop_enforced"), native_status)
                self.assertTrue(native_status.get("provider_tool_result_echo_ignored"), native_status)
                self.assertIn("single_top_level_tool_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("flat_tool_calls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("content_block_tool_use", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("single_content_block_tool_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("top_level_content_block_tool_use", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("content_parts_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("single_responses_output_function_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_stream_function_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_output_message_typeless_wrapper", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_tool_calls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_toolCalls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_tool_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_toolCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("responses_message_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_message_tool_calls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_functionCalls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_functionCalls_nested_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_function_calls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("root_function_calls_nested_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_functionCalls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_function_calls", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("message_function_calls_nested_functionCall", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("legacy_function_call", native_status.get("provider_native_tool_call_variants", []))
                self.assertIn("tool_use_id", native_status.get("provider_tool_call_id_aliases", []))
                self.assertIn("function_result", native_status.get("provider_tool_result_block_types_ignored", []))
                self.assertIn("toolResult", native_status.get("provider_tool_result_block_types_ignored", []))
                self.assertIn("functionCallOutput", native_status.get("provider_tool_result_block_types_ignored", []))
                self.assertIn("toolCallResult", native_status.get("provider_tool_result_block_types_ignored", []))
                self.assertIn("custom_tool_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("server_tool_use", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("mcp_tool_use", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("computer_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("file_search_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("image_generation_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("local_shell_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("mcp_call", native_status.get("provider_unsupported_tool_call_types_rejected", []))
                self.assertIn("approve", native_status.get("approval_control_tools_hidden_from_model", []))
                self.assertIn("deny", native_status.get("approval_control_tools_hidden_from_model", []))
                self.assertIn("run_command", native_status.get("execution_capable_tools", []))
                self.assertIn("nmap_scan", native_status.get("target_affecting_tools", []))
                transcript_counts = native_status.get("transcript_counts", {})
                self.assertGreaterEqual(transcript_counts.get("plan", 0), 1)
                self.assertGreaterEqual(transcript_counts.get("loop", 0), 1)
                self.assertTrue(native_status.get("no_target_activity"))
                self.assertFalse(native_status.get("raw_file_contents_emitted"))
                self.assertIn('"native_tool_calling"', runtime.handle_message('/status'))
                self.assertNotIn("loop-secret", json.dumps(runtime_status.to_dict()))

                invalid_req = urllib.request.Request(
                    f"http://{host}:{port}/auto-loop",
                    data=json.dumps({"prompt": "bad steps", "steps": "1.5"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(invalid_req, timeout=5)
                self.assertEqual(raised.exception.code, 400)
                invalid_payload = json.loads(raised.exception.read().decode("utf-8"))
                self.assertEqual(invalid_payload.get("error"), "steps must be an integer")

                bridge = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text='!phobos /auto-loop model=true steps=4 prompt="native bridge loop token=bridge-secret"', channel_id="C-native", user_id="U-native", message_id="M-native"),
                    BridgeConfig(platform="discord", allowed_channel_ids=("C-native",), allowed_user_ids=("U-native",), command_prefix="!phobos", max_response_chars=1200),
                )
                self.assertEqual(bridge.status, "handled", bridge.to_dict())
                self.assertIn("Native tool loop stopped", bridge.response)
                self.assertIn("Actual results", bridge.response)
                self.assertIn("Execution ledger", bridge.response)
                self.assertIn("Auto loop completed", bridge.raw_response)
                self.assertNotIn("bridge-secret", bridge.response + bridge.raw_response)
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()

    def test_model_auto_loop_media_and_sealed_export_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                model_runtime = OffSecAgentRuntime(
                    AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "model-agent.db"), session_name="model", auto_model_planning=True),
                    adapter=FakePlannerAdapter(),
                )
                try:
                    planned = model_runtime.handle_message('/auto model=true prompt="remember a model planner marker"')
                    self.assertIn('"mode": "plan_only"', planned)
                    applied = model_runtime.handle_message('/auto apply=true model=true prompt="remember a model planner marker"')
                    self.assertIn('"tool": "remember"', applied)
                    looped = model_runtime.handle_message('/auto-loop model=true prompt="remember a model planner marker" steps=3')
                    self.assertIn("Auto loop completed", looped)
                    recalled = model_runtime.handle_message('/recall query=model-plan')
                    self.assertIn("model planner worked", recalled)
                finally:
                    model_runtime.close()

                media_src = Path(tmp) / "proof.txt"
                media_src.write_text("media marker token=supersecret", encoding="utf-8")
                media = runtime.registry.run("media_import", {"path": str(media_src)})
                self.assertEqual(media.status, "ok", media.to_dict())
                self.assertTrue(Path(media.artifacts["file"]).exists())
                media_list = runtime.registry.run("media_list", {})
                self.assertEqual(len(media_list.data["media"]), 1)
                media_id = media.data["media"]["id"]
                media_detail = runtime.registry.run("media_get", {"id": media_id})
                self.assertEqual(media_detail.status, "ok", media_detail.to_dict())
                self.assertTrue(media_detail.data["media"]["no_file_content_read"])
                self.assertIn("media_get", runtime.handle_message('/schemas name=media_get'))
                self.assertIn("Media/artifact", runtime.handle_message(f'/media-get id={media_id}'))
                other_media_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent.db"), session_name="other-media"))
                try:
                    other_media_id = other_media_runtime.store.create_media_artifact(
                        other_media_runtime.session_id,
                        "file",
                        "/tmp/foreign-media-secret-token-supersecret.txt",
                        "/tmp/foreign-media-secret-token-supersecret.txt",
                        "text/plain",
                        "0" * 64,
                        1,
                        {"note": "foreign media token=supersecret"},
                    )
                finally:
                    other_media_runtime.close()
                cross_media = runtime.registry.run("media_get", {"id": other_media_id})
                self.assertEqual(cross_media.status, "error", cross_media.to_dict())
                self.assertIn("not found in this session", cross_media.message)
                self.assertNotIn("supersecret", json.dumps(cross_media.to_dict()))

                missing = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_TEST_MISSING_PASSPHRASE"})
                self.assertEqual(missing.status, "error")
                os.environ["PHOBOS_TEST_SEAL"] = "correct horse battery staple"
                os.environ["PHOBOS_TEST_SEAL_WRONG"] = "wrong passphrase"
                runtime.handle_message('/remember key=sealed-client value="ACME token=supersecret" tags=sealed')
                node = runtime.handle_message('/lcm-compact title="sealed context" limit=40')
                self.assertIn("Context node", node)
                sealed = runtime.registry.run("sealed_export", {"passphrase_env": "PHOBOS_TEST_SEAL", "out": "unit.sealed.json"})
                self.assertEqual(sealed.status, "ok", sealed.to_dict())
                sealed_path = Path(sealed.data["path"])
                sealed_text = sealed_path.read_text(encoding="utf-8")
                self.assertIn("PHOBOS_SEALED_V1", sealed_text)
                self.assertNotIn("supersecret", sealed_text)
                wrong = runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_TEST_SEAL_WRONG"})
                self.assertEqual(wrong.status, "error")
            finally:
                runtime.close()
                os.environ.pop("PHOBOS_TEST_SEAL", None)
                os.environ.pop("PHOBOS_TEST_SEAL_WRONG", None)

            os.environ["PHOBOS_TEST_SEAL"] = "correct horse battery staple"
            imported_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "sealed-import.db"), session_name="sealed-import"))
            try:
                imported = imported_runtime.registry.run("sealed_import", {"path": str(sealed_path), "passphrase_env": "PHOBOS_TEST_SEAL"})
                self.assertEqual(imported.status, "ok", imported.to_dict())
                self.assertGreaterEqual(imported.data["imported_context_nodes"], 1)
                recalled = imported_runtime.handle_message('/recall query=sealed-client')
                self.assertIn("ACME", recalled)
            finally:
                imported_runtime.close()
                os.environ.pop("PHOBOS_TEST_SEAL", None)

            sealed_bytes = seal_bytes(b"sealed roundtrip", "passphrase", aad=b"unit")
            self.assertEqual(unseal_bytes(sealed_bytes, "passphrase", aad=b"unit"), b"sealed roundtrip")
            with self.assertRaises(ValueError):
                unseal_bytes(sealed_bytes, "wrong", aad=b"unit")
            tampered = sealed_bytes.replace(b"PHOBOS_SEALED_V1", b"PHOBOS_SEALED_VX", 1)
            with self.assertRaises(ValueError):
                unseal_bytes(tampered, "passphrase", aad=b"unit")

    def test_fts_auto_planner_workspace_escape_and_pack_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 2)
                status = runtime.handle_message('/status')
                self.assertIn('"fts_available"', status)
                self.assertIn('"safety_mode": "non_destructive"', status)

                runtime.handle_message("session polishmarkerfts searchable artifact")
                searched = runtime.handle_message('/search query=polishmarkerfts')
                self.assertIn("polishmarkerfts", searched)

                escaped = runtime.handle_message('/write path=../escape.txt content=nope')
                self.assertIn("escapes the engagement workspace", escaped)
                self.assertFalse((Path(tmp) / "escape.txt").exists())

                planned = runtime.handle_message('/auto prompt="remember planner-client: ACME polished engagement"')
                self.assertIn('"mode": "plan_only"', planned)
                applied = runtime.handle_message('/auto apply=true prompt="remember planner-client: ACME polished engagement"')
                self.assertIn('"tool": "remember"', applied)
                recalled = runtime.handle_message('/recall query=planner-client')
                self.assertIn("ACME polished engagement", recalled)

                auto_assess = runtime.handle_message('/auto apply=true prompt=\'assess target=10.10.0.5 type=service-enumeration purpose=version-scan command="nmap -sV 10.10.0.5"\'')
                self.assertIn('"tool": "assess_action"', auto_assess)
                self.assertIn('"status": "allow"', auto_assess)

                runtime.handle_message('/run target=app.example.test type=host purpose="secret redaction smoke" command="printf token=supersecret" execute=true')
                packed = runtime.registry.run("export_pack", {"out": "unit-pack.zip"})
                self.assertEqual(packed.status, "ok", packed.to_dict())
                pack_path = Path(packed.data["pack"])
                self.assertTrue(pack_path.exists())
                with zipfile.ZipFile(pack_path) as archive:
                    names = set(archive.namelist())
                    self.assertIn("PACK_README.md", names)
                    self.assertIn("MANIFEST.json", names)
                    self.assertIn("runtime/state.json", names)
                    combined = "\n".join(archive.read(name).decode("utf-8", errors="replace") for name in names if name.endswith(('.json', '.md', '.jsonl', '.log', '.txt')))
                self.assertNotIn("supersecret", combined)
            finally:
                runtime.close()

    def test_task_board_policy_briefing_and_session_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, engagement = self.make_runtime(tmp)
            try:
                self.assertGreaterEqual(runtime.store.schema_info()["schema_version"], 3)
                added = runtime.handle_message('/task-add content="parity polish token=supersecret"')
                self.assertIn("Task 1 added", added)
                updated = runtime.handle_message('/task-update id=1 status=in_progress')
                self.assertIn('"status": "in_progress"', updated)
                tasks = runtime.handle_message('/tasks')
                self.assertIn("parity polish", tasks)

                runtime.handle_message('/remember key=handoff-client value="ACME token=supersecret" tags=handoff')
                runtime.handle_message("portable handoff context marker")
                compact = runtime.handle_message('/compact limit=20')
                self.assertIn("Context summary", compact)
                briefing = runtime.registry.run("operator_briefing", {"query": "handoff-client"})
                self.assertEqual(briefing.status, "ok", briefing.to_dict())
                briefing_path = Path(briefing.artifacts["markdown"])
                self.assertTrue(briefing_path.exists())
                briefing_text = briefing_path.read_text(encoding="utf-8")
                self.assertIn("Phobos Agent Operator Briefing", briefing_text)
                self.assertNotIn("supersecret", briefing_text)

                exported = runtime.registry.run("export_session", {"out": "unit-handoff.json"})
                self.assertEqual(exported.status, "ok", exported.to_dict())
                handoff = Path(exported.data["path"])
                self.assertTrue(handoff.exists())
                exported_text = handoff.read_text(encoding="utf-8")
                self.assertIn("phobos-agent-session-handoff", exported_text)
                self.assertNotIn("supersecret", exported_text)
            finally:
                runtime.close()

            imported_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=str(engagement), db_path=str(Path(tmp) / "agent-import.db"), session_name="imported"))
            try:
                imported = imported_runtime.registry.run("import_session", {"path": str(handoff)})
                self.assertEqual(imported.status, "ok", imported.to_dict())
                recalled = imported_runtime.handle_message('/recall query=handoff-client')
                self.assertIn("imported:", recalled)
                imported_tasks = imported_runtime.handle_message('/tasks')
                self.assertIn("Imported from", imported_tasks)
            finally:
                imported_runtime.close()

    def test_runtime_tool_policy_confirm_and_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            EngagementROE(
                name="Policy Runtime Test",
                authorized=True,
                in_scope_targets=["app.example.test"],
                evidence_dir=str(tmp_path / "evidence"),
            ).save(engagement)
            runtime = OffSecAgentRuntime(AgentRuntimeConfig(
                engagement_path=str(engagement),
                db_path=str(tmp_path / "agent.db"),
                session_name="policy",
                confirm_tools=("workspace_write",),
                blocked_tools=("export_pack",),
            ))
            try:
                pending = runtime.registry.run("workspace_write", {"path": "notes/policy.md", "content": "policy-ok"})
                self.assertEqual(pending.status, "needs_approval", pending.to_dict())
                self.assertFalse((runtime.registry.workspace_root / "notes" / "policy.md").exists())
                approved = runtime.registry.run("approve", {"id": pending.data["approval_id"]})
                self.assertEqual(approved.status, "ok", approved.to_dict())
                self.assertTrue((runtime.registry.workspace_root / "notes" / "policy.md").exists())
                blocked = runtime.registry.run("export_pack", {})
                self.assertEqual(blocked.status, "blocked", blocked.to_dict())
                status = runtime.registry.run("runtime_status", {})
                self.assertIn("export_pack", status.data["policy"]["blocked_tools"])
            finally:
                runtime.close()

    def test_local_skills_progressive_loading_and_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime, engagement = self.make_runtime(tmp)
            runtime.close()
            skills_dir = tmp_path / "skills"
            skill_dir = skills_dir / "demo-skill"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: demo-skill\n"
                "description: Demo local skill for progressive disclosure.\n"
                "triggers:\n"
                "  - demo trigger\n"
                "---\n"
                "# Demo Skill\n\n"
                "Step 1: keep scope and evidence first.\n",
                encoding="utf-8",
            )
            discovered = discover_skills([str(skills_dir)])
            self.assertIn("demo-skill", discovered)
            self.assertNotIn("Step 1", discovered["demo-skill"].to_dict().get("description", ""))
            loaded_direct = load_skill("demo-skill", [str(skills_dir)])
            self.assertIn("Step 1", loaded_direct.content)

            cfg_path = tmp_path / "agent.config.json"
            AgentAppConfig(
                workspace_dir=str(tmp_path / "workspace"),
                skill_dirs=[str(skills_dir)],
                preload_skills=["demo-skill"],
                skill_bundles={"demo": ["demo-skill"]},
            ).save(cfg_path)
            cfg = AgentAppConfig.load(cfg_path)
            self.assertEqual(cfg.skill_dirs, [str(skills_dir)])
            runtime = OffSecAgentRuntime(cfg.to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "skills"))
            try:
                self.assertIn("demo-skill", runtime.loaded_skills)
                skills = runtime.handle_message("/skills")
                self.assertIn("Demo local skill", skills)
                self.assertNotIn("Step 1: keep scope", skills)
                shown = runtime.handle_message("/skill name=demo-skill")
                self.assertIn("Step 1: keep scope", shown)
                runtime.loaded_skills.clear()
                dynamic = runtime.handle_message("/demo-skill")
                self.assertIn("Loaded skill demo-skill", dynamic)
                runtime.loaded_skills.clear()
                bundle = runtime.handle_message("/skill bundle=demo")
                self.assertIn('"demo-skill"', bundle)
                escaped = runtime.handle_message("/skill name=../demo-skill")
                self.assertIn("Skill load failed", escaped)
            finally:
                runtime.close()

    def test_tool_run_and_finding_storage_redaction_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                run_id = runtime.store.create_tool_run(
                    runtime.session_id,
                    "httpx_probe",
                    "https://app.example.test token=storage-secret",
                    "httpx -json https://app.example.test token=storage-secret",
                    "parsed",
                    decision={"status": "allow", "api_key": "storage-secret", "reason": "token=storage-secret"},
                    parsed={"responses": [{"url": "https://app.example.test", "title": "token=storage-secret", "headers": {"token": "storage-secret"}}]},
                    metadata={"token": "storage-secret", "note": "secret=storage-secret"},
                )
                finding_id = runtime.store.create_finding(
                    runtime.session_id,
                    "Stored finding token=storage-secret",
                    severity="Medium",
                    status="needs-evidence",
                    description="Description includes password=storage-secret for redaction testing.",
                    impact="Impact includes secret=storage-secret for redaction testing.",
                    recommendation="Recommendation includes api_key=storage-secret for redaction testing.",
                    evidence=[{"type": "tool_run", "id": run_id, "note": "token=storage-secret", "api_key": "storage-secret"}],
                    tags="token=storage-secret",
                )
                updated = runtime.store.update_finding(
                    finding_id,
                    session_id=runtime.session_id,
                    evidence=[{"type": "manual", "note": "password=storage-secret", "token": "storage-secret"}],
                    description="Updated description secret=storage-secret",
                )
                self.assertIsNotNone(updated)

                raw_tool = runtime.store.conn.execute(
                    "SELECT target, command, decision_json, parsed_json, metadata_json FROM tool_runs WHERE id=?",
                    (run_id,),
                ).fetchone()
                raw_finding = runtime.store.conn.execute(
                    "SELECT title, description, impact, recommendation, evidence_json, tags FROM findings WHERE id=?",
                    (finding_id,),
                ).fetchone()
                serialized_raw = json.dumps({"tool": dict(raw_tool), "finding": dict(raw_finding)}, sort_keys=True)
                self.assertNotIn("storage-secret", serialized_raw)
                self.assertIn("<REDACTED>", serialized_raw)

                tool_detail = runtime.registry.run("get_tool_run", {"id": run_id})
                finding_detail = runtime.registry.run("get_finding", {"id": finding_id})
                serialized_detail = json.dumps({"tool": tool_detail.to_dict(), "finding": finding_detail.to_dict()}, sort_keys=True)
                self.assertEqual(tool_detail.status, "ok", tool_detail.to_dict())
                self.assertEqual(finding_detail.status, "ok", finding_detail.to_dict())
                self.assertNotIn("storage-secret", serialized_detail)
                self.assertIn("<REDACTED>", serialized_detail)
            finally:
                runtime.close()

    def test_structured_wrappers_findings_and_remote_gateway_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            gateway = None
            old_token = os.environ.get("PHOBOS_GATEWAY_TEST_TOKEN")
            os.environ["PHOBOS_GATEWAY_TEST_TOKEN"] = "unit-token"
            try:
                nmap_output = """Starting Nmap
Nmap scan report for 10.10.0.5
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.24
443/tcp open  https   nginx 1.24
"""
                nmap = runtime.registry.run("nmap_scan", {"target": "10.10.0.5", "ports": "80,443", "stdout": nmap_output})
                self.assertEqual(nmap.status, "parsed", nmap.to_dict())
                self.assertEqual(nmap.data["parsed"]["summary"]["open_ports"], 2)
                self.assertTrue(Path(nmap.data["artifact_path"]).exists())
                nmap_run_id = nmap.data["run_id"]

                httpx = runtime.registry.run("httpx_probe", {"url": "https://app.example.test", "stdout": json.dumps({"url": "https://app.example.test", "status_code": 200, "title": "ACME Portal", "tech": ["nginx"]})})
                self.assertEqual(httpx.status, "parsed", httpx.to_dict())
                self.assertEqual(httpx.data["parsed"]["responses"][0]["status_code"], 200)

                nuclei_line = json.dumps({"template-id": "exposed-panel", "info": {"name": "Exposed Panel", "severity": "medium"}, "matched-at": "https://app.example.test/admin"})
                nuclei = runtime.registry.run("nuclei_scan", {"url": "https://app.example.test", "stdout": nuclei_line})
                self.assertEqual(nuclei.status, "parsed", nuclei.to_dict())
                self.assertEqual(nuclei.data["parsed"]["summary"]["count"], 1)

                ffuf_output = json.dumps({"results": [{"url": "https://app.example.test/admin", "status": 200, "length": 1234, "words": 12, "lines": 5}]})
                ffuf = runtime.registry.run("ffuf_scan", {"url": "https://app.example.test/FUZZ", "wordlist": "words.txt", "stdout": ffuf_output})
                self.assertEqual(ffuf.status, "parsed", ffuf.to_dict())
                self.assertEqual(ffuf.data["parsed"]["summary"]["count"], 1)

                runs = runtime.registry.run("list_tool_runs", {})
                self.assertGreaterEqual(len(runs.data["runs"]), 4)
                self.assertIn("nmap_scan", runtime.handle_message('/schemas name=nmap_scan'))
                self.assertIn("Structured tool run", runtime.handle_message(f'/tool-run id={nmap_run_id}'))

                created = runtime.registry.run("create_finding", {
                    "title": "Exposed administrative interface",
                    "severity": "Medium",
                    "status": "needs-evidence",
                    "description": "An administrative interface was exposed during safe enumeration.",
                    "impact": "Attackers could target administrative authentication workflows.",
                    "recommendation": "Restrict access to trusted management networks and require MFA.",
                    "tool_run_ids": str(nmap_run_id),
                    "tags": "web,exposure",
                })
                self.assertEqual(created.status, "ok", created.to_dict())
                finding_id = created.data["finding"]["id"]

                other_runtime = OffSecAgentRuntime(AgentRuntimeConfig(engagement_path=runtime.config.engagement_path, db_path=runtime.config.db_path, session_name="other-detail-session"))
                try:
                    other_nmap = other_runtime.registry.run("nmap_scan", {"target": "10.10.0.6", "stdout": "80/tcp open http nginx"})
                    self.assertEqual(other_nmap.status, "parsed", other_nmap.to_dict())
                    other_run_id = other_nmap.data["run_id"]
                    other_finding = other_runtime.registry.run("create_finding", {"title": "Other session detail sentinel", "tool_run_ids": str(other_run_id)})
                    self.assertEqual(other_finding.status, "ok", other_finding.to_dict())
                    other_finding_id = other_finding.data["finding"]["id"]
                    self.assertIn("not found in this session", runtime.handle_message(f"/tool-run id={other_run_id}"))
                    self.assertIn("not found in this session", runtime.handle_message(f"/finding-get id={other_finding_id}"))
                    self.assertIn("not found in this session", runtime.registry.run("update_finding", {"id": other_finding_id, "status": "confirmed"}).message)
                    self.assertIn("not found in this session", runtime.registry.run("finding_export", {"id": other_finding_id}).message)
                    self.assertIn("not found in this session", runtime.registry.run("finding_review", {"id": other_finding_id}).message)
                    self.assertIn("not found in this session", runtime.registry.run("finding_bundle", {"id": other_finding_id}).message)
                    cross_link = runtime.registry.run("create_finding", {"title": "Cross-session link probe", "tool_run_ids": str(other_run_id)})
                    self.assertEqual(cross_link.status, "ok", cross_link.to_dict())
                    self.assertEqual(cross_link.data["finding"].get("evidence"), [])
                    self.assertIn("not found in this session", other_runtime.handle_message(f"/tool-run id={nmap_run_id}"))
                    self.assertIn("not found in this session", other_runtime.handle_message(f"/finding-get id={finding_id}"))
                finally:
                    other_runtime.close()

                outside_bundle_secret = Path(tmp) / "outside-finding-bundle-sentinel.txt"
                outside_bundle_secret.write_text("OUTSIDE_FINDING_BUNDLE_SENTINEL", encoding="utf-8")
                bundle_escape_link = runtime.registry.harness.store.root / "reports" / "bundle-outside-link.txt"
                bundle_escape_link.parent.mkdir(parents=True, exist_ok=True)
                if hasattr(os, "symlink"):
                    try:
                        bundle_escape_link.symlink_to(outside_bundle_secret)
                    except OSError:
                        bundle_escape_link.write_text("local fallback evidence", encoding="utf-8")
                else:
                    bundle_escape_link.write_text("local fallback evidence", encoding="utf-8")

                updated = runtime.registry.run("update_finding", {
                    "id": finding_id,
                    "status": "confirmed",
                    "evidence": [
                        {"type": "note", "value": "Gateway screenshot captured token=supersecret"},
                        {"type": "artifact", "artifact_path": str(bundle_escape_link)},
                    ],
                    "append_evidence": True,
                })
                self.assertEqual(updated.data["finding"]["status"], "confirmed")
                exported = runtime.registry.run("finding_export", {"id": finding_id})
                self.assertEqual(exported.status, "ok", exported.to_dict())
                markdown = Path(exported.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Exposed administrative interface", markdown)
                self.assertIn("Tool run", markdown)
                reviewed = runtime.registry.run("finding_review", {"id": finding_id})
                self.assertEqual(reviewed.status, "ok", reviewed.to_dict())
                self.assertEqual(reviewed.data["review"]["readiness"], "ready_with_advisories")
                self.assertFalse(reviewed.data["review"]["blocking_gaps"])
                review_markdown = Path(reviewed.artifacts["markdown"]).read_text(encoding="utf-8")
                self.assertIn("Phobos Finding Review", review_markdown)
                self.assertIn("Negative control", review_markdown)
                self.assertNotIn("supersecret", review_markdown)
                bundled = runtime.registry.run("finding_bundle", {"id": finding_id, "out": "unit-finding-bundle.zip"})
                self.assertEqual(bundled.status, "ok", bundled.to_dict())
                self.assertTrue(bundled.data["no_target_activity"])
                self.assertFalse(bundled.data["raw_file_contents_emitted"])
                bundle_path = Path(bundled.artifacts["zip"])
                self.assertTrue(bundle_path.exists())
                with zipfile.ZipFile(bundle_path) as archive:
                    names = set(archive.namelist())
                    self.assertTrue({"BUNDLE_README.md", "MANIFEST.json", "finding/finding.md", "finding/review.md", "finding/finding.json"}.issubset(names))
                    self.assertTrue(any(name.startswith("evidence/agent/tool-runs/") for name in names), names)
                    manifest = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
                    self.assertTrue(any("outside evidence root" in str(item.get("reason", "")) for item in manifest.get("skipped", [])), manifest)
                    zipped_blob = b"\n".join(archive.read(name) for name in names if not name.endswith("/"))
                self.assertNotIn(b"supersecret", zipped_blob)
                self.assertNotIn(b"OUTSIDE_FINDING_BUNDLE_SENTINEL", zipped_blob)
                self.assertIn("finding_bundle", runtime.handle_message('/schemas name=finding_bundle'))
                self.assertIn("Finding #", runtime.handle_message(f'/finding-bundle id={finding_id} out=slash-finding-bundle.zip'))
                weak = runtime.registry.run("create_finding", {"title": "Version-only candidate", "severity": "High"})
                weak_review = runtime.registry.run("finding_review", {"id": weak.data["finding"]["id"]})
                self.assertEqual(weak_review.status, "ok", weak_review.to_dict())
                self.assertEqual(weak_review.data["review"]["readiness"], "needs_evidence")
                self.assertTrue(weak_review.data["review"]["blocking_gaps"])
                self.assertIn("finding_review", runtime.handle_message('/schemas name=finding_review'))
                self.assertIn("Finding #", runtime.handle_message(f'/finding-review id={finding_id}'))
                listed = runtime.handle_message('/findings status=all')
                self.assertIn("Exposed administrative interface", listed)
                status = runtime.registry.run("runtime_status", {}).data
                self.assertGreaterEqual(status["schema"]["schema_version"], 5)
                self.assertGreaterEqual(status["tool_runs"], 4)
                self.assertGreaterEqual(status["findings"], 1)

                with self.assertRaises(ValueError):
                    AgentGateway(runtime, host="0.0.0.0", port=0)
                gateway = AgentGateway(runtime, port=0, token_env="PHOBOS_GATEWAY_TEST_TOKEN", allow_origins=("*",))
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
                    health = json.loads(response.read().decode("utf-8"))
                self.assertTrue(health["auth_required"])
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5)
                self.assertEqual(raised.exception.code, 401)
                authed = urllib.request.Request(f"http://{host}:{port}/status", headers={"Authorization": "Bearer unit-token", "Origin": "https://ui.example"})
                with urllib.request.urlopen(authed, timeout=5) as response:
                    remote_status = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "*")
                self.assertEqual(remote_status["status"], "ok")
                audit_id = runtime.store.audit(runtime.session_id, "gateway_audit_detail", {"token": "gateway-audit-secret"})
                audit_detail_req = urllib.request.Request(
                    f"http://{host}:{port}/audit-detail?id={audit_id}",
                    headers={"Authorization": "Bearer unit-token"},
                )
                with urllib.request.urlopen(audit_detail_req, timeout=5) as response:
                    audit_detail = json.loads(response.read().decode("utf-8"))
                self.assertEqual(audit_detail["status"], "ok")
                self.assertEqual(audit_detail["data"]["audit"]["id"], audit_id)
                self.assertNotIn("gateway-audit-secret", json.dumps(audit_detail))

                for bad_route, expected_error in [
                    ("/timeline?limit=not-an-int", "limit must be an integer"),
                    ("/manifest?max_bytes=not-an-int", "max_bytes must be an integer"),
                    (f"/finding-bundle?id={finding_id}&max_bytes=not-an-int", "max_bytes must be an integer"),
                ]:
                    bad_query_req = urllib.request.Request(
                        f"http://{host}:{port}{bad_route}",
                        headers={"Authorization": "Bearer unit-token"},
                    )
                    with self.assertRaises(urllib.error.HTTPError) as bad_query:
                        urllib.request.urlopen(bad_query_req, timeout=5)
                    self.assertEqual(bad_query.exception.code, 400)
                    bad_payload = json.loads(bad_query.exception.read().decode("utf-8"))
                    self.assertEqual(bad_payload.get("error"), expected_error)
                    self.assertNotIn("Traceback", json.dumps(bad_payload))

                with urllib.request.urlopen(f"http://{host}:{port}/ui-client", timeout=5) as response:
                    ui_html = response.read().decode("utf-8")
                self.assertIn("Phobos Agent Remote Client", ui_html)
                finding_req = urllib.request.Request(
                    f"http://{host}:{port}/finding",
                    data=json.dumps({"title": "Remote-created finding", "severity": "Low"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": "Bearer unit-token"},
                    method="POST",
                )
                with urllib.request.urlopen(finding_req, timeout=5) as response:
                    remote_finding = json.loads(response.read().decode("utf-8"))
                self.assertEqual(remote_finding["result"]["status"], "ok")
                finding_detail_req = urllib.request.Request(
                    f"http://{host}:{port}/finding?id={finding_id}",
                    headers={"Authorization": "Bearer unit-token"},
                )
                with urllib.request.urlopen(finding_detail_req, timeout=5) as response:
                    finding_detail = json.loads(response.read().decode("utf-8"))
                self.assertEqual(finding_detail["status"], "ok")
                self.assertEqual(finding_detail["data"]["finding"]["id"], finding_id)
                finding_bundle_req = urllib.request.Request(
                    f"http://{host}:{port}/finding-bundle?id={finding_id}&out=gateway-finding-bundle.zip",
                    headers={"Authorization": "Bearer unit-token"},
                )
                with urllib.request.urlopen(finding_bundle_req, timeout=5) as response:
                    finding_bundle = json.loads(response.read().decode("utf-8"))
                self.assertEqual(finding_bundle["status"], "ok")
                self.assertTrue(Path(finding_bundle["artifacts"]["zip"]).exists())
                tool_run_detail_req = urllib.request.Request(
                    f"http://{host}:{port}/tool-run?id={nmap_run_id}",
                    headers={"Authorization": "Bearer unit-token"},
                )
                with urllib.request.urlopen(tool_run_detail_req, timeout=5) as response:
                    tool_run_detail = json.loads(response.read().decode("utf-8"))
                self.assertEqual(tool_run_detail["status"], "ok")
                self.assertEqual(tool_run_detail["data"]["run"]["id"], nmap_run_id)
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()
                if old_token is None:
                    os.environ.pop("PHOBOS_GATEWAY_TEST_TOKEN", None)
                else:
                    os.environ["PHOBOS_GATEWAY_TEST_TOKEN"] = old_token

    def test_bridge_allowlists_prefix_mentions_and_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime, _ = self.make_runtime(tmp)
            try:
                config = BridgeConfig(
                    platform="discord",
                    allowed_channel_ids=("C1",),
                    allowed_user_ids=("U1",),
                    command_prefix="!phobos",
                    max_response_chars=240,
                )
                wrong_channel = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C2", user_id="U1"),
                    config,
                )
                self.assertEqual(wrong_channel.status, "ignored")
                self.assertEqual(wrong_channel.reason, "channel-not-allowed")

                missing_prefix = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/status", channel_id="C1", user_id="U1"),
                    config,
                )
                self.assertEqual(missing_prefix.status, "ignored")
                self.assertEqual(missing_prefix.reason, "prefix-required")

                handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", message_id="M1"),
                    config,
                )
                self.assertEqual(handled.status, "handled", handled.to_dict())
                self.assertEqual(handled.normalized_text, "/status")
                self.assertIn("Phobos is up", handled.response)
                self.assertIn("Safety: `non_destructive`", handled.response)
                self.assertNotIn('"session_id"', handled.response)
                self.assertIn('"safety_mode": "non_destructive"', handled.raw_response)
                self.assertTrue(handled.chunks)
                self.assertTrue(all(len(chunk) <= 240 for chunk in handled.chunks))

                raw_config = BridgeConfig.from_dict("discord", {"allowed_channel_ids": ["C1"], "allowed_user_ids": ["U1"], "command_prefix": "!phobos", "response_polish": False})
                raw_handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", message_id="M1-raw"),
                    raw_config,
                )
                self.assertIn('"safety_mode": "non_destructive"', raw_handled.response)
                self.assertEqual(raw_handled.response, raw_handled.raw_response)

                voice_note = Path(tmp) / "bridge-voice.ogg"
                voice_note.write_bytes(b"OggS voice-note token=supersecret")
                attachment_handled = handle_bridge_message(
                    runtime,
                    BridgeMessage(
                        platform="discord",
                        text="!phobos /media-list",
                        channel_id="C1",
                        user_id="U1",
                        message_id="M-media",
                        attachments=[{"local_path": str(voice_note), "mime_type": "audio/ogg", "kind": "audio", "name": "voice.ogg"}],
                    ),
                    config,
                )
                self.assertEqual(attachment_handled.status, "handled", attachment_handled.to_dict())
                self.assertEqual(attachment_handled.attachments[0]["status"], "ok")
                self.assertEqual(attachment_handled.attachments[0]["kind"], "audio")
                self.assertIn("audio", runtime.handle_message("/media-list"))

                media_count_before_oversize = len(runtime.store.list_media_artifacts(runtime.session_id, limit=100))
                oversized_note = Path(tmp) / "bridge-oversized.bin"
                oversized_note.write_bytes(b"x" * 64)
                oversized_blocked = handle_bridge_message(
                    runtime,
                    BridgeMessage(
                        platform="discord",
                        text="!phobos /status",
                        channel_id="C1",
                        user_id="U1",
                        message_id="M-too-large",
                        attachments=[{"local_path": str(oversized_note), "mime_type": "application/octet-stream", "name": "token=supersecret-too-large.bin"}],
                    ),
                    BridgeConfig(platform="discord", allowed_channel_ids=("C1",), allowed_user_ids=("U1",), command_prefix="!phobos", max_attachment_bytes=8),
                )
                self.assertEqual(oversized_blocked.status, "blocked", oversized_blocked.to_dict())
                self.assertEqual(oversized_blocked.reason, "attachment-too-large")
                self.assertEqual(oversized_blocked.normalized_text, "/status")
                self.assertIn("no text command was executed", oversized_blocked.response)
                self.assertEqual(oversized_blocked.attachments[0]["status"], "skipped")
                self.assertEqual(oversized_blocked.attachments[0]["reason"], "attachment-too-large")
                self.assertEqual(oversized_blocked.attachments[0]["size"], 64)
                self.assertNotIn("supersecret", json.dumps(oversized_blocked.to_dict()))
                self.assertEqual(len(runtime.store.list_media_artifacts(runtime.session_id, limit=100)), media_count_before_oversize)

                attachment_only = handle_bridge_message(
                    runtime,
                    BridgeMessage(
                        platform="telegram",
                        text="",
                        channel_id="PRIVATE1",
                        user_id="U3",
                        is_private=True,
                        attachments=[{"url": "https://example.invalid/evidence.png", "mime_type": "image/png", "size": 123, "name": "token=supersecret-remote.png"}],
                    ),
                    BridgeConfig(platform="telegram"),
                )
                self.assertEqual(attachment_only.status, "handled")
                self.assertEqual(attachment_only.reason, "attachments")
                self.assertEqual(attachment_only.attachments[0]["status"], "metadata-recorded")
                self.assertNotIn("supersecret", json.dumps(attachment_only.to_dict()))

                ignored_bot = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C1", user_id="U1", is_bot=True),
                    config,
                )
                self.assertEqual(ignored_bot.reason, "bot-message")

                user_only_public = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /status", channel_id="C-anywhere", user_id="U1"),
                    BridgeConfig(platform="discord", allowed_user_ids=("U1",), command_prefix="!phobos"),
                )
                self.assertEqual(user_only_public.status, "ignored")
                self.assertEqual(user_only_public.reason, "channel-allowlist-required")

                approval_blocked = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /approve id=1", channel_id="C1", user_id="U1"),
                    config,
                )
                self.assertEqual(approval_blocked.status, "blocked")
                self.assertEqual(approval_blocked.reason, "approval-action-disabled")

                approval_allowed = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="!phobos /approve id=999999", channel_id="C1", user_id="U1"),
                    BridgeConfig(platform="discord", allowed_channel_ids=("C1",), allowed_user_ids=("U1",), command_prefix="!phobos", allow_approval_actions=True),
                )
                self.assertEqual(approval_allowed.status, "handled")
                self.assertIn("not found", approval_allowed.response)

                mention_config = BridgeConfig(platform="discord", allowed_channel_ids=("C1",), mention_required=True)
                no_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(no_mention.reason, "mention-required")
                mentioned = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="<@BOT1> /tools", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(mentioned.status, "handled")
                self.assertIn("Phobos tools are registered", mentioned.response)
                self.assertIn("/schemas name=<tool>", mentioned.response)

                inline_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="hey <@BOT1> /status", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(inline_mention.status, "handled")
                self.assertEqual(inline_mention.reason, "mentioned")
                self.assertEqual(inline_mention.normalized_text, "/status")
                self.assertIn("Phobos is up", inline_mention.response)
                self.assertIn('"safety_mode": "non_destructive"', inline_mention.raw_response)

                literal_alias = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="@phobos /status", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(literal_alias.status, "handled")
                self.assertEqual(literal_alias.reason, "mentioned")
                self.assertEqual(literal_alias.normalized_text, "/status")
                self.assertIn("Phobos is up", literal_alias.response)
                self.assertIn('"safety_mode": "non_destructive"', literal_alias.raw_response)

                trailing_alias = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools @Phobos", channel_id="C1", user_id="U1"),
                    config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(trailing_alias.status, "handled")
                self.assertEqual(trailing_alias.normalized_text, "/tools")
                self.assertIn("Phobos tools are registered", trailing_alias.response)

                trailing_mention = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="discord", text="/tools <@BOT1>", channel_id="C1", user_id="U2"),
                    mention_config,
                    bot_user_id="BOT1",
                )
                self.assertEqual(trailing_mention.status, "handled")
                self.assertEqual(trailing_mention.normalized_text, "/tools")
                self.assertIn("Phobos tools are registered", trailing_mention.response)

                thread_config = BridgeConfig.from_dict(
                    "discord",
                    {"allowed_channel_ids": ["C1"], "command_prefix": "!phobos", "discord_thread_mode": "per-message"},
                )
                parent_message = BridgeMessage(platform="discord", text="@phobos /status", channel_id="C1", user_id="U1", message_id="M1", raw={"channel_type": 0})
                parent_result = handle_bridge_message(runtime, parent_message, thread_config, bot_user_id="BOT1")
                self.assertEqual(parent_result.status, "handled")
                bridge = DiscordGatewayBridge.__new__(DiscordGatewayBridge)
                bridge.runtime = runtime
                bridge.config = thread_config
                created_threads = []

                def fake_create_thread(channel_id, message_id, name):
                    created_threads.append((channel_id, message_id, name))
                    return "T1"

                bridge.create_thread_from_message = fake_create_thread
                self.assertEqual(bridge.response_channel_id(parent_message, parent_result), "T1")
                self.assertEqual(created_threads[0][0], "C1")
                self.assertEqual(created_threads[0][1], "M1")
                self.assertTrue(created_threads[0][2].startswith("Phobos - status"))

                thread_message = BridgeMessage(
                    platform="discord",
                    text="/status",
                    channel_id="T1",
                    user_id="U1",
                    message_id="M2",
                    raw={"channel_type": 11, "parent_id": "C1"},
                )
                thread_result = handle_bridge_message(runtime, thread_message, thread_config, bot_user_id="BOT1")
                self.assertEqual(thread_result.status, "handled")
                self.assertEqual(thread_result.normalized_text, "/status")
                self.assertEqual(bridge.response_channel_id(thread_message, BridgeDispatchResult("handled", normalized_text="/status")), "T1")

                private_message = handle_bridge_message(
                    runtime,
                    BridgeMessage(platform="telegram", text="/status", channel_id="PRIVATE1", user_id="U3", is_private=True),
                    BridgeConfig(platform="telegram"),
                )
                self.assertEqual(private_message.status, "handled")

                chunks = chunk_text("word " * 120, 200)
                self.assertGreater(len(chunks), 1)
                self.assertTrue(all(len(chunk) <= 200 for chunk in chunks))
                neutralized = "\n".join(chunk_text("@everyone @here <!channel> " + ("word " * 120), 200))
                self.assertNotIn("@everyone", neutralized)
                self.assertNotIn("@here", neutralized)
                self.assertNotIn("<!channel>", neutralized)
                self.assertIn("@\u200beveryone", neutralized)
            finally:
                runtime.close()

    def test_plugin_config_and_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime, engagement = self.make_runtime(tmp)
            runtime.close()
            plugin_dir = tmp_path / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "echo_plugin.py").write_text(
                "from offsec_agent_harness.agent_tools import ToolResult\n"
                "def register(registry):\n"
                "    def echo(args):\n"
                "        return ToolResult('ok', 'plugin echo', {'echo': args.get('value', '')})\n"
                "    registry.register_tool('plugin_echo', echo, {'description': 'Echo from a local plugin.', 'schema': {'type': 'object', 'properties': {'value': {'type': 'string'}}}})\n",
                encoding="utf-8",
            )
            cfg_path = tmp_path / "agent.config.json"
            AgentAppConfig(workspace_dir=str(tmp_path / "workspace"), plugin_dirs=[str(plugin_dir)]).save(cfg_path)
            cfg = AgentAppConfig.load(cfg_path).to_runtime_config(str(engagement), str(tmp_path / "agent.db"), "unit", config_path=str(cfg_path))
            runtime = OffSecAgentRuntime(cfg)
            gateway = None
            try:
                self.assertIn("plugin_echo", runtime.handle_message('/tools'))
                plugin_result = runtime.handle_message('/tool name=plugin_echo value=hello')
                self.assertIn('"echo": "hello"', plugin_result)
                schema = runtime.handle_message('/schemas name=plugin_echo')
                self.assertIn("Echo from a local plugin", schema)

                gateway = AgentGateway(runtime, port=0)
                thread = threading.Thread(target=gateway.serve_forever, daemon=True)
                thread.start()
                host, port = gateway.server_address
                with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5) as response:
                    health = json.loads(response.read().decode("utf-8"))
                self.assertTrue(health["ok"])
                with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
                    dashboard = response.read().decode("utf-8")
                self.assertIn("Phobos Agent Gateway", dashboard)
                self.assertIn("Granular Guardrails", dashboard)
                with urllib.request.urlopen(f"http://{host}:{port}/guardrails", timeout=5) as response:
                    guardrails = json.loads(response.read().decode("utf-8"))
                self.assertEqual(guardrails["engagement"]["safety_mode"], "non_destructive")
                self.assertTrue(any(tool["name"] == "nmap_scan" for tool in guardrails["tools"]))
                policy_req = urllib.request.Request(
                    f"http://{host}:{port}/guardrails",
                    data=json.dumps({
                        "safety_mode": "standard",
                        "testing_window": "business hours with client lead online",
                        "notes": "UI test note: tighten only, no secrets.",
                        "in_scope_targets": ["app.example.test", "10.10.0.0/24"],
                        "allowed_techniques": ["web", "service-enumeration", "offline-analysis"],
                        "prohibited_techniques": ["dos", "destructive", "persistence", "evasion", "malware", "credential-dumping"],
                        "stop_conditions": ["Stop before customer data access.", "Stop before production changes."],
                        "confirm_tools": ["nmap_scan"],
                        "blocked_tools": ["export_pack"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(policy_req, timeout=5) as response:
                    updated_policy = json.loads(response.read().decode("utf-8"))
                self.assertEqual(updated_policy["status"], "updated")
                self.assertIn("engagement.safety_mode", updated_policy["changed"])
                self.assertTrue(updated_policy["persisted"]["engagement"])
                self.assertTrue(updated_policy["persisted"]["runtime_policy"])
                persisted_roe = EngagementROE.load(engagement)
                self.assertEqual(persisted_roe.safety_mode, "standard")
                self.assertEqual(persisted_roe.testing_window, "business hours with client lead online")
                self.assertIn("tighten only", persisted_roe.notes)
                bad_req = urllib.request.Request(
                    f"http://{host}:{port}/guardrails",
                    data=json.dumps({"unknown_field": True}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_exc:
                    urllib.request.urlopen(bad_req, timeout=5)
                self.assertEqual(bad_exc.exception.code, 400)
                self.assertIn("unknown guardrail policy fields", bad_exc.exception.read().decode("utf-8"))
                persisted_cfg = AgentAppConfig.load(cfg_path)
                self.assertIn("nmap_scan", persisted_cfg.confirm_tools)
                self.assertIn("export_pack", persisted_cfg.blocked_tools)
                active_scan_confirm = runtime.handle_message('/assess target=app.example.test type=service-enumeration purpose="tight client" command="nmap -sV app.example.test"')
                self.assertIn("Guardrail decision: confirm", active_scan_confirm)
                policy_confirm = runtime.registry.run("nmap_scan", {"target": "app.example.test", "stdout": "80/tcp open http nginx"})
                self.assertEqual(policy_confirm.status, "needs_approval", policy_confirm.to_dict())
                policy_block = runtime.registry.run("export_pack", {})
                self.assertEqual(policy_block.status, "blocked", policy_block.to_dict())
                with urllib.request.urlopen(f"http://{host}:{port}/status", timeout=5) as response:
                    gateway_status = json.loads(response.read().decode("utf-8"))
                self.assertEqual(gateway_status["status"], "ok")

                gateway_job = runtime.registry.run("schedule_job", {"name": "gateway-job", "prompt": "/status", "schedule": "manual"})
                gateway_job_id = gateway_job.data["job_id"]
                media_src = tmp_path / "gateway-proof.txt"
                media_src.write_text("gateway media marker", encoding="utf-8")
                gateway_media = runtime.registry.run("media_import", {"path": str(media_src)})
                gateway_delegation = runtime.registry.run("delegate_tasks", {"prompt": "gateway delegation marker", "roles": "scope"})
                process = runtime.registry.run("start_process", {"target": "app.example.test", "type": "host", "purpose": "gateway route process", "command": "printf gateway-process", "execute": True})
                runtime.registry.run("wait_process", {"id": process.data["process_id"], "timeout": 5})
                gateway_manifest = runtime.registry.run("evidence_manifest", {"out": "gateway-manifest.json"})
                self.assertEqual(gateway_manifest.status, "ok", gateway_manifest.to_dict())
                gateway_media_id = gateway_media.data["media"]["id"]
                gateway_delegation_id = gateway_delegation.data["delegation"]["id"]

                for route, marker in [
                    ("/routes", "/schemas"),
                    ("/schemas?name=start_process", "start_process"),
                    ("/jobs", "gateway-job"),
                    (f"/job-detail?id={gateway_job_id}", "gateway-job"),
                    ("/processes", "gateway route process"),
                    ("/timeline?include_audit=false", "gateway route process"),
                    ("/manifest-verify?path=gateway-manifest.json&detect_new=false", "verification_status"),
                    ("/delegations", "gateway delegation marker"),
                    (f"/delegation-detail?id={gateway_delegation_id}", "gateway delegation marker"),
                    ("/media", "gateway-proof"),
                    (f"/media-detail?id={gateway_media_id}", "no_file_content_read"),
                    ("/auth", "secret_values_redacted"),
                    ("/bridges", "discord"),
                    ("/guardrails", "standard"),
                    ("/lcm", "nodes"),
                ]:
                    with urllib.request.urlopen(f"http://{host}:{port}{route}", timeout=5) as response:
                        routed = response.read().decode("utf-8")
                    self.assertIn(marker, routed, route)

                approval = runtime.registry.run("run_command", {"target": "app.example.test", "type": "web", "purpose": "gateway deny approval", "command": "curl -X POST https://app.example.test/api", "execute": True})
                self.assertEqual(approval.status, "needs_approval", approval.to_dict())
                deny_req = urllib.request.Request(
                    f"http://{host}:{port}/deny",
                    data=json.dumps({"id": approval.data["approval_id"], "by": "unit", "reason": "gateway-test"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(deny_req, timeout=5) as response:
                    deny_data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(deny_data["result"]["status"], "denied")
                req = urllib.request.Request(
                    f"http://{host}:{port}/message",
                    data=json.dumps({"message": "/schemas name=plugin_echo"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode("utf-8"))
                self.assertIn("plugin_echo", data["response"])
                tool_req = urllib.request.Request(
                    f"http://{host}:{port}/tool",
                    data=json.dumps({"name": "plugin_echo", "args": {"value": "via-gateway"}}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(tool_req, timeout=5) as response:
                    tool_data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(tool_data["result"]["data"]["echo"], "via-gateway")
            finally:
                if gateway is not None:
                    gateway.shutdown()
                runtime.close()



    def test_bridge_doctor_sanitizes_live_auth_checks(self):
        import offsec_agent_harness.agent_bridges as bridges

        def fake_http_json(method, url, *, payload=None, headers=None, timeout=30.0):
            self.assertTrue(headers or url.startswith("https://api.telegram.org"))
            if "discord.com/api/v10/users/@me" in url:
                return {"id": "D-BOT", "username": "phobos"}
            if "discord.com/api/v10/gateway/bot" in url:
                return {"url": "wss://gateway.example", "session_start_limit": {"remaining": 100}}
            if "slack.com/api/auth.test" in url:
                return {"ok": True, "team_id": "T1", "user_id": "U-BOT"}
            if "slack.com/api/apps.connections.open" in url:
                return {"ok": True, "url": "wss://socket-mode-secret.example"}
            if "api.telegram.org" in url:
                return {"ok": True, "result": {"id": 42, "username": "phobos_bot"}}
            raise AssertionError(url)

        env = {
            "PHOBOS_DISCORD_TOKEN": "discord-secret",
            "PHOBOS_SLACK_BOT_TOKEN": "slack-bot-secret",
            "PHOBOS_SLACK_APP_TOKEN": "slack-app-secret",
            "PHOBOS_TELEGRAM_TOKEN": "telegram-secret",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(bridges, "_http_json", fake_http_json):
            result = bridge_doctor(["discord", "slack", "telegram"])
        self.assertTrue(result["ok"])
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("socket-mode-secret", serialized)
        self.assertTrue(all(item["message_sending"] is False for item in result["checks"]))

class AgentCliTests(unittest.TestCase):
    def test_phobos_agent_cli_once_and_tools(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engagement = tmp_path / "engagement.json"
            init_engagement = subprocess.run([
                sys.executable, "-m", "phobos_agent.cli", "init",
                "--name", "Agent CLI", "--scope", "app.example.test", "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init_engagement.returncode, 0, init_engagement.stderr)
            init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "init", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init.returncode, 0, init.stderr)
            data = json.loads(init.stdout)
            self.assertIn("session_id", data)

            tools = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "tools", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(tools.returncode, 0, tools.stderr)
            self.assertIn("run_command", tools.stdout)

            schema = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "schema", "--engagement", str(engagement), "--name", "runtime_status",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(schema.returncode, 0, schema.stderr)
            self.assertIn("runtime_status", schema.stdout)

            status = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "status", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("schema_version", status.stdout)

            auto_plan = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "auto", "--engagement", str(engagement), "--prompt", "remember cli-native-plan: CLI native plan token=cli-auto-secret",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(auto_plan.returncode, 0, auto_plan.stderr)
            self.assertIn("Auto plan (no tools executed)", auto_plan.stdout)
            auto_plan_payload = json.loads(auto_plan.stdout.split("\n", 1)[1])
            self.assertEqual(auto_plan_payload["mode"], "plan_only")
            self.assertTrue(auto_plan_payload["no_tools_executed"])
            self.assertEqual(auto_plan_payload["execution_ledger"], [])
            self.assertNotIn("cli-auto-secret", auto_plan.stdout)

            auto_apply = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "auto", "--engagement", str(engagement), "--apply", "--prompt", "remember cli-native-apply: CLI native apply token=cli-apply-secret",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(auto_apply.returncode, 0, auto_apply.stderr)
            auto_apply_payload = json.loads(auto_apply.stdout.split("\n", 1)[1])
            self.assertEqual(auto_apply_payload["mode"], "applied")
            self.assertEqual(auto_apply_payload["results"][0]["result"]["status"], "ok")
            self.assertEqual(auto_apply_payload["execution_ledger"][0]["execution_state"], "completed_without_command_execution")
            self.assertNotIn("cli-apply-secret", auto_apply.stdout)

            auto_loop = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "auto-loop", "--engagement", str(engagement), "--steps", "2", "--prompt", "remember cli-native-loop: CLI native loop token=cli-loop-secret",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(auto_loop.returncode, 0, auto_loop.stderr)
            auto_loop_payload = json.loads(auto_loop.stdout.split("\n", 1)[1])
            self.assertEqual(auto_loop_payload["stop_reason"], "deterministic_plan_applied")
            self.assertEqual(auto_loop_payload["steps_executed"], 1)
            self.assertFalse(any(item.get("actual_command_or_process_activity") for item in auto_loop_payload.get("execution_ledger", [])))
            self.assertNotIn("cli-loop-secret", auto_loop.stdout)

            evidence_manifest = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "evidence-manifest", "--engagement", str(engagement), "--out", "cli-manifest.json",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(evidence_manifest.returncode, 0, evidence_manifest.stderr)
            manifest_json = json.loads(evidence_manifest.stdout)
            self.assertEqual(manifest_json["status"], "ok")
            self.assertTrue(Path(manifest_json["artifacts"]["json"]).exists())
            self.assertTrue(Path(manifest_json["artifacts"]["markdown"]).exists())

            manifest_verify = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "manifest-verify", "--engagement", str(engagement), "--path", "cli-manifest.json", "--out", "cli-manifest-verify.json", "--no-detect-new",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(manifest_verify.returncode, 0, manifest_verify.stderr)
            manifest_verify_json = json.loads(manifest_verify.stdout)
            self.assertEqual(manifest_verify_json["status"], "ok")
            self.assertEqual(manifest_verify_json["data"]["verification_status"], "verified")
            self.assertTrue(manifest_verify_json["data"]["no_target_activity"])
            self.assertTrue(Path(manifest_verify_json["artifacts"]["markdown"]).exists())

            closeout = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "closeout", "--engagement", str(engagement), "--out", "cli-closeout.md",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(closeout.returncode, 0, closeout.stderr)
            closeout_json = json.loads(closeout.stdout)
            self.assertEqual(closeout_json["status"], "ok")
            self.assertTrue(closeout_json["data"]["no_target_activity"])
            self.assertTrue(Path(closeout_json["artifacts"]["markdown"]).exists())
            self.assertIn(closeout_json["data"]["readiness"], {"ready", "review", "blocked"})

            ui_client = tmp_path / "phobos-remote-ui.html"
            ui = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "ui-client", "--out", str(ui_client), "--agent-url", "https://agent.example.test",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(ui.returncode, 0, ui.stderr)
            self.assertTrue(ui_client.exists())
            self.assertIn("Phobos Agent Remote Client", ui_client.read_text(encoding="utf-8"))
            self.assertIn("https://agent.example.test", ui_client.read_text(encoding="utf-8"))

            deploy_dir = tmp_path / "deploy-kit"
            deploy = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "deploy-kit", "--out", str(deploy_dir), "--domain", "phobos.example.test", "--allow-origin", "https://ui.example.test",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(deploy.returncode, 0, deploy.stderr)
            deploy_json = json.loads(deploy.stdout)
            self.assertFalse(deploy_json["token_value_written"])
            self.assertTrue((deploy_dir / "phobos-agent.service").exists())
            self.assertTrue((deploy_dir / "nginx-phobos-agent.conf").exists())
            deploy_text = "\n".join(path.read_text(encoding="utf-8") for path in deploy_dir.iterdir() if path.is_file())
            self.assertIn("--token-env PHOBOS_GATEWAY_TOKEN", deploy_text)
            self.assertIn("127.0.0.1", deploy_text)
            self.assertIn("phobos.example.test", deploy_text)
            self.assertNotIn("use-a-long-random-secret", deploy_text)

            auth_env = dict(env)
            auth_env["PHOBOS_DISCORD_TOKEN"] = "discord-secret-value"
            auth = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "auth-status", "--engagement", str(engagement),
            ], cwd=project, env=auth_env, text=True, capture_output=True)
            self.assertEqual(auth.returncode, 0, auth.stderr)
            self.assertIn("secret_values_redacted", auth.stdout)
            self.assertNotIn("discord-secret-value", auth.stdout)

            bridge = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"),
                "bridge-test", "--engagement", str(engagement), "--platform", "discord",
                "--allow-channel", "C1", "--allow-user", "U1", "--prefix", "!phobos",
                "--channel-id", "C1", "--user-id", "U1", "--message", "!phobos /status",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(bridge.returncode, 0, bridge.stderr)
            bridge_json = json.loads(bridge.stdout)
            self.assertEqual(bridge_json["result"]["status"], "handled")
            self.assertEqual(bridge_json["result"]["normalized_text"], "/status")

            once = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", '/assess target=app.example.test type=web purpose=headers command="curl -I https://app.example.test"',
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(once.returncode, 0, once.stderr)
            self.assertIn("Guardrail decision: allow", once.stdout)

            marker = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", '/remember key=db-at-rest value="DB_AT_REST_SECRET_MARKER"',
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(marker.returncode, 0, marker.stderr)
            sealed_env = dict(env)
            sealed_env["PHOBOS_TEST_DB_SEAL"] = "correct-passphrase"
            sealed = tmp_path / "agent.db.sealed"
            sealed_run = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "seal-db", "--out", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL", "--remove-plaintext",
            ], cwd=project, env=sealed_env, text=True, capture_output=True)
            self.assertEqual(sealed_run.returncode, 0, sealed_run.stderr)
            sealed_json = json.loads(sealed_run.stdout)
            self.assertEqual(sealed_json["status"], "sealed")
            self.assertFalse((tmp_path / "agent.db").exists())
            self.assertNotIn(b"DB_AT_REST_SECRET_MARKER", sealed.read_bytes())

            wrong_env = dict(env)
            wrong_env["PHOBOS_TEST_DB_SEAL_WRONG"] = "wrong-passphrase"
            wrong = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "wrong.db"), "unseal-db", "--in", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL_WRONG", "--overwrite",
            ], cwd=project, env=wrong_env, text=True, capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)

            unsealed = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "unseal-db", "--in", str(sealed), "--passphrase-env", "PHOBOS_TEST_DB_SEAL", "--overwrite",
            ], cwd=project, env=sealed_env, text=True, capture_output=True)
            self.assertEqual(unsealed.returncode, 0, unsealed.stderr)
            recalled = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--db", str(tmp_path / "agent.db"), "once", "--engagement", str(engagement), "--message", "/recall query=db-at-rest",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(recalled.returncode, 0, recalled.stderr)
            self.assertIn("DB_AT_REST_SECRET_MARKER", recalled.stdout)

    def test_phobos_agent_profiles_cli(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env["HOME"] = str(tmp_path)
            profile_init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "caligo",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(profile_init.returncode, 0, profile_init.stderr)
            profile_json = json.loads(profile_init.stdout)
            self.assertEqual(profile_json["profile"], "caligo")
            self.assertTrue(Path(profile_json["config"]).exists())

            profiles = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profiles",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(profiles.returncode, 0, profiles.stderr)
            self.assertIn("caligo", profiles.stdout)

            engagement = tmp_path / "engagement.json"
            init_engagement = subprocess.run([
                sys.executable, "-m", "phobos_agent.cli", "init",
                "--name", "Profile CLI", "--scope", "app.example.test", "--evidence-dir", str(tmp_path / "evidence"), "--out", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init_engagement.returncode, 0, init_engagement.stderr)

            init = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "--profile", "caligo", "init", "--engagement", str(engagement),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(init.returncode, 0, init.stderr)
            init_json = json.loads(init.stdout)
            self.assertIn(".phobos/profiles/caligo/phobos-agent.db", init_json["db"])
            self.assertTrue((tmp_path / ".phobos" / "profiles" / "caligo" / "phobos-agent.db").exists())

            bad = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "profile-init", "--name", "../bad",
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)

    def test_phobos_agent_config_init_cli(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        project = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "agent.config.json"
            completed = subprocess.run([
                sys.executable, "-m", "phobos_agent.agent_cli", "config-init", "--out", str(out),
            ], cwd=project, env=env, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(out.exists())
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["providers"][0]["provider"], "heuristic")
            self.assertFalse(data["auto_execute_natural"])
            self.assertFalse(data["auto_model_planning"])
            self.assertEqual(data["max_auto_steps"], 5)
            self.assertEqual(data["blocked_tools"], [])
            self.assertEqual(data["confirm_tools"], [])
            self.assertEqual(data["skill_dirs"], [])
            self.assertEqual(data["preload_skills"], [])
            self.assertEqual(data["skill_bundles"], {})
            self.assertIn("discord", data["bridges"])
            self.assertIn("slack", data["bridges"])
            self.assertIn("telegram", data["bridges"])
            self.assertEqual(data["bridges"]["discord"]["token_env"], "PHOBOS_DISCORD_TOKEN")
            self.assertFalse(data["bridges"]["discord"]["enabled"])
            self.assertFalse(data["bridges"]["discord"]["allow_approval_actions"])


if __name__ == "__main__":
    unittest.main()
