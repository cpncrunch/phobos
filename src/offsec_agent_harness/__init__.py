"""Authorized offensive security agent harness."""

from .models import ActionRequest, DecisionStatus, EngagementROE, SafetyDecision
from .guardrails import GuardrailEngine
from .harness import OffSecHarness
from .bloodhound import analyze_bloodhound
from .burp_mcp import BurpMCPClient, HTTPRequestArtifact
from .cve_advisor import CveAdvisor
from .model_adapters import FallbackModelAdapter, build_adapter, build_fallback_adapter
from .reporting import FindingInput, FindingMarkdownExporter
from .agent_runtime import AgentRuntimeConfig, OffSecAgentRuntime
from .agent_store import AgentStore
from .agent_config import AgentAppConfig, ModelProviderConfig
from .agent_gateway import AgentGateway
from .agent_planner import AgentPlan, PlannedToolCall, plan_agent_actions
from .agent_skills import LocalSkill, discover_skills, load_skill, render_loaded_skills
from .agent_bridges import BridgeConfig, BridgeDispatchResult, BridgeMessage, chunk_text, default_bridge_configs, handle_bridge_message, run_bridge

PhobosAgentRuntime = OffSecAgentRuntime

__all__ = [
    "ActionRequest",
    "DecisionStatus",
    "EngagementROE",
    "SafetyDecision",
    "GuardrailEngine",
    "OffSecHarness",
    "analyze_bloodhound",
    "BurpMCPClient",
    "HTTPRequestArtifact",
    "CveAdvisor",
    "build_adapter",
    "build_fallback_adapter",
    "FallbackModelAdapter",
    "FindingInput",
    "FindingMarkdownExporter",
    "AgentRuntimeConfig",
    "OffSecAgentRuntime",
    "PhobosAgentRuntime",
    "AgentStore",
    "AgentAppConfig",
    "ModelProviderConfig",
    "AgentGateway",
    "AgentPlan",
    "PlannedToolCall",
    "plan_agent_actions",
    "LocalSkill",
    "discover_skills",
    "load_skill",
    "render_loaded_skills",
    "BridgeConfig",
    "BridgeDispatchResult",
    "BridgeMessage",
    "chunk_text",
    "default_bridge_configs",
    "handle_bridge_message",
    "run_bridge",
]
