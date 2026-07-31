from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json

from .agent_runtime import AgentRuntimeConfig
from .agent_bridges import BridgeConfig, default_bridge_configs
from .config_types import config_bool, config_int, config_optional_string, config_string, config_string_list, config_string_list_map


@dataclass(slots=True)
class ModelProviderConfig:
    provider: str = "heuristic"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    key_env: str = "OPENAI_API_KEY"
    command_template: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, field: str = "providers[]") -> "ModelProviderConfig":
        if not isinstance(data, dict):
            raise ValueError(f"{field} must be an object.")
        return cls(
            provider=config_string(data.get("provider", "heuristic"), f"{field}.provider", default="heuristic"),
            model=config_string(data.get("model", "gpt-4o-mini"), f"{field}.model", default="gpt-4o-mini"),
            base_url=config_optional_string(data.get("base_url"), f"{field}.base_url"),
            key_env=config_string(data.get("key_env", "OPENAI_API_KEY"), f"{field}.key_env", default="OPENAI_API_KEY"),
            command_template=config_optional_string(data.get("command_template"), f"{field}.command_template"),
        )


@dataclass(slots=True)
class AgentAppConfig:
    """Disk-backed runtime configuration for the standalone Phobos Agent.

    The file format is intentionally JSON so the runtime stays stdlib-only. It
    models the Hermes-style pieces the Phobos runtime needs: workspace location,
    plugin directories, context budget, tool timeout, and model fallback chain.
    """

    workspace_dir: str = "agent-workspace"
    operator_name: str = "operator"
    assistant_style: str = "direct, concise, practical, evidence-first"
    plugin_dirs: list[str] = field(default_factory=list)
    max_context_messages: int = 12
    tool_timeout: int = 30
    auto_execute_natural: bool = False
    auto_model_planning: bool = False
    max_auto_steps: int = 5
    blocked_tools: list[str] = field(default_factory=list)
    confirm_tools: list[str] = field(default_factory=list)
    skill_dirs: list[str] = field(default_factory=list)
    preload_skills: list[str] = field(default_factory=list)
    skill_bundles: dict[str, list[str]] = field(default_factory=dict)
    bridges: dict[str, dict[str, Any]] = field(default_factory=default_bridge_configs)
    providers: list[ModelProviderConfig] = field(default_factory=lambda: [ModelProviderConfig()])

    @classmethod
    def default(cls) -> "AgentAppConfig":
        return cls()

    @classmethod
    def load(cls, path: str | Path) -> "AgentAppConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("agent config must be a JSON object.")
        provider_items = data.get("providers", [])
        if isinstance(provider_items, dict):
            provider_items = [provider_items]
        if provider_items is None:
            provider_items = []
        if not isinstance(provider_items, list):
            raise ValueError("providers must be a list of objects.")
        providers = [ModelProviderConfig.from_dict(item, field=f"providers[{idx}]") for idx, item in enumerate(provider_items)]
        if not providers:
            providers = [ModelProviderConfig()]
        return cls(
            workspace_dir=config_string(data.get("workspace_dir", "agent-workspace"), "workspace_dir", default="agent-workspace"),
            operator_name=config_string(data.get("operator_name", "operator"), "operator_name", default="operator"),
            assistant_style=config_string(data.get("assistant_style", "direct, concise, practical, evidence-first"), "assistant_style", default="direct, concise, practical, evidence-first"),
            plugin_dirs=config_string_list(data.get("plugin_dirs", []), "plugin_dirs"),
            max_context_messages=config_int(data.get("max_context_messages", 12), "max_context_messages", default=12, minimum=1),
            tool_timeout=config_int(data.get("tool_timeout", 30), "tool_timeout", default=30, minimum=1),
            auto_execute_natural=config_bool(data.get("auto_execute_natural", False), "auto_execute_natural", default=False),
            auto_model_planning=config_bool(data.get("auto_model_planning", False), "auto_model_planning", default=False),
            max_auto_steps=config_int(data.get("max_auto_steps", 5), "max_auto_steps", default=5, minimum=1, maximum=10),
            blocked_tools=config_string_list(data.get("blocked_tools", []), "blocked_tools"),
            confirm_tools=config_string_list(data.get("confirm_tools", []), "confirm_tools"),
            skill_dirs=config_string_list(data.get("skill_dirs", []), "skill_dirs"),
            preload_skills=config_string_list(data.get("preload_skills", []), "preload_skills"),
            skill_bundles=config_string_list_map(data.get("skill_bundles", {}), "skill_bundles"),
            bridges=_load_bridge_configs(data.get("bridges")),
            providers=providers,
        )

    def save(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(self)
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return out

    def to_runtime_config(self, engagement_path: str, db_path: str, session_name: str, config_path: str | None = None) -> AgentRuntimeConfig:
        first = self.providers[0] if self.providers else ModelProviderConfig()
        return AgentRuntimeConfig(
            engagement_path=engagement_path,
            db_path=db_path,
            session_name=session_name,
            operator_name=self.operator_name,
            assistant_style=self.assistant_style,
            provider=first.provider,
            model=first.model,
            base_url=first.base_url,
            key_env=first.key_env,
            command_template=first.command_template,
            workspace_dir=self.workspace_dir,
            plugin_dirs=tuple(self.plugin_dirs),
            max_context_messages=self.max_context_messages,
            tool_timeout=self.tool_timeout,
            auto_execute_natural=self.auto_execute_natural,
            auto_model_planning=self.auto_model_planning,
            max_auto_steps=self.max_auto_steps,
            blocked_tools=tuple(self.blocked_tools),
            confirm_tools=tuple(self.confirm_tools),
            skill_dirs=tuple(self.skill_dirs),
            preload_skills=tuple(self.preload_skills),
            skill_bundles={name: tuple(skills) for name, skills in self.skill_bundles.items()},
            bridges={name: dict(config) for name, config in self.bridges.items()},
            model_providers=tuple(asdict(provider) for provider in self.providers),
            config_path=config_path,
        )


def _load_bridge_configs(value: Any) -> dict[str, dict[str, Any]]:
    configs = default_bridge_configs()
    if value is None:
        return configs
    if not isinstance(value, dict):
        raise ValueError("bridges must be an object.")
    for platform, data in value.items():
        platform_name = config_string(platform, "bridges key").strip()
        if not platform_name:
            continue
        if not isinstance(data, dict):
            raise ValueError(f"bridges.{platform_name} must be an object.")
        merged = dict(configs.get(platform_name, {})) | dict(data)
        BridgeConfig.from_dict(platform_name, merged)
        configs[platform_name] = merged
    return configs
