from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import json

from .agent_runtime import AgentRuntimeConfig
from .agent_bridges import default_bridge_configs


@dataclass(slots=True)
class ModelProviderConfig:
    provider: str = "heuristic"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    key_env: str = "OPENAI_API_KEY"
    command_template: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelProviderConfig":
        return cls(
            provider=str(data.get("provider", "heuristic")),
            model=str(data.get("model", "gpt-4o-mini")),
            base_url=data.get("base_url"),
            key_env=str(data.get("key_env", "OPENAI_API_KEY")),
            command_template=data.get("command_template"),
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
        providers = [ModelProviderConfig.from_dict(item) for item in data.get("providers", [])]
        if not providers:
            providers = [ModelProviderConfig()]
        return cls(
            workspace_dir=str(data.get("workspace_dir", "agent-workspace")),
            operator_name=str(data.get("operator_name", "operator")),
            assistant_style=str(data.get("assistant_style", "direct, concise, practical, evidence-first")),
            plugin_dirs=[str(p) for p in data.get("plugin_dirs", [])],
            max_context_messages=int(data.get("max_context_messages", 12)),
            tool_timeout=int(data.get("tool_timeout", 30)),
            auto_execute_natural=bool(data.get("auto_execute_natural", False)),
            auto_model_planning=bool(data.get("auto_model_planning", False)),
            max_auto_steps=int(data.get("max_auto_steps", 5)),
            blocked_tools=[str(item) for item in data.get("blocked_tools", [])],
            confirm_tools=[str(item) for item in data.get("confirm_tools", [])],
            skill_dirs=[str(item) for item in data.get("skill_dirs", [])],
            preload_skills=[str(item) for item in data.get("preload_skills", [])],
            skill_bundles={str(key): [str(item) for item in value] for key, value in dict(data.get("skill_bundles", {})).items()},
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
    if not isinstance(value, dict):
        return configs
    for platform, data in value.items():
        if isinstance(data, dict):
            configs[str(platform)] = dict(configs.get(str(platform), {})) | dict(data)
    return configs
