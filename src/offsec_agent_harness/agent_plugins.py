from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any
import importlib.util
import traceback


class PluginLoadError(RuntimeError):
    pass


def load_plugins(registry: Any, plugin_dirs: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    """Load local Phobos Agent plugins from Python files.

    A plugin is a `.py` file with a `register(registry)` function. The registry
    exposes `register_tool(name, handler, spec)` and the usual built-in types.
    Plugins run locally with the operator's permissions, so load paths are
    explicit and audit entries are created for success/failure.
    """

    loaded: list[dict[str, Any]] = []
    for directory in plugin_dirs:
        root = Path(directory).expanduser().resolve()
        if not root.exists():
            loaded.append({"directory": str(root), "status": "missing"})
            continue
        for plugin_file in sorted(root.glob("*.py")):
            if plugin_file.name.startswith("_"):
                continue
            record = {"path": str(plugin_file), "name": plugin_file.stem, "status": "pending"}
            try:
                module = _load_module(plugin_file)
                register = getattr(module, "register", None)
                if not callable(register):
                    record.update({"status": "skipped", "reason": "no register(registry) function"})
                else:
                    before = {spec.name for spec in registry.specs()}
                    register(registry)
                    after = {spec.name for spec in registry.specs()}
                    record.update({"status": "loaded", "tools": sorted(after - before)})
                    registry.store.audit(registry.session_id, "plugin_loaded", record)
            except Exception as exc:  # pragma: no cover - exact plugin errors are operator supplied
                record.update({"status": "error", "error": str(exc), "traceback": traceback.format_exc(limit=5)})
                registry.store.audit(registry.session_id, "plugin_error", record)
            loaded.append(record)
    return loaded


def _load_module(plugin_file: Path) -> ModuleType:
    module_name = f"offsec_agent_plugin_{plugin_file.stem}_{abs(hash(str(plugin_file)))}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"Could not load plugin spec for {plugin_file}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
