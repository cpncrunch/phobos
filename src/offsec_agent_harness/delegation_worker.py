from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .model_adapters import HeuristicAdapter
from .models import redact_secrets


def _redacted(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value) or ""
    if isinstance(value, dict):
        return {str(k): _redacted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    return value


def run_worker(payload: dict[str, Any]) -> dict[str, Any]:
    role = str(payload.get("role") or "impact")
    prompt = redact_secrets(str(payload.get("prompt") or "")) or ""
    context = redact_secrets(str(payload.get("context") or "")) or ""
    child_workspace = str(payload.get("child_workspace") or "")
    if child_workspace:
        Path(child_workspace).mkdir(parents=True, exist_ok=True)
    response = HeuristicAdapter().generate(role, prompt, context=context)
    return _redacted({
        "status": "ok",
        "role": role,
        "content": response.content,
        "metadata": {
            "sandbox": "process",
            "process_isolated": True,
            "no_target_activity": True,
            "child_session_id": str(payload.get("child_session_id") or ""),
            "child_session_name": str(payload.get("child_session_name") or ""),
            "child_workspace": child_workspace,
            "input_redacted": True,
        },
    })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one Phobos delegation task in a separate local worker process.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output_path = Path(args.output)
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        result = run_worker(payload if isinstance(payload, dict) else {})
    except Exception as exc:  # pragma: no cover - defensive process boundary
        result = {"status": "error", "content": "ERROR: " + (redact_secrets(str(exc)) or exc.__class__.__name__), "metadata": {"sandbox": "process", "process_isolated": True, "no_target_activity": True}}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(_redacted(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":  # pragma: no cover - subprocess entrypoint
    raise SystemExit(main())
