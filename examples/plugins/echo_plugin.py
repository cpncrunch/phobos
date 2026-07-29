"""Example Phobos Agent plugin.

Load with:

    offsec-agent --plugin-dir examples/plugins ...

Plugins run locally and should keep target-affecting activity behind the built-in
ROE-gated tools. This example is intentionally local/read-only.
"""

from offsec_agent_harness.agent_tools import ToolResult


def register(registry):
    def echo(args):
        value = str(args.get("value", ""))
        return ToolResult("ok", "Example plugin echo.", {"echo": value})

    registry.register_tool(
        "example_echo",
        echo,
        {
            "description": "Echo a value from the example local plugin.",
            "schema": {
                "type": "object",
                "properties": {"value": {"type": "string", "description": "Text to echo."}},
                "required": [],
            },
        },
    )
