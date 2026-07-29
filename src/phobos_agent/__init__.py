"""Phobos Agent public package.

The implementation lives in :mod:`offsec_agent_harness` for backwards
compatibility with the original prototype. New integrations can import from
``phobos_agent`` while older ``offsec_agent_harness`` imports keep working.
"""

from offsec_agent_harness import *  # noqa: F401,F403
from offsec_agent_harness import OffSecAgentRuntime as PhobosAgentRuntime

try:
    from offsec_agent_harness import __all__ as _legacy_all
except ImportError:  # pragma: no cover - defensive
    _legacy_all = []

__all__ = list(_legacy_all) + ["PhobosAgentRuntime"]
