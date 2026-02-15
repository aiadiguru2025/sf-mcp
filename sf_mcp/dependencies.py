"""FastMCP dependency injection for tool-internal parameters.

These dependencies replace the deprecated `exclude_args` pattern.
Parameters annotated with Depends() are automatically hidden from the
MCP tool schema and resolved at runtime by FastMCP's DI engine.

The sf_tool decorator still generates the actual values (request_id,
start_time) and computes api_host from data_center + environment.
These dependency functions serve as schema-exclusion markers with
sensible fallback defaults for direct (non-MCP) invocation.
"""

import time
import uuid
from typing import cast

from docket.dependencies import Dependency


class _RequestId(Dependency):
    """Generates a short unique request ID for tracing."""

    async def __aenter__(self) -> str:
        return str(uuid.uuid4())[:8]


def RequestId() -> str:
    """Dependency that provides a unique request ID per tool call."""
    return cast(str, _RequestId())


class _StartTime(Dependency):
    """Captures the wall-clock start time of the tool invocation."""

    async def __aenter__(self) -> float:
        return time.time()


def StartTime() -> float:
    """Dependency that provides the start timestamp per tool call."""
    return cast(float, _StartTime())


class _ApiHost(Dependency):
    """Placeholder resolved by the sf_tool decorator from data_center + environment."""

    async def __aenter__(self) -> str:
        return ""


def ApiHost() -> str:
    """Dependency that provides the resolved SAP API hostname."""
    return cast(str, _ApiHost())
