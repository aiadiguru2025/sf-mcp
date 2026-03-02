"""FastMCP dependency injection for tool-internal parameters.

Parameters with Dependency defaults are automatically hidden from the
MCP tool schema by FastMCP's DI engine (it checks isinstance(default, Dependency)).

The sf_tool decorator overrides the actual values (request_id,
start_time, api_host) at runtime. These dependency classes serve as
schema-exclusion markers with sensible fallback defaults.
"""

import time
import uuid
from typing import Any, cast

from fastmcp.server.dependencies import Dependency


class _RequestId(Dependency):
    """Generates a short unique request ID for tracing."""

    async def __aenter__(self) -> Any:
        return str(uuid.uuid4())[:8]


def RequestId() -> str:
    """Dependency that provides a unique request ID per tool call."""
    return cast(str, _RequestId())


class _StartTime(Dependency):
    """Captures the wall-clock start time of the tool invocation."""

    async def __aenter__(self) -> Any:
        return time.time()


def StartTime() -> float:
    """Dependency that provides the start timestamp per tool call."""
    return cast(float, _StartTime())


class _ApiHost(Dependency):
    """Placeholder resolved by the sf_tool decorator from data_center + environment."""

    async def __aenter__(self) -> Any:
        return ""


def ApiHost() -> str:
    """Dependency that provides the resolved SAP API hostname."""
    return cast(str, _ApiHost())
