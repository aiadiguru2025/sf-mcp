"""Tool decorator that eliminates boilerplate from MCP tool functions."""

import functools
import time
import uuid
from collections.abc import Callable
from typing import Any

from sf_mcp.config import get_api_host
from sf_mcp.logging_config import audit_log
from sf_mcp.validation import VALIDATORS, validate_identifier


def sf_tool(
    tool_name: str,
    validate: dict[str, str] | None = None,
    max_top: int | None = None,
):
    """
    Decorator that wraps an MCP tool function with standard boilerplate.

    Handles:
    - Generates request_id and start_time
    - Logs tool_invocation started/success/error
    - Validates instance (always) and optional extra fields
    - Resolves api_host from data_center + environment
    - Clamps `top` parameter if max_top is set
    - Catches ValueError from validation and returns error dict
    - Catches all exceptions and returns error dict + logs

    The wrapped function receives these as extra keyword-only args:
        request_id: str
        start_time: float
        api_host: str

    Args:
        tool_name: Name for audit logging
        validate: Optional dict mapping param_name -> validator_name for additional validation
        max_top: Optional maximum value for a `top` parameter
    """

    def decorator(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> dict[str, Any]:
            request_id = str(uuid.uuid4())[:8]
            start_time_val = time.time()
            instance = kwargs.get("instance", "")

            # Clamp top if applicable
            if max_top is not None and "top" in kwargs:
                top = kwargs["top"]
                kwargs["top"] = max(1, min(top, max_top))

            # Build safe details for logging (mask password)
            log_details = {k: v for k, v in kwargs.items() if k not in ("auth_password",)}

            # Log start
            audit_log(
                event_type="tool_invocation",
                tool_name=tool_name,
                instance=instance,
                status="started",
                details=log_details,
                request_id=request_id,
            )

            # Validation phase
            try:
                validate_identifier(instance, "instance")
                if validate:
                    for param_name, validator_name in validate.items():
                        value = kwargs.get(param_name)
                        if value is not None:
                            validator_fn = VALIDATORS.get(validator_name)
                            if validator_fn:
                                validator_fn(value, param_name)
                # Always resolve api_host
                api_host = get_api_host(
                    kwargs.get("data_center", ""),
                    kwargs.get("environment", ""),
                )
            except ValueError as e:
                audit_log(
                    event_type="validation_error",
                    tool_name=tool_name,
                    instance=instance,
                    status="failure",
                    details={"error": str(e)},
                    request_id=request_id,
                    duration_ms=(time.time() - start_time_val) * 1000,
                )
                return {"error": str(e)}

            # Inject context into kwargs
            kwargs["request_id"] = request_id
            kwargs["start_time"] = start_time_val
            kwargs["api_host"] = api_host

            # Execute the actual tool logic
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                audit_log(
                    event_type="tool_invocation",
                    tool_name=tool_name,
                    instance=instance,
                    status="error",
                    details={"error": str(e)},
                    request_id=request_id,
                    duration_ms=(time.time() - start_time_val) * 1000,
                )
                return {"error": f"Internal error: {str(e)}"}

            # Log success or error based on result
            if isinstance(result, dict) and "error" in result:
                audit_log(
                    event_type="tool_invocation",
                    tool_name=tool_name,
                    instance=instance,
                    status="error",
                    details={"error": result.get("error")},
                    request_id=request_id,
                    duration_ms=(time.time() - start_time_val) * 1000,
                )
            else:
                audit_log(
                    event_type="tool_invocation",
                    tool_name=tool_name,
                    instance=instance,
                    status="success",
                    request_id=request_id,
                    duration_ms=(time.time() - start_time_val) * 1000,
                )

            return result

        return wrapper

    return decorator
