"""Structured logging configuration for Cloud Logging compatibility."""

import json
import logging
import uuid


class CloudLoggingFormatter(logging.Formatter):
    """JSON formatter compatible with Google Cloud Logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }

        if hasattr(record, "audit_data"):
            log_entry["audit"] = record.audit_data
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "tool_name"):
            log_entry["tool_name"] = record.tool_name
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def _setup_logging() -> logging.Logger:
    """Configure structured logging for the application."""
    logger = logging.getLogger("sf-mcp")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(CloudLoggingFormatter())
        logger.addHandler(handler)

    return logger


logger = _setup_logging()


def _mask_sensitive_data(data: dict) -> dict:
    """Mask sensitive fields in data for logging."""
    sensitive_fields = {"auth_password", "password", "SF_PASSWORD", "credentials"}
    masked = {}
    for key, value in data.items():
        if key.lower() in {f.lower() for f in sensitive_fields}:
            masked[key] = "***MASKED***" if value else None
        elif isinstance(value, dict):
            masked[key] = _mask_sensitive_data(value)
        else:
            masked[key] = value
    return masked


def audit_log(
    event_type: str,
    tool_name: str | None = None,
    instance: str | None = None,
    user_id: str | None = None,
    status: str = "success",
    details: dict | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None,
) -> None:
    """
    Log an audit event with structured data.

    Args:
        event_type: Type of event (tool_invocation, authentication, validation_error, api_request)
        tool_name: Name of the MCP tool being called
        instance: SuccessFactors instance ID
        user_id: User ID making the request (masked for auth events)
        status: Event status (success, failure, error)
        details: Additional event details (sensitive data will be masked)
        request_id: Unique request identifier for tracing
        duration_ms: Request duration in milliseconds
    """
    audit_data = {
        "event_type": event_type,
        "status": status,
        "instance": instance,
    }

    if tool_name:
        audit_data["tool_name"] = tool_name
    if user_id:
        audit_data["user_id_prefix"] = user_id[:4] + "***" if len(user_id) > 4 else "***"
    if details:
        audit_data["details"] = _mask_sensitive_data(details)

    extra = {
        "audit_data": audit_data,
        "request_id": request_id or str(uuid.uuid4())[:8],
    }
    if tool_name:
        extra["tool_name"] = tool_name
    if duration_ms is not None:
        extra["duration_ms"] = round(duration_ms, 2)

    level = logging.INFO if status == "success" else logging.WARNING
    logger.log(level, f"AUDIT: {event_type} - {status}", extra=extra)
