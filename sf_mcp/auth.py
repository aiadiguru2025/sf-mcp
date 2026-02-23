"""Authentication, credential handling, and API key middleware."""

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from sf_mcp.logging_config import audit_log, logger


def resolve_credentials(auth_user_id: str, auth_password: str) -> tuple[str, str]:
    """Return credentials provided by caller. Credentials are required on every tool call."""
    return auth_user_id, auth_password


def _get_mcp_api_key() -> str | None:
    """
    Get MCP API key from environment or GCP Secret Manager.

    Priority:
    1. MCP_API_KEY environment variable
    2. GCP Secret Manager (if GCP_PROJECT_ID is set)

    Returns:
        API key string or None if not configured
    """
    api_key = os.environ.get("MCP_API_KEY")
    if api_key:
        return api_key

    try:
        from google.cloud import secretmanager

        project_id = os.environ.get("GCP_PROJECT_ID")
        if project_id:
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/mcp-api-key/versions/latest"
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
    except (ImportError, Exception):
        pass

    return None


MCP_API_KEY = _get_mcp_api_key()
if MCP_API_KEY:
    logger.info("MCP API key authentication enabled")
else:
    logger.warning("MCP API key not configured - endpoint is unprotected")


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate API key for MCP endpoint protection.

    Accepts API key via:
    - X-API-Key header
    - Authorization: Bearer <key> header
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in ["/health", "/healthz", "/"]:
            return await call_next(request)

        if MCP_API_KEY:
            client_key = request.headers.get("X-API-Key")
            if not client_key:
                auth_header = request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    client_key = auth_header[7:]

            if client_key != MCP_API_KEY:
                audit_log(
                    event_type="authentication",
                    status="failure",
                    details={
                        "reason": "invalid_api_key",
                        "path": str(request.url.path),
                        "has_key": bool(client_key),
                    },
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )

        return await call_next(request)
