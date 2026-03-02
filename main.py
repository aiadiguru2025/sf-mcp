"""SF-MCP: SAP SuccessFactors Model Context Protocol Server.

Provides 43 tools for querying and managing SuccessFactors via OData APIs.
Supports both stdio mode (Claude Desktop) and HTTP mode (Cloud Run).
"""

import os

from dotenv import load_dotenv

load_dotenv()

import sf_mcp.tools  # noqa: E402, F401 — triggers @mcp.tool() registrations
from sf_mcp.auth import MCP_API_KEY, APIKeyMiddleware  # noqa: E402
from sf_mcp.server import mcp  # noqa: E402


def main():
    """Start the MCP server in HTTP mode (Cloud Run) or stdio mode (Claude Desktop)."""
    if os.environ.get("PORT"):
        # HTTP mode for Cloud Run
        import uvicorn
        from starlette.middleware import Middleware

        middleware = []
        if MCP_API_KEY:
            middleware.append(Middleware(APIKeyMiddleware))

        app = mcp.http_app(
            transport="streamable-http",
            middleware=middleware or None,
        )

        port = int(os.environ["PORT"])
        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        # Stdio mode for Claude Desktop
        mcp.run()


if __name__ == "__main__":
    main()
