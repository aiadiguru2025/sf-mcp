import os
import asyncio
from typing import Any
from dotenv import load_dotenv
from fastmcp import FastMCP
import requests
import xmltodict

# Load environment variables from .env file
load_dotenv()

#Init Server
mcp = FastMCP("SFgetConfig")

@mcp.tool()
def get_configuration(instance: str , entity: str ) -> dict[str, Any]:
    """Get Configuration metadata details for the entity within the instance"""
    user_id = os.environ.get("SF_USER_ID")
    password = os.environ.get("SF_PASSWORD")
    api_host = os.environ.get("SF_API_HOST", "api55preview.sapsf.eu")

    if not user_id or not password:
        return {"error": "Missing credentials. Set SF_USER_ID and SF_PASSWORD environment variables."}

    username = f"{user_id}@{instance}"
    apiUrl = f"https://{api_host}/odata/v2/{entity}/$metadata"
    credentials = (username, password)

    meta_response = requests.get(apiUrl, auth=credentials)

    # Check if request was successful
    if meta_response.status_code != 200:
        return {
            "error": f"HTTP {meta_response.status_code}",
            "message": meta_response.text[:500]
        }

    # Check if response is empty
    if not meta_response.text.strip():
        return {"error": "Empty response from API"}

    # Try to parse XML
    try:
        meta_json = xmltodict.parse(meta_response.text.encode("UTF-8"))
        return meta_json
    except Exception as e:
        return {
            "error": f"XML parse error: {str(e)}",
            "response_preview": meta_response.text[:500]
        }


if __name__ == "__main__":
    # Get port from environment (Cloud Run sets PORT)
    port = int(os.environ.get("PORT", 8080))

    # Use streamable-http transport for Cloud Run deployment
    asyncio.run(
        mcp.run_async(
            transport="streamable-http",
            host="0.0.0.0",
            port=port,
        )
    )
