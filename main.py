import os
import asyncio
from typing import Any
from dotenv import load_dotenv
from fastmcp import FastMCP
import requests
import xmltodict

# Load environment variables from .env file
load_dotenv()

# API host configuration for different environments
SF_API_HOSTS = {
    "production": "api55.sapsf.eu",
    "preview": "api55preview.sapsf.eu"
}


def _get_api_host(environment: str = "preview") -> str:
    """Return the appropriate API host based on environment."""
    return SF_API_HOSTS.get(environment, SF_API_HOSTS["preview"])


def _resolve_credentials(
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> tuple[str | None, str | None]:
    """Resolve credentials from parameters or fall back to environment variables."""
    resolved_user_id = auth_user_id if auth_user_id else os.environ.get("SF_USER_ID")
    resolved_password = auth_password if auth_password else os.environ.get("SF_PASSWORD")
    return resolved_user_id, resolved_password


#Init Server
mcp = FastMCP("SFgetConfig")


def _make_sf_odata_request(
    instance: str,
    endpoint: str,
    params: dict | None = None,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Make an OData API request to SuccessFactors (JSON format).

    Args:
        instance: The SuccessFactors instance/company ID
        endpoint: The OData endpoint path (e.g., "/odata/v2/RBPRole")
        params: Optional query parameters
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict with either the JSON response data or an error dict
    """
    user_id, password = _resolve_credentials(auth_user_id, auth_password)
    api_host = _get_api_host(environment)

    if not user_id or not password:
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters, or set SF_USER_ID and SF_PASSWORD environment variables."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}{endpoint}"
    credentials = (username, password)
    headers = {"Accept": "application/json"}

    try:
        response = requests.get(url, auth=credentials, headers=headers, params=params)

        if response.status_code != 200:
            return {
                "error": f"HTTP {response.status_code}",
                "message": response.text[:500]
            }

        if not response.text.strip():
            return {"error": "Empty response from API"}

        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except ValueError as e:
        return {"error": f"JSON parse error: {str(e)}", "response_preview": response.text[:500]}

@mcp.tool()
def get_configuration(
    instance: str,
    entity: str,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get Configuration metadata details for the entity within the instance.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: The OData entity name (e.g., "User", "EmpEmployment")
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)
    """
    user_id, password = _resolve_credentials(auth_user_id, auth_password)
    api_host = _get_api_host(environment)

    if not user_id or not password:
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters, or set SF_USER_ID and SF_PASSWORD environment variables."}

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


@mcp.tool()
def get_rbp_roles(
    instance: str,
    include_description: bool = False,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all RBP (Role-Based Permission) roles in the SuccessFactors instance.

    Args:
        instance: The SuccessFactors instance/company ID
        include_description: If True, includes role descriptions
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing list of roles with roleId, roleName, userType, lastModifiedDate
    """
    select_fields = "roleId,roleName,userType,lastModifiedDate"
    if include_description:
        select_fields += ",roleDesc"

    params = {"$select": select_fields, "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/RBPRole", params, environment, auth_user_id, auth_password)

    if "error" in result:
        return result

    # Extract results from OData response
    if "d" in result and "results" in result["d"]:
        return {"roles": result["d"]["results"], "count": len(result["d"]["results"])}

    return result


@mcp.tool()
def get_dynamic_groups(
    instance: str,
    group_type: str | None = None,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get dynamic groups (permission groups) used in RBP rules.

    Args:
        instance: The SuccessFactors instance/company ID
        group_type: Optional filter for group type
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing list of dynamic groups
    """
    params = {"$format": "json"}
    if group_type:
        params["$filter"] = f"groupType eq '{group_type}'"

    result = _make_sf_odata_request(instance, "/odata/v2/DynamicGroup", params, environment, auth_user_id, auth_password)

    if "error" in result:
        return result

    # Extract results from OData response
    if "d" in result and "results" in result["d"]:
        return {"groups": result["d"]["results"], "count": len(result["d"]["results"])}

    return result


@mcp.tool()
def get_role_permissions(
    instance: str,
    role_ids: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all permissions assigned to one or more RBP roles.

    Args:
        instance: The SuccessFactors instance/company ID
        role_ids: Role ID(s) - single ID ("10") or comma-separated ("10,20,30")
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing role details and permissions
    """
    params = {"locale": locale, "roleIds": f"'{role_ids}'", "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/getRolesPermissions", params, environment, auth_user_id, auth_password)

    if "error" in result:
        return result

    return {"role_ids": role_ids, "permissions": result}


@mcp.tool()
def get_user_permissions(
    instance: str,
    user_ids: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all permissions for one or more users based on their assigned roles.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: User ID(s) - single ID ("admin") or comma-separated ("admin,user2,user3")
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing the users' effective permissions from all assigned roles
    """
    params = {"locale": locale, "userIds": f"'{user_ids}'", "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/getUsersPermissions", params, environment, auth_user_id, auth_password)

    if "error" in result:
        return result

    return {"user_ids": user_ids, "permissions": result}


@mcp.tool()
def get_permission_metadata(
    instance: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get permission metadata mapping UI labels to permission types and values.

    This API helps map the UI text to the permission type and permission string value,
    which are needed for the checkUserPermission API.

    Args:
        instance: The SuccessFactors instance/company ID
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing permission metadata with field-id, perm-type, and permission-string-value
    """
    params = {"locale": locale}
    return _make_sf_odata_request(instance, "/odata/v2/getPermissionMetadata", params, environment, auth_user_id, auth_password)


@mcp.tool()
def check_user_permission(
    instance: str,
    access_user_id: str,
    target_user_id: str,
    perm_type: str,
    perm_string_value: str,
    perm_long_value: str = "-1L",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Check if a user has a specific permission for a target user.

    Args:
        instance: The SuccessFactors instance/company ID
        access_user_id: The user making the permission check
        target_user_id: The user whose data access is being verified
        perm_type: Permission category (e.g., "EmployeeFilesViews_type")
        perm_string_value: Permission identifier (e.g., "$_payrollIntegration_view")
        perm_long_value: Long value representation (default: "-1L")
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing boolean permission status (true/false)
    """
    params = {
        "accessUserId": f"'{access_user_id}'",
        "targetUserId": f"'{target_user_id}'",
        "permType": f"'{perm_type}'",
        "permStringValue": f"'{perm_string_value}'",
        "permLongValue": perm_long_value,
        "$format": "json"
    }
    return _make_sf_odata_request(instance, "/odata/v2/checkUserPermission", params, environment, auth_user_id, auth_password)


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
