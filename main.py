import os
import re
import asyncio
from typing import Any
from dotenv import load_dotenv
from fastmcp import FastMCP
import requests
import defusedxml.ElementTree as DefusedET

# Load environment variables from .env file
load_dotenv()


# =============================================================================
# SECURITY: Input Validation Functions
# =============================================================================

# Patterns for validating OData input parameters
SAFE_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')
SAFE_IDS_PATTERN = re.compile(r'^[a-zA-Z0-9_\-,]+$')
SAFE_LOCALE_PATTERN = re.compile(r'^[a-zA-Z]{2}(-[a-zA-Z]{2})?$')
VALID_ENVIRONMENTS = {"preview", "production"}


def _validate_identifier(value: str, field_name: str) -> str:
    """Validate that a value contains only safe identifier characters."""
    if not value or not SAFE_IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, underscores, and hyphens")
    return value


def _validate_ids(value: str, field_name: str) -> str:
    """Validate comma-separated IDs contain only safe characters."""
    if not value or not SAFE_IDS_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, underscores, hyphens, and commas")
    return value


def _validate_locale(value: str) -> str:
    """Validate locale format (e.g., 'en-US', 'de')."""
    if not SAFE_LOCALE_PATTERN.match(value):
        raise ValueError(f"Invalid locale format: {value}. Expected format like 'en-US' or 'en'")
    return value


def _validate_environment(value: str) -> str:
    """Validate environment is one of the allowed values."""
    if value not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid environment: {value}. Must be one of: {VALID_ENVIRONMENTS}")
    return value


def _sanitize_odata_string(value: str) -> str:
    """Sanitize a string value for use in OData queries by escaping single quotes."""
    # Escape single quotes by doubling them (OData standard)
    return value.replace("'", "''")


def _xml_to_dict(xml_content: bytes) -> dict:
    """
    Safely parse XML to dictionary using defusedxml to prevent XXE attacks.

    Args:
        xml_content: XML content as bytes

    Returns:
        Dictionary representation of the XML
    """
    def element_to_dict(element):
        """Recursively convert an XML element to a dictionary."""
        result = {}

        # Add attributes with @ prefix
        if element.attrib:
            for key, value in element.attrib.items():
                result[f"@{key}"] = value

        # Process child elements
        children = list(element)
        if children:
            child_dict = {}
            for child in children:
                child_data = element_to_dict(child)
                tag = child.tag
                # Handle namespace in tag
                if '}' in tag:
                    tag = tag.split('}')[1]

                if tag in child_dict:
                    # Convert to list if multiple children with same tag
                    if not isinstance(child_dict[tag], list):
                        child_dict[tag] = [child_dict[tag]]
                    child_dict[tag].append(child_data if child_data else child.text)
                else:
                    child_dict[tag] = child_data if child_data else child.text
            result.update(child_dict)
        elif element.text and element.text.strip():
            # If no children but has text content
            if result:  # Has attributes
                result['#text'] = element.text.strip()
            else:
                return element.text.strip()

        return result if result else None

    # Parse with defusedxml (prevents XXE, billion laughs, etc.)
    root = DefusedET.fromstring(xml_content)

    # Get root tag (handle namespace)
    root_tag = root.tag
    if '}' in root_tag:
        root_tag = root_tag.split('}')[1]

    return {root_tag: element_to_dict(root)}


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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(entity, "entity")
        _validate_environment(environment)
    except ValueError as e:
        return {"error": str(e)}

    user_id, password = _resolve_credentials(auth_user_id, auth_password)
    api_host = _get_api_host(environment)

    if not user_id or not password:
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters, or set SF_USER_ID and SF_PASSWORD environment variables."}

    username = f"{user_id}@{instance}"
    apiUrl = f"https://{api_host}/odata/v2/{entity}/$metadata"
    credentials = (username, password)

    meta_response = requests.get(apiUrl, auth=credentials, timeout=30)

    # Check if request was successful
    if meta_response.status_code != 200:
        return {
            "error": f"HTTP {meta_response.status_code}",
            "message": "Request failed. Check instance and entity parameters."
        }

    # Check if response is empty
    if not meta_response.text.strip():
        return {"error": "Empty response from API"}

    # Try to parse XML safely (prevents XXE attacks)
    try:
        meta_json = _xml_to_dict(meta_response.text.encode("UTF-8"))
        return meta_json
    except Exception as e:
        return {
            "error": f"XML parse error: {str(e)}"
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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_environment(environment)
    except ValueError as e:
        return {"error": str(e)}

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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_environment(environment)
        if group_type:
            _validate_identifier(group_type, "group_type")
    except ValueError as e:
        return {"error": str(e)}

    params = {"$format": "json"}
    if group_type:
        # Sanitize to prevent OData injection
        safe_group_type = _sanitize_odata_string(group_type)
        params["$filter"] = f"groupType eq '{safe_group_type}'"

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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(role_ids, "role_ids")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        return {"error": str(e)}

    # Sanitize role_ids for OData query
    safe_role_ids = _sanitize_odata_string(role_ids)
    params = {"locale": locale, "roleIds": f"'{safe_role_ids}'", "$format": "json"}
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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(user_ids, "user_ids")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        return {"error": str(e)}

    # Sanitize user_ids for OData query
    safe_user_ids = _sanitize_odata_string(user_ids)
    params = {"locale": locale, "userIds": f"'{safe_user_ids}'", "$format": "json"}
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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        return {"error": str(e)}

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
    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(access_user_id, "access_user_id")
        _validate_identifier(target_user_id, "target_user_id")
        _validate_environment(environment)
        # perm_type and perm_string_value can have special chars like $ and _, so we sanitize instead
    except ValueError as e:
        return {"error": str(e)}

    # Sanitize all string values for OData query to prevent injection
    params = {
        "accessUserId": f"'{_sanitize_odata_string(access_user_id)}'",
        "targetUserId": f"'{_sanitize_odata_string(target_user_id)}'",
        "permType": f"'{_sanitize_odata_string(perm_type)}'",
        "permStringValue": f"'{_sanitize_odata_string(perm_string_value)}'",
        "permLongValue": _sanitize_odata_string(perm_long_value),
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
