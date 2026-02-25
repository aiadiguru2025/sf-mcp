"""RBP Security tools: roles, permissions, dynamic groups."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_rbp_roles")
def get_rbp_roles(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_description: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get all Role-Based Permission (RBP) roles in the instance.

    Lists all security roles configured in the system, including admin roles,
    HR roles, manager roles, and employee self-service roles.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_description: If True, includes detailed role descriptions
    """
    select_fields = "roleId,roleName,userType,lastModifiedDate"
    if include_description:
        select_fields += ",roleDesc"

    params = {"$select": select_fields, "$format": "json"}
    result = make_odata_request(
        instance,
        "/odata/v2/RBPRole",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
        cache_category="permissions",
    )

    if "error" in result:
        return result

    roles = result.get("d", {}).get("results", [])
    return {"roles": roles, "count": len(roles)}


@mcp.tool()
@sf_tool("get_role_permissions")
def get_role_permissions(
    instance: str,
    role_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get detailed permissions for a specific RBP role.

    Shows what each role can access and do - essential for security audits.

    Args:
        instance: The SuccessFactors instance/company ID
        role_id: The role ID to get permissions for (e.g., "10")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for labels (default: en-US)
    """
    safe_role_id = sanitize_odata_string(role_id)
    params = {
        "locale": locale,
        "roleIds": f"'{safe_role_id}'",
        "$format": "json",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/getRolesPermissions",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result
    return {"role_id": role_id, "permissions": result}


@mcp.tool()
@sf_tool("get_user_permissions")
def get_user_permissions(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get all permissions for a specific user across all their assigned roles.

    Useful for answering 'What can this user do?' by showing their complete permission set.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The user ID to look up permissions for
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for labels (default: en-US)
    """
    safe_user_id = sanitize_odata_string(user_id)
    params = {
        "locale": locale,
        "userId": f"'{safe_user_id}'",
        "$format": "json",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/getUserPermissions",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result
    return {"user_id": user_id, "permissions": result}


@mcp.tool()
@sf_tool("get_user_roles")
def get_user_roles(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_permissions: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get all RBP roles assigned to a specific user.

    This tool complements get_user_permissions by showing which roles
    are assigned to a user, not just the resulting permissions.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The user ID to look up roles for
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_permissions: If True, also fetches permissions for each role
    """
    # Step 1: Get user's permissions via getUserPermissions (valid function import)
    # This returns permission entries that include roleId, allowing us to derive assigned roles.
    safe_user_id = sanitize_odata_string(user_id)
    perm_params = {
        "locale": "en-US",
        "userId": f"'{safe_user_id}'",
        "$format": "json",
    }

    perm_result = make_odata_request(
        instance,
        "/odata/v2/getUserPermissions",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        perm_params,
        request_id,
    )

    if "error" in perm_result:
        return perm_result

    # Extract unique role IDs from permission entries
    role_ids_seen: set[str] = set()
    for entry in perm_result.get("d", {}).get("results", []):
        rid = entry.get("roleId")
        if rid:
            role_ids_seen.add(str(rid))

    if not role_ids_seen:
        return {"user_id": user_id, "roles": [], "role_count": 0}

    # Step 2: Fetch role details from RBPRole (valid entity)
    role_filter = " or ".join(f"roleId eq '{sanitize_odata_string(rid)}'" for rid in sorted(role_ids_seen))
    role_params = {
        "$filter": role_filter,
        "$select": "roleId,roleName,roleDesc,userType,lastModifiedDate",
        "$format": "json",
    }

    role_result = make_odata_request(
        instance,
        "/odata/v2/RBPRole",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        role_params,
        request_id,
        cache_category="permissions",
    )

    roles = []
    if "error" not in role_result:
        for entry in role_result.get("d", {}).get("results", []):
            roles.append(
                {
                    "roleId": entry.get("roleId"),
                    "roleName": entry.get("roleName"),
                    "roleDesc": entry.get("roleDesc"),
                    "userType": entry.get("userType"),
                }
            )
    else:
        # Fallback: return role IDs without details if RBPRole query fails
        roles = [{"roleId": rid, "roleName": None, "roleDesc": None, "userType": None} for rid in sorted(role_ids_seen)]

    # Step 3: Optionally fetch detailed permissions per role
    if include_permissions and roles:
        role_id_str = ",".join(str(r["roleId"]) for r in roles if r["roleId"])
        if role_id_str:
            detail_params = {
                "locale": "en-US",
                "roleIds": f"'{role_id_str}'",
                "$format": "json",
            }
            detail_result = make_odata_request(
                instance,
                "/odata/v2/getRolesPermissions",
                data_center,
                environment,
                auth_user_id,
                auth_password,
                detail_params,
                request_id,
            )
            if "error" not in detail_result:
                for role in roles:
                    role["permissions"] = detail_result

    return {"user_id": user_id, "roles": roles, "role_count": len(roles)}


@mcp.tool()
@sf_tool("get_permission_metadata")
def get_permission_metadata(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get the mapping of permission type labels for RBP security analysis.

    This metadata helps understand what permission categories exist in the system,
    mapping technical IDs to human-readable labels.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for labels (default: en-US)
    """
    params = {"locale": locale, "$format": "json"}
    result = make_odata_request(
        instance,
        "/odata/v2/getPermissionMetadata",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
        cache_category="permissions",
    )

    if "error" in result:
        return result
    return {"locale": locale, "metadata": result}


@mcp.tool()
@sf_tool("check_user_permission")
def check_user_permission(
    instance: str,
    user_id: str,
    permission_type: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Check if a specific user has a particular permission.

    Quickly verify whether a user has access to a specific feature or data.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The user ID to check
        permission_type: Permission type to check (e.g., "Employee Central Effective Dated Entities")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for labels (default: en-US)
    """
    safe_user_id = sanitize_odata_string(user_id)
    params = {
        "locale": locale,
        "userId": f"'{safe_user_id}'",
        "$format": "json",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/getUserPermissions",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    has_permission = False
    matching_permissions = []

    if "d" in result and "results" in result["d"]:
        for entry in result["d"]["results"]:
            ptype = entry.get("permissionType", "")
            if permission_type.lower() in ptype.lower():
                has_permission = True
                matching_permissions.append(entry)

    return {
        "user_id": user_id,
        "permission_type_searched": permission_type,
        "has_permission": has_permission,
        "matching_permissions": matching_permissions,
        "match_count": len(matching_permissions),
    }


@mcp.tool()
@sf_tool("get_dynamic_groups")
def get_dynamic_groups(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List all dynamic permission groups in the instance.

    Dynamic groups are used in RBP to define target populations.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        top: Maximum results (default: 100, max: 500)
    """
    params = {
        "$format": "json",
        "$top": str(top),
    }

    result = make_odata_request(
        instance,
        "/odata/v2/DynamicGroup",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    groups = result.get("d", {}).get("results", [])
    return {"groups": groups, "count": len(groups)}
