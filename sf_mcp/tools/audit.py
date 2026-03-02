"""Audit tools: role history, role assignment history."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string
from sf_mcp.xml_utils import parse_sap_date


def _build_date_range_filter(field_name: str, from_date: str | None, to_date: str | None) -> list[str]:
    """Build OData date range filter clauses."""
    filters = []
    if from_date:
        filters.append(f"{field_name} ge datetime'{from_date}T00:00:00'")
    if to_date:
        filters.append(f"{field_name} le datetime'{to_date}T23:59:59'")
    return filters


@mcp.tool()
@sf_tool("get_role_history", max_top=500)
def get_role_history(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    role_id: str | None = None,
    role_name: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get modification history for RBP roles.

    Returns who modified the role, when, and what changes were made.
    This helps audit role configuration changes over time.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        role_id: Optional role ID to filter (e.g., "10")
        role_name: Optional role name to filter (alternative to role_id)
        from_date: Optional start date filter (ISO format: YYYY-MM-DD)
        to_date: Optional end date filter (ISO format: YYYY-MM-DD)
        top: Maximum records to return (default 100, max 500)
    """
    filters = []
    if role_id:
        filters.append(f"roleId eq {sanitize_odata_string(role_id)}")
    if role_name:
        filters.append(f"roleName eq '{sanitize_odata_string(role_name)}'")
    filters.extend(_build_date_range_filter("lastModifiedDate", from_date, to_date))

    params = {
        "$select": "roleId,roleName,roleDesc,userType,lastModifiedBy,lastModifiedDate,createdBy,createdDate",
        "$orderby": "lastModifiedDate desc",
        "$top": str(top),
        "$format": "json",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/RBPRole",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    history = []
    for entry in result.get("d", {}).get("results", []):
        history.append(
            {
                "role_id": entry.get("roleId"),
                "role_name": entry.get("roleName"),
                "role_description": entry.get("roleDesc"),
                "user_type": entry.get("userType"),
                "last_modified_by": entry.get("lastModifiedBy"),
                "last_modified_date": parse_sap_date(entry.get("lastModifiedDate", "")),
                "created_by": entry.get("createdBy"),
                "created_date": parse_sap_date(entry.get("createdDate", "")),
            }
        )

    return {
        "filters_applied": {"role_id": role_id, "role_name": role_name, "from_date": from_date, "to_date": to_date},
        "history": history,
        "count": len(history),
    }


@mcp.tool()
@sf_tool("get_role_assignment_history", max_top=500)
def get_role_assignment_history(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    role_id: str | None = None,
    user_id: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get role assignments for users, showing which roles are assigned.

    When user_id is provided, shows all roles assigned to that user via
    getUserPermissions. When role_id is provided, shows role details and
    modification history from RBPRole. At least one filter is required.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        role_id: Optional role ID to filter assignments for a specific role
        user_id: Optional user ID to filter assignments for a specific user
        from_date: Optional start date filter (ISO format: YYYY-MM-DD, applied to role modification date)
        to_date: Optional end date filter (ISO format: YYYY-MM-DD, applied to role modification date)
        top: Maximum records to return (default 100, max 500)
    """
    if not role_id and not user_id:
        return {
            "error": "At least one of role_id or user_id is required",
            "message": "Provide a role ID to see role history, or a user ID to see their role assignments.",
        }

    # Step 1: If user_id provided, get their role assignments via getUserPermissions
    user_role_ids: set[str] = set()
    if user_id:
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

        for entry in perm_result.get("d", {}).get("results", []):
            rid = entry.get("roleId")
            if rid:
                user_role_ids.add(str(rid))

        if not user_role_ids:
            return {
                "user_id": user_id,
                "filters_applied": {"role_id": role_id, "user_id": user_id, "from_date": from_date, "to_date": to_date},
                "assignments": [],
                "count": 0,
            }

    # Step 2: Fetch role details from RBPRole
    role_filters = []
    if role_id:
        role_filters.append(f"roleId eq {sanitize_odata_string(role_id)}")
    if user_role_ids:
        if role_id:
            # Intersect: only show the specific role if user has it
            if role_id not in user_role_ids:
                return {
                    "user_id": user_id,
                    "filters_applied": {
                        "role_id": role_id, "user_id": user_id,
                        "from_date": from_date, "to_date": to_date,
                    },
                    "assignments": [],
                    "count": 0,
                    "message": f"User '{user_id}' does not have role '{role_id}'",
                }
        else:
            id_clauses = " or ".join(f"roleId eq {sanitize_odata_string(rid)}" for rid in sorted(user_role_ids))
            role_filters.append(f"({id_clauses})")

    role_filters.extend(_build_date_range_filter("lastModifiedDate", from_date, to_date))

    params = {
        "$select": "roleId,roleName,roleDesc,userType,lastModifiedBy,lastModifiedDate,createdBy,createdDate",
        "$orderby": "lastModifiedDate desc",
        "$top": str(top),
        "$format": "json",
    }
    if role_filters:
        params["$filter"] = " and ".join(role_filters)

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

    assignments = []
    for entry in result.get("d", {}).get("results", []):
        assignments.append(
            {
                "user_id": user_id,
                "role_id": entry.get("roleId"),
                "role_name": entry.get("roleName"),
                "role_description": entry.get("roleDesc"),
                "user_type": entry.get("userType"),
                "created_by": entry.get("createdBy"),
                "created_date": parse_sap_date(entry.get("createdDate", "")),
                "last_modified_by": entry.get("lastModifiedBy"),
                "last_modified_date": parse_sap_date(entry.get("lastModifiedDate", "")),
            }
        )

    return {
        "filters_applied": {"role_id": role_id, "user_id": user_id, "from_date": from_date, "to_date": to_date},
        "assignments": assignments,
        "count": len(assignments),
    }
