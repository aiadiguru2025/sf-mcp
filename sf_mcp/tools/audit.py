"""Audit tools: role history, role assignment history, security & login audit."""

from datetime import date, timedelta
from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.tools.utils import display_name as _display_name
from sf_mcp.validation import sanitize_odata_string
from sf_mcp.xml_utils import parse_sap_date

# Default Segregation-of-Duty conflict pairs for RBP permission assignments.
# Each pair is (permission_a_substring, permission_b_substring); a user holding
# permissions matching both sides of a pair is flagged as a potential conflict.
_DEFAULT_SOD_PAIRS: list[tuple[str, str]] = [
    ("Manage Permission Roles", "Manage User"),
    ("Manage Permission Roles", "Manage Password & Login Policy"),
    ("Manage Permission Roles", "Manage Integration Tools"),
    ("Manage Data", "Approve Workflow"),
    ("Employee Central Effective Dated Entities", "Approve Compensation"),
]


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


@mcp.tool()
@sf_tool("get_login_audit_log", max_top=500)
def get_login_audit_log(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    user_id: str = "",
    from_date: str = "",
    to_date: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get login audit events: who logged in, when, and from where.

    Requires the instance's Audit Trail / Login Tracking feature to be
    provisioned; not every tenant exposes this entity.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        user_id: Optional user ID to filter to a single user's login history
        from_date: Optional start date filter (YYYY-MM-DD)
        to_date: Optional end date filter (YYYY-MM-DD)
        top: Maximum records to return (default 100, max 500)
    """
    filters = []
    if user_id:
        filters.append(f"userId eq '{sanitize_odata_string(user_id)}'")
    if from_date:
        filters.append(f"loginTime ge datetime'{from_date}T00:00:00'")
    if to_date:
        filters.append(f"loginTime le datetime'{to_date}T23:59:59'")

    params = {
        "$select": "userId,loginTime,ipAddress,loginStatus,userAgent",
        "$format": "json",
        "$top": str(top),
        "$orderby": "loginTime desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/LoginAudit",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    events = [
        {
            "user_id": e.get("userId"),
            "login_time": parse_sap_date(e.get("loginTime", "")),
            "ip_address": e.get("ipAddress"),
            "status": e.get("loginStatus"),
            "user_agent": e.get("userAgent"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "events": events,
        "count": len(events),
        "filters_applied": {"user_id": user_id or None, "from_date": from_date or None, "to_date": to_date or None},
    }


@mcp.tool()
@sf_tool("get_admin_audit_log", max_top=500)
def get_admin_audit_log(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    entity_name: str = "",
    changed_by: str = "",
    from_date: str = "",
    to_date: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Track admin-level configuration changes: who changed what, and when.

    Covers config/data changes captured by the instance's Audit Trail feature
    (RBP roles, MDF objects, user records, etc). Requires Audit Trail to be
    provisioned; not every tenant exposes this entity.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        entity_name: Optional entity/object name to filter (e.g., 'RBPRole', 'User')
        changed_by: Optional user ID of the admin who made the change
        from_date: Optional start date filter (YYYY-MM-DD)
        to_date: Optional end date filter (YYYY-MM-DD)
        top: Maximum records to return (default 100, max 500)
    """
    filters = []
    if entity_name:
        filters.append(f"entityName eq '{sanitize_odata_string(entity_name)}'")
    if changed_by:
        filters.append(f"changedBy eq '{sanitize_odata_string(changed_by)}'")
    if from_date:
        filters.append(f"changedDate ge datetime'{from_date}T00:00:00'")
    if to_date:
        filters.append(f"changedDate le datetime'{to_date}T23:59:59'")

    params = {
        "$select": "entityName,recordId,fieldName,oldValue,newValue,changedBy,changedDate",
        "$format": "json",
        "$top": str(top),
        "$orderby": "changedDate desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/AuditLog",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    changes = [
        {
            "entity_name": e.get("entityName"),
            "record_id": e.get("recordId"),
            "field_name": e.get("fieldName"),
            "old_value": e.get("oldValue"),
            "new_value": e.get("newValue"),
            "changed_by": e.get("changedBy"),
            "changed_date": parse_sap_date(e.get("changedDate", "")),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "changes": changes,
        "count": len(changes),
        "filters_applied": {
            "entity_name": entity_name or None,
            "changed_by": changed_by or None,
            "from_date": from_date or None,
            "to_date": to_date or None,
        },
    }


@mcp.tool()
@sf_tool("get_sod_violations")
def get_sod_violations(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    permission_pairs: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Detect Segregation-of-Duty conflicts across a user's RBP permission assignments.

    Flags users who hold both sides of a conflicting permission pair (e.g. someone
    who can both manage RBP roles and manage users, letting them self-grant access).
    Uses a built-in list of common conflicts unless permission_pairs is provided.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) to check - single ID or comma-separated (max 20)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        permission_pairs: Optional custom conflict pairs, format
            "PermA|PermB,PermC|PermD" (substring match, case-insensitive).
            Defaults to a built-in list of common RBP admin conflicts.
    """
    if permission_pairs:
        pairs: list[tuple[str, str]] = []
        for raw_pair in permission_pairs.split(","):
            parts = raw_pair.split("|")
            if len(parts) == 2:
                pairs.append((parts[0].strip(), parts[1].strip()))
    else:
        pairs = _DEFAULT_SOD_PAIRS

    id_list = [uid.strip() for uid in user_ids.split(",")][:20]

    results = []
    for uid in id_list:
        safe_uid = sanitize_odata_string(uid)
        params = {"locale": "en-US", "userId": f"'{safe_uid}'", "$format": "json"}

        perm_result = make_odata_request(
            instance,
            "/odata/v2/getUserPermissions",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )

        if "error" in perm_result:
            results.append({"user_id": uid, "error": perm_result.get("error")})
            continue

        permission_types = [
            entry.get("permissionType", "") for entry in perm_result.get("d", {}).get("results", [])
        ]
        permission_types_lower = [p.lower() for p in permission_types if p]

        violations = []
        for perm_a, perm_b in pairs:
            a_match = next((p for p in permission_types if perm_a.lower() in p.lower()), None)
            b_match = next((p for p in permission_types if perm_b.lower() in p.lower()), None)
            if a_match and b_match:
                violations.append(
                    {"permission_a": a_match, "permission_b": b_match, "conflict_rule": f"{perm_a} + {perm_b}"}
                )

        results.append(
            {
                "user_id": uid,
                "permission_count": len(permission_types_lower),
                "violations": violations,
                "has_violations": len(violations) > 0,
            }
        )

    total_violations = sum(len(r.get("violations", [])) for r in results)

    return {
        "employees": results,
        "count": len(results),
        "users_with_violations": sum(1 for r in results if r.get("has_violations")),
        "total_violations": total_violations,
        "conflict_rules_checked": len(pairs),
    }


@mcp.tool()
@sf_tool("get_dormant_users", max_top=500)
def get_dormant_users(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    dormant_days: int = 90,
    department: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Find active user accounts with no login activity in the last N days.

    Cross-references active employees against the login audit log. Requires
    the instance's Audit Trail / Login Tracking feature to be provisioned.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        dormant_days: Flag users with no login in this many days (default: 90)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    user_filters = ["(status eq 'active' or status eq 't')"]
    if department:
        user_filters.append(f"department eq '{sanitize_odata_string(department)}'")

    user_params = {
        "$filter": " and ".join(user_filters),
        "$select": "userId,firstName,lastName,displayName,department,hireDate",
        "$format": "json",
        "$top": "1000",
    }

    user_result = make_odata_request(
        instance,
        "/odata/v2/User",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        user_params,
        request_id,
    )

    if "error" in user_result:
        return user_result

    users = user_result.get("d", {}).get("results", [])
    cutoff = (date.today() - timedelta(days=dormant_days)).isoformat()

    login_params = {
        "$filter": f"loginTime ge datetime'{cutoff}T00:00:00'",
        "$select": "userId,loginTime",
        "$format": "json",
        "$top": "1000",
        "$orderby": "loginTime desc",
    }

    login_result = make_odata_request(
        instance,
        "/odata/v2/LoginAudit",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        login_params,
        request_id,
    )

    if "error" in login_result:
        return login_result

    recently_active = {e.get("userId") for e in login_result.get("d", {}).get("results", []) if e.get("userId")}

    dormant = [
        {
            "user_id": u.get("userId"),
            "display_name": _display_name(u),
            "department": u.get("department"),
            "hire_date": u.get("hireDate"),
        }
        for u in users
        if u.get("userId") not in recently_active
    ]

    total_active_users = len(users)
    dormant = dormant[:top]

    return {
        "dormant_users": dormant,
        "count": len(dormant),
        "total_active_users_checked": total_active_users,
        "dormant_days_threshold": dormant_days,
        "filters_applied": {"department": department or None},
    }
