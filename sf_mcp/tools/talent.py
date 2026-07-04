"""Performance & Talent tools: goals, development plans, talent flags, succession."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string

# Succession Data Model field IDs vary per instance; these are the field names
# SuccessFactors ships in its out-of-box Succession Data Model template.
_TALENT_FLAG_FIELDS = ["potential", "performanceRating", "riskOfLoss", "impactOfLoss", "keyPosition", "futureLeader"]


@mcp.tool()
@sf_tool("get_goal_summary", max_top=200)
def get_goal_summary(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    status: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get an employee's goals from the Goal Management module.

    Shows goal name, category, weight, and completion percentage. Requires
    the Goal Management module to be enabled on the instance.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        status: Filter by goal state: 'not_started', 'in_progress', 'completed', or '' for all
        top: Maximum results (default: 100, max: 200)
    """
    safe_user_id = sanitize_odata_string(user_id)
    filters = [f"userId eq '{safe_user_id}'"]

    status_map = {"not_started": "1", "in_progress": "2", "completed": "3"}
    if status and status in status_map:
        filters.append(f"state eq {status_map[status]}")

    params = {
        "$filter": " and ".join(filters),
        "$select": "objId,name,category,state,startDate,dueDate,weight,metricsGoalPct,planId,lastModifiedDate",
        "$format": "json",
        "$top": str(top),
        "$orderby": "dueDate asc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/Goal",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    state_labels = {"1": "Not Started", "2": "In Progress", "3": "Completed"}
    goals = []
    state_counts: dict[str, int] = {}
    weighted_completion = 0.0
    total_weight = 0.0

    for entry in result.get("d", {}).get("results", []):
        state_label = state_labels.get(str(entry.get("state", "")), entry.get("state"))
        state_counts[state_label] = state_counts.get(state_label, 0) + 1

        weight = entry.get("weight") or 0
        completion = entry.get("metricsGoalPct") or 0
        try:
            weighted_completion += float(weight) * float(completion)
            total_weight += float(weight)
        except (TypeError, ValueError):
            pass

        goals.append(
            {
                "goal_id": entry.get("objId"),
                "name": entry.get("name"),
                "category": entry.get("category"),
                "state": state_label,
                "start_date": entry.get("startDate"),
                "due_date": entry.get("dueDate"),
                "weight": weight,
                "completion_percent": completion,
                "plan_id": entry.get("planId"),
                "last_modified": entry.get("lastModifiedDate"),
            }
        )

    overall_completion = round(weighted_completion / total_weight, 1) if total_weight else None

    return {
        "user_id": user_id,
        "goals": goals,
        "count": len(goals),
        "by_state": state_counts,
        "overall_weighted_completion_percent": overall_completion,
        "filters_applied": {"status": status or "all"},
    }


@mcp.tool()
@sf_tool("get_development_plans", max_top=200)
def get_development_plans(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    status: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get an employee's development goals and learning activities.

    Shows development goal name, category, target date, and completion state.
    Requires the Development Goal Plan module to be enabled on the instance.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        status: Filter by state: 'not_started', 'in_progress', 'completed', or '' for all
        top: Maximum results (default: 100, max: 200)
    """
    safe_user_id = sanitize_odata_string(user_id)
    filters = [f"userId eq '{safe_user_id}'"]

    status_map = {"not_started": "1", "in_progress": "2", "completed": "3"}
    if status and status in status_map:
        filters.append(f"state eq {status_map[status]}")

    params = {
        "$filter": " and ".join(filters),
        "$select": "id,name,category,state,startDate,dueDate,description,planId,lastModifiedDate",
        "$format": "json",
        "$top": str(top),
        "$orderby": "dueDate asc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/DevGoal",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    state_labels = {"1": "Not Started", "2": "In Progress", "3": "Completed"}
    plans = []
    state_counts: dict[str, int] = {}

    for entry in result.get("d", {}).get("results", []):
        state_label = state_labels.get(str(entry.get("state", "")), entry.get("state"))
        state_counts[state_label] = state_counts.get(state_label, 0) + 1
        plans.append(
            {
                "goal_id": entry.get("id"),
                "name": entry.get("name"),
                "category": entry.get("category"),
                "state": state_label,
                "start_date": entry.get("startDate"),
                "due_date": entry.get("dueDate"),
                "description": entry.get("description"),
                "plan_id": entry.get("planId"),
                "last_modified": entry.get("lastModifiedDate"),
            }
        )

    return {
        "user_id": user_id,
        "development_goals": plans,
        "count": len(plans),
        "by_state": state_counts,
        "filters_applied": {"status": status or "all"},
    }


@mcp.tool()
@sf_tool("get_talent_flags")
def get_talent_flags(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get talent profile flags for employees: potential, flight risk, impact of
    loss, and key position indicators.

    These fields come from the instance's Succession Data Model and their
    availability depends on how that model is configured. Field names shown
    are SuccessFactors' out-of-box defaults and may not match a customized model.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) - single ID or comma-separated (max 20)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
    """
    id_list = [uid.strip() for uid in user_ids.split(",")][:20]
    select_fields = "userId,startDate," + ",".join(_TALENT_FLAG_FIELDS)

    all_flags = []
    for uid in id_list:
        safe_uid = sanitize_odata_string(uid)
        params = {
            "$filter": f"userId eq '{safe_uid}'",
            "$select": select_fields,
            "$format": "json",
            "$top": "1",
            "$orderby": "startDate desc",
        }

        result = make_odata_request(
            instance,
            "/odata/v2/EmpJob",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )

        if "error" in result:
            all_flags.append({"user_id": uid, "error": result.get("error")})
            continue

        records = result.get("d", {}).get("results", [])
        if not records:
            all_flags.append({"user_id": uid, "flags": None, "message": "No job record found"})
            continue

        record = records[0]
        all_flags.append(
            {
                "user_id": uid,
                "flags": {field: record.get(field) for field in _TALENT_FLAG_FIELDS},
                "as_of_date": record.get("startDate"),
            }
        )

    return {"employees": all_flags, "count": len(all_flags)}


@mcp.tool()
@sf_tool("get_succession_nominees", max_top=200)
def get_succession_nominees(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    pool_id: str = "",
    user_id: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List succession nominees for talent pools (key position backups).

    Requires the Succession Management / Talent Pools module. Provide either
    a pool_id to see all nominees for a pool, or a user_id to see which pools
    an employee has been nominated to.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        pool_id: Optional talent pool ID to filter nominees for a specific pool
        user_id: Optional employee user ID to filter pools they're nominated to
        top: Maximum results (default: 100, max: 200)
    """
    filters = []
    if pool_id:
        filters.append(f"poolId eq '{sanitize_odata_string(pool_id)}'")
    if user_id:
        filters.append(f"userId eq '{sanitize_odata_string(user_id)}'")

    params = {
        "$select": "poolId,userId,nominationStatus,readinessLevel,nominationDate,lastModifiedDate",
        "$format": "json",
        "$top": str(top),
        "$orderby": "nominationDate desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/TalentPoolUser",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    nominees = [
        {
            "pool_id": e.get("poolId"),
            "user_id": e.get("userId"),
            "nomination_status": e.get("nominationStatus"),
            "readiness_level": e.get("readinessLevel"),
            "nomination_date": e.get("nominationDate"),
            "last_modified": e.get("lastModifiedDate"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "nominees": nominees,
        "count": len(nominees),
        "filters_applied": {"pool_id": pool_id or None, "user_id": user_id or None},
    }
