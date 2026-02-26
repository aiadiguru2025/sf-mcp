"""Integration & monitoring tools: alert notifications, scheduled jobs, IC jobs."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_alert_notifications", max_top=500)
def get_alert_notifications(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    status: str = "active",
    alert_id: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Retrieve system alert messages configured in Employee Central.

    Returns alert definitions including header, description, and status.
    These are the MDF-based AlertMessage objects used by EC business rules
    to trigger notifications for HR events (hires, terminations, etc.).

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        status: Filter by status: 'active', 'inactive', or 'all' (default: 'active')
        alert_id: Filter to a specific alert by externalCode (optional)
        top: Maximum results to return (default: 100, max: 500)
    """
    filters: list[str] = []

    if status != "all":
        status_val = "A" if status == "active" else "I"
        filters.append(f"effectiveStatus eq '{status_val}'")

    if alert_id:
        filters.append(
            f"externalCode eq '{sanitize_odata_string(alert_id)}'"
        )

    params: dict[str, str] = {
        "$select": (
            "externalCode,externalName,alertHeader,alertDescription,"
            "effectiveStatus,effectiveStartDate,effectiveEndDate,"
            "createdBy,createdDateTime,lastModifiedBy,"
            "lastModifiedDateTime"
        ),
        "$format": "json",
        "$top": str(top),
        "$orderby": "lastModifiedDateTime desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/AlertMessage",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    alerts = []
    for entry in result.get("d", {}).get("results", []):
        alerts.append({
            "alert_id": entry.get("externalCode"),
            "name": entry.get("externalName"),
            "header": entry.get("alertHeader"),
            "description": entry.get("alertDescription"),
            "status": (
                "active" if entry.get("effectiveStatus") == "A"
                else "inactive"
            ),
            "effective_start": entry.get("effectiveStartDate"),
            "effective_end": entry.get("effectiveEndDate"),
            "created_by": entry.get("createdBy"),
            "created_date": entry.get("createdDateTime"),
            "last_modified_by": entry.get("lastModifiedBy"),
            "last_modified": entry.get("lastModifiedDateTime"),
        })

    # Count by status
    status_counts: dict[str, int] = {}
    for a in alerts:
        s = a.get("status") or "unknown"
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "alerts": alerts,
        "count": len(alerts),
        "by_status": status_counts,
        "filters_applied": {
            "status": status,
            "alert_id": alert_id or None,
        },
    }


@mcp.tool()
@sf_tool("get_scheduled_job_status", max_top=500)
def get_scheduled_job_status(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    job_name: str = "",
    status: str = "all",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Monitor scheduled jobs and their last run status.

    Queries the TodoEntryV2 entity for system-generated items across all
    categories, providing visibility into pending system tasks, scheduled
    process notifications, and background job alerts.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        job_name: Filter by job/task name (substring match, optional)
        status: 'pending', 'completed', or 'all' (default: 'all')
        top: Maximum results to return (default: 100, max: 500)
    """
    # Exclude workflow categories (14, 17) already covered by
    # get_pending_approvals — focus on system/scheduled categories
    filters: list[str] = [
        "(categoryId ne '14' and categoryId ne '17')",
    ]

    if status == "pending":
        filters.append("status eq '2'")
    elif status == "completed":
        filters.append("status eq '3'")

    if job_name:
        safe_name = sanitize_odata_string(job_name)
        filters.append(
            f"substringof('{safe_name}', todoEntryName)"
        )

    params: dict[str, str] = {
        "$filter": " and ".join(filters),
        "$select": (
            "todoEntryId,todoEntryName,categoryId,categoryLabel,"
            "subjectId,status,completedDateTime,createdDate,dueDate,"
            "linkUrl"
        ),
        "$format": "json",
        "$top": str(top),
        "$orderby": "createdDate desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/TodoEntryV2",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    status_map = {"2": "pending", "3": "completed", "4": "overdue"}
    jobs: list[dict[str, Any]] = []
    category_counts: dict[str, int] = {}

    for entry in result.get("d", {}).get("results", []):
        cat_label = (
            entry.get("categoryLabel")
            or entry.get("categoryId")
            or "Unknown"
        )
        category_counts[cat_label] = category_counts.get(cat_label, 0) + 1

        raw_status = entry.get("status") or ""
        jobs.append({
            "entry_id": entry.get("todoEntryId"),
            "name": entry.get("todoEntryName"),
            "category_id": entry.get("categoryId"),
            "category_label": cat_label,
            "subject_id": entry.get("subjectId"),
            "status": status_map.get(raw_status, raw_status),
            "created_date": entry.get("createdDate"),
            "due_date": entry.get("dueDate"),
            "completed_date": entry.get("completedDateTime"),
            "link_url": entry.get("linkUrl"),
        })

    return {
        "jobs": jobs,
        "count": len(jobs),
        "by_category": category_counts,
        "filters_applied": {
            "job_name": job_name or None,
            "status": status,
        },
    }


@mcp.tool()
@sf_tool("get_integration_center_jobs", max_top=500)
def get_integration_center_jobs(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    job_name: str = "",
    status: str = "all",
    top: int = 50,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Check status of Integration Center and data replication jobs.

    Queries the OData Change Log entity to show recent data changes
    triggered by integrations, providing visibility into what data
    was modified, when, and by which process.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        job_name: Filter by entity/object name (optional)
        status: 'success', 'error', or 'all' (default: 'all')
        top: Maximum results to return (default: 50, max: 500)
    """
    filters: list[str] = []

    if job_name:
        safe_name = sanitize_odata_string(job_name)
        filters.append(f"objectType eq '{safe_name}'")

    if status == "success":
        filters.append("operationStatus eq 'success'")
    elif status == "error":
        filters.append("operationStatus eq 'error'")

    params: dict[str, str] = {
        "$select": (
            "changeLogId,objectType,objectId,operation,"
            "operationStatus,changedBy,changedDate,"
            "externalNameOfEntity"
        ),
        "$format": "json",
        "$top": str(top),
        "$orderby": "changedDate desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/MDFChangeLog",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    entries: list[dict[str, Any]] = []
    operation_counts: dict[str, int] = {}
    entity_counts: dict[str, int] = {}

    for entry in result.get("d", {}).get("results", []):
        op = entry.get("operation") or "unknown"
        operation_counts[op] = operation_counts.get(op, 0) + 1

        obj_type = entry.get("objectType") or "unknown"
        entity_counts[obj_type] = entity_counts.get(obj_type, 0) + 1

        entries.append({
            "change_log_id": entry.get("changeLogId"),
            "entity": obj_type,
            "entity_name": entry.get("externalNameOfEntity"),
            "object_id": entry.get("objectId"),
            "operation": op,
            "status": entry.get("operationStatus"),
            "changed_by": entry.get("changedBy"),
            "changed_date": entry.get("changedDate"),
        })

    return {
        "entries": entries,
        "count": len(entries),
        "by_operation": operation_counts,
        "by_entity": entity_counts,
        "filters_applied": {
            "job_name": job_name or None,
            "status": status,
        },
    }
