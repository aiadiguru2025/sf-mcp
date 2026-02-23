"""Recruiting tools: requisitions, candidates, new hires."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


def _display_name(entry: dict) -> str:
    return entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip()


@mcp.tool()
@sf_tool("get_open_requisitions", max_top=500)
def get_open_requisitions(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    hiring_manager_id: str = "",
    location: str = "",
    status: str = "open",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List job requisitions with status and hiring manager.

    Shows open (or all) job requisitions for tracking the hiring pipeline.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        hiring_manager_id: Filter by hiring manager's user ID
        location: Filter by work location
        status: Requisition status: 'open', 'filled', 'closed', or 'all' (default: 'open')
        top: Maximum results (default: 100, max: 500)
    """
    filters = []

    status_map = {"open": "Open", "filled": "Filled", "closed": "Closed"}
    if status != "all" and status in status_map:
        filters.append(f"status eq '{sanitize_odata_string(status_map[status])}'")
    if department:
        filters.append(f"department eq '{sanitize_odata_string(department)}'")
    if hiring_manager_id:
        filters.append(f"hiringManagerId eq '{sanitize_odata_string(hiring_manager_id)}'")
    if location:
        filters.append(f"location eq '{sanitize_odata_string(location)}'")

    params = {
        "$select": (
            "jobReqId,jobTitle,department,location,status,numberOpenings,"
            "hiringManagerId,recruiterName,createdDateTime,lastModifiedDateTime"
        ),
        "$format": "json",
        "$top": str(top),
        "$orderby": "createdDateTime desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/JobRequisition",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    requisitions = [
        {
            "requisition_id": e.get("jobReqId"),
            "job_title": e.get("jobTitle"),
            "department": e.get("department"),
            "location": e.get("location"),
            "status": e.get("status"),
            "openings": e.get("numberOpenings"),
            "hiring_manager_id": e.get("hiringManagerId"),
            "recruiter": e.get("recruiterName"),
            "created_date": e.get("createdDateTime"),
            "last_modified": e.get("lastModifiedDateTime"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "requisitions": requisitions,
        "count": len(requisitions),
        "filters_applied": {
            "status": status,
            "department": department or None,
            "hiring_manager_id": hiring_manager_id or None,
            "location": location or None,
        },
    }


@mcp.tool()
@sf_tool("get_candidate_pipeline", max_top=500)
def get_candidate_pipeline(
    instance: str,
    requisition_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_rejected: bool = False,
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Track candidates for a job requisition through hiring stages.

    Shows all applicants for a specific job requisition with their current
    stage, application date, and status.

    Args:
        instance: The SuccessFactors instance/company ID
        requisition_id: The job requisition ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_rejected: If True, include rejected candidates (default: False)
        top: Maximum results (default: 100, max: 500)
    """
    safe_req_id = sanitize_odata_string(requisition_id)
    filter_expr = f"jobReqId eq '{safe_req_id}'"
    if not include_rejected:
        filter_expr += " and statusId ne 3"

    params = {
        "$filter": filter_expr,
        "$select": "applicationId,candidateId,jobReqId,statusId,applicationDate,lastModifiedDateTime",
        "$expand": "candidateNav,statusNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "lastModifiedDateTime desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/JobApplication",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    candidates = []
    stage_counts = {}
    for entry in result.get("d", {}).get("results", []):
        candidate_nav = entry.get("candidateNav", {}) or {}
        status_nav = entry.get("statusNav", {}) or {}
        stage = status_nav.get("label") or status_nav.get("appStatusName") or str(entry.get("statusId", "Unknown"))

        stage_counts[stage] = stage_counts.get(stage, 0) + 1

        candidates.append(
            {
                "application_id": entry.get("applicationId"),
                "candidate_id": entry.get("candidateId"),
                "candidate_name": (
                    f"{candidate_nav.get('firstName', '')} {candidate_nav.get('lastName', '')}".strip()
                    if candidate_nav
                    else "Unknown"
                ),
                "email": candidate_nav.get("email") if candidate_nav else None,
                "current_stage": stage,
                "application_date": entry.get("applicationDate"),
                "last_updated": entry.get("lastModifiedDateTime"),
            }
        )

    return {
        "requisition_id": requisition_id,
        "candidates": candidates,
        "count": len(candidates),
        "by_stage": stage_counts,
    }


@mcp.tool()
@sf_tool("get_new_hires", max_top=500)
def get_new_hires(
    instance: str,
    start_date_from: str,
    start_date_to: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List recent and upcoming new hires for onboarding planning.

    Shows employees hired within a date range with their job details.

    Args:
        instance: The SuccessFactors instance/company ID
        start_date_from: Show hires starting on or after this date (YYYY-MM-DD)
        start_date_to: Show hires starting on or before this date (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    filters = [
        f"hireDate ge datetime'{start_date_from}T00:00:00'",
        f"hireDate le datetime'{start_date_to}T23:59:59'",
    ]
    if department:
        filters.append(f"department eq '{sanitize_odata_string(department)}'")

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,division,location,manager",
        "$format": "json",
        "$top": str(top),
        "$orderby": "hireDate asc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/User",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    new_hires = [
        {
            "user_id": e.get("userId"),
            "display_name": _display_name(e),
            "email": e.get("email"),
            "hire_date": e.get("hireDate"),
            "title": e.get("title"),
            "department": e.get("department"),
            "division": e.get("division"),
            "location": e.get("location"),
            "manager_id": e.get("manager"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "new_hires": new_hires,
        "count": len(new_hires),
        "date_range": {"from": start_date_from, "to": start_date_to},
        "filters_applied": {"department": department or None},
    }
