"""Time off tools: balances, upcoming time off, time off requests."""

from datetime import date
from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.tools.utils import display_name as _display_name
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_time_off_balances")
def get_time_off_balances(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    as_of_date: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Check vacation, PTO, and sick leave balances for one or more employees.

    Quickly answer 'How much PTO do I have?' for any employee. Supports
    checking multiple employees at once.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) - single ID or comma-separated (max 50)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        as_of_date: Check balance as of this date (YYYY-MM-DD). Defaults to today.
    """
    id_list = [uid.strip() for uid in user_ids.split(",")][:50]

    all_balances = []
    for uid in id_list:
        safe_uid = sanitize_odata_string(uid)
        params = {"$filter": f"userId eq '{safe_uid}'", "$format": "json", "$top": "100"}

        result = make_odata_request(
            instance,
            "/odata/v2/EmpTimeAccountBalance",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )

        if "error" in result:
            all_balances.append({"user_id": uid, "error": result.get("error")})
            continue

        balances = [
            {
                "account_type": e.get("timeAccountType") or e.get("timeAccount"),
                "balance": e.get("balance"),
                "as_of_date": e.get("asOfAccountingPeriodEnd") or as_of_date or str(date.today()),
            }
            for e in result.get("d", {}).get("results", [])
        ]

        all_balances.append({"user_id": uid, "balances": balances, "account_count": len(balances)})

    return {"employees": all_balances, "count": len(all_balances)}


@mcp.tool()
@sf_tool("get_upcoming_time_off", max_top=500)
def get_upcoming_time_off(
    instance: str,
    start_date: str,
    end_date: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    manager_id: str = "",
    status: str = "approved",
    top: int = 200,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    See who is out or taking time off in a date range (team absence calendar).

    Shows all approved (or pending) absences for a period. Filter by department
    or manager to see just your team.

    Args:
        instance: The SuccessFactors instance/company ID
        start_date: Start of date range (YYYY-MM-DD)
        end_date: End of date range (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department name or code
        manager_id: Filter to a specific manager's team
        status: Filter by approval status: 'approved', 'pending', or 'all' (default: 'approved')
        top: Maximum results (default: 200, max: 500)
    """
    filters = [
        f"startDate le datetime'{end_date}T23:59:59'",
        f"endDate ge datetime'{start_date}T00:00:00'",
    ]
    if status == "approved":
        filters.append("approvalStatus eq 'APPROVED'")
    elif status == "pending":
        filters.append("approvalStatus eq 'PENDING'")

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,startDate,endDate,timeType,approvalStatus,quantityInDays,quantityInHours",
        "$expand": "userIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "startDate asc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/EmployeeTime",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    absences = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userIdNav", {}) or {}
        emp_department = user_nav.get("department", "")
        emp_manager = user_nav.get("manager", "")

        if department and emp_department and department.lower() not in emp_department.lower():
            continue
        if manager_id and emp_manager and manager_id != emp_manager:
            continue

        absences.append(
            {
                "user_id": entry.get("userId"),
                "employee_name": _display_name(user_nav) if user_nav else entry.get("userId"),
                "department": emp_department,
                "start_date": entry.get("startDate"),
                "end_date": entry.get("endDate"),
                "time_type": entry.get("timeType"),
                "status": entry.get("approvalStatus"),
                "days": entry.get("quantityInDays"),
                "hours": entry.get("quantityInHours"),
            }
        )

    return {
        "date_range": {"start": start_date, "end": end_date},
        "absences": absences,
        "count": len(absences),
        "filters_applied": {"status": status, "department": department or None, "manager_id": manager_id or None},
    }


@mcp.tool()
@sf_tool("get_time_off_requests", max_top=200)
def get_time_off_requests(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    user_id: str = "",
    status: str = "pending",
    from_date: str = "",
    top: int = 50,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    View time-off requests for approval tracking.

    Shows pending, approved, or rejected time-off requests. Filter by employee
    or view all requests visible to you.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        user_id: Filter to a specific employee's requests (optional)
        status: Filter by status: 'pending', 'approved', 'rejected', 'cancelled', or 'all' (default: 'pending')
        from_date: Only show requests created on or after this date (YYYY-MM-DD)
        top: Maximum results (default: 50, max: 200)
    """
    filters = []

    if user_id:
        filters.append(f"userId eq '{sanitize_odata_string(user_id)}'")

    status_map = {"pending": "PENDING", "approved": "APPROVED", "rejected": "REJECTED", "cancelled": "CANCELLED"}
    if status != "all" and status in status_map:
        filters.append(f"approvalStatus eq '{status_map[status]}'")

    if from_date:
        filters.append(f"createdDate ge datetime'{from_date}T00:00:00'")

    params = {
        "$select": "userId,startDate,endDate,timeType,approvalStatus,quantityInDays,quantityInHours,createdDate",
        "$expand": "userIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "createdDate desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/EmployeeTime",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    requests_list = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userIdNav", {}) or {}
        requests_list.append(
            {
                "user_id": entry.get("userId"),
                "employee_name": _display_name(user_nav) if user_nav else entry.get("userId"),
                "start_date": entry.get("startDate"),
                "end_date": entry.get("endDate"),
                "time_type": entry.get("timeType"),
                "status": entry.get("approvalStatus"),
                "days": entry.get("quantityInDays"),
                "hours": entry.get("quantityInHours"),
                "submitted_date": entry.get("createdDate"),
            }
        )

    return {
        "requests": requests_list,
        "count": len(requests_list),
        "filters_applied": {"user_id": user_id or None, "status": status, "from_date": from_date or None},
    }
