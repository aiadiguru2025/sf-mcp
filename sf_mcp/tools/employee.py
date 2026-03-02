"""Employee tools: profile, search, history, team roster."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.tools.utils import display_name as _display_name
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_employee_profile")
def get_employee_profile(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_compensation: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get a complete employee profile including job info, contact details, and manager.

    Returns the employee's current job title, department, location, manager,
    email, phone, and hire date in a single call. Optionally includes compensation.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID (e.g., 'jsmith')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_compensation: If True, also fetches current compensation details
    """
    safe_user_id = sanitize_odata_string(user_id)

    params = {
        "$filter": f"userId eq '{safe_user_id}'",
        "$select": (
            "userId,username,firstName,lastName,displayName,email,hireDate,"
            "status,hr,manager,department,division,location,title"
        ),
        "$expand": "manager,hr",
        "$format": "json",
        "$top": "1",
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

    users = result.get("d", {}).get("results", [])
    if not users:
        return {"error": f"Employee '{user_id}' not found", "message": "Check the user ID and try again."}

    user = users[0]

    profile = {
        "user_id": user.get("userId"),
        "display_name": _display_name(user),
        "first_name": user.get("firstName"),
        "last_name": user.get("lastName"),
        "email": user.get("email"),
        "hire_date": user.get("hireDate"),
        "status": user.get("status"),
        "title": user.get("title"),
        "department": user.get("department"),
        "division": user.get("division"),
        "location": user.get("location"),
    }

    # Extract manager info
    manager_data = user.get("manager", {})
    if isinstance(manager_data, dict) and "results" in manager_data:
        mgrs = manager_data["results"]
        if mgrs:
            mgr = mgrs[0]
            profile["manager"] = {"user_id": mgr.get("userId"), "name": _display_name(mgr)}
    elif isinstance(manager_data, dict) and manager_data.get("userId"):
        profile["manager"] = {"user_id": manager_data.get("userId"), "name": _display_name(manager_data)}

    # Extract HR info
    hr_data = user.get("hr", {})
    if isinstance(hr_data, dict) and hr_data.get("userId"):
        profile["hr_rep"] = {"user_id": hr_data.get("userId"), "name": _display_name(hr_data)}

    if include_compensation:
        comp_params = {
            "$filter": f"userId eq '{safe_user_id}'",
            "$select": "userId,startDate,payGroup,payGrade,compensatedHours",
            "$expand": "empPayCompRecurringNav",
            "$format": "json",
            "$top": "5",
            "$orderby": "startDate desc",
        }
        comp_result = make_odata_request(
            instance,
            "/odata/v2/EmpCompensation",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            comp_params,
            request_id,
        )
        if "error" not in comp_result:
            comp_records = comp_result.get("d", {}).get("results", [])
            if comp_records:
                latest = comp_records[0]
                comp_info = {
                    "pay_group": latest.get("payGroup"),
                    "pay_grade": latest.get("payGrade"),
                    "effective_date": latest.get("startDate"),
                }
                recurring = latest.get("empPayCompRecurringNav", {})
                if isinstance(recurring, dict) and "results" in recurring:
                    comp_info["pay_components"] = [
                        {
                            "pay_component": r.get("payComponent"),
                            "amount": r.get("paycompvalue"),
                            "currency": r.get("currencyCode"),
                            "frequency": r.get("frequency"),
                        }
                        for r in recurring["results"]
                    ]
                profile["compensation"] = comp_info

    return {"profile": profile}


@mcp.tool()
@sf_tool("search_employees", max_top=200)
def search_employees(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    search_text: str = "",
    department: str = "",
    location: str = "",
    manager_id: str = "",
    status: str = "active",
    top: int = 50,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Search for employees by name, department, location, or manager.

    Find employees without knowing their exact user IDs. Supports partial name
    matching and filtering by department, location, or manager.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        search_text: Partial name to search (searches first name and last name)
        department: Filter by department name or code
        location: Filter by work location
        manager_id: Filter to show only this manager's direct reports
        status: Employee status filter: 'active', 'inactive', or 'all' (default: 'active')
        top: Maximum number of results to return (default: 50, max: 200)
    """
    filters = []

    if search_text:
        safe_text = sanitize_odata_string(search_text)
        filters.append(
            f"(substringof('{safe_text}',firstName) or "
            f"substringof('{safe_text}',lastName) or "
            f"substringof('{safe_text}',displayName))"
        )
    if department:
        filters.append(f"department eq '{sanitize_odata_string(department)}'")
    if location:
        filters.append(f"location eq '{sanitize_odata_string(location)}'")
    if manager_id:
        filters.append(f"manager eq '{sanitize_odata_string(manager_id)}'")
    if status == "active":
        filters.append("(status eq 'active' or status eq 't')")
    elif status == "inactive":
        filters.append("(status eq 'inactive' or status eq 'f')")

    params = {
        "$select": (
            "userId,firstName,lastName,displayName,email,hireDate,status,title,department,division,location,manager"
        ),
        "$format": "json",
        "$top": str(top),
    }
    if filters:
        params["$filter"] = " and ".join(filters)

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

    employees = [
        {
            "user_id": e.get("userId"),
            "display_name": _display_name(e),
            "email": e.get("email"),
            "title": e.get("title"),
            "department": e.get("department"),
            "division": e.get("division"),
            "location": e.get("location"),
            "hire_date": e.get("hireDate"),
            "status": e.get("status"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    return {
        "employees": employees,
        "count": len(employees),
        "search_criteria": {
            "search_text": search_text or None,
            "department": department or None,
            "location": location or None,
            "manager_id": manager_id or None,
            "status": status,
        },
    }


@mcp.tool()
@sf_tool("get_employee_history")
def get_employee_history(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_compensation_changes: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    View an employee's job history including promotions, transfers, and title changes.

    Shows chronological job records with title, department, location, and manager
    for each period. Useful for reviewing career progression.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_compensation_changes: If True, also fetches salary history
    """
    safe_user_id = sanitize_odata_string(user_id)

    params = {
        "$filter": f"userId eq '{safe_user_id}'",
        "$select": (
            "userId,startDate,endDate,jobTitle,department,location,"
            "position,managerId,employeeClass,eventReason,emplStatus"
        ),
        "$orderby": "startDate desc",
        "$format": "json",
        "$top": "100",
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
        return result

    history = [
        {
            "start_date": e.get("startDate"),
            "end_date": e.get("endDate"),
            "job_title": e.get("jobTitle"),
            "department": e.get("department"),
            "location": e.get("location"),
            "position": e.get("position"),
            "manager_id": e.get("managerId"),
            "employee_class": e.get("employeeClass"),
            "event_reason": e.get("eventReason"),
            "employment_status": e.get("emplStatus"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    response_data = {"user_id": user_id, "job_history": history, "record_count": len(history)}

    if include_compensation_changes:
        comp_params = {
            "$filter": f"userId eq '{safe_user_id}'",
            "$select": "userId,startDate,payGroup,payGrade",
            "$expand": "empPayCompRecurringNav",
            "$orderby": "startDate desc",
            "$format": "json",
            "$top": "50",
        }
        comp_result = make_odata_request(
            instance,
            "/odata/v2/EmpCompensation",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            comp_params,
            request_id,
        )
        if "error" not in comp_result:
            comp_history = []
            for entry in comp_result.get("d", {}).get("results", []):
                comp_record = {
                    "effective_date": entry.get("startDate"),
                    "pay_group": entry.get("payGroup"),
                    "pay_grade": entry.get("payGrade"),
                }
                recurring = entry.get("empPayCompRecurringNav", {})
                if isinstance(recurring, dict) and "results" in recurring:
                    comp_record["pay_components"] = [
                        {
                            "pay_component": r.get("payComponent"),
                            "amount": r.get("paycompvalue"),
                            "currency": r.get("currencyCode"),
                            "frequency": r.get("frequency"),
                        }
                        for r in recurring["results"]
                    ]
                comp_history.append(comp_record)
            response_data["compensation_history"] = comp_history

    return response_data


@mcp.tool()
@sf_tool("get_team_roster", max_top=200)
def get_team_roster(
    instance: str,
    manager_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_indirect_reports: bool = False,
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get a manager's team roster with direct (and optionally indirect) reports.

    Shows all active team members with their job title, department, location,
    and hire date. Useful for org chart views, team planning, and 1-on-1 prep.

    Args:
        instance: The SuccessFactors instance/company ID
        manager_id: The manager's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_indirect_reports: If True, also fetches reports-of-reports (1 level deep)
        top: Maximum direct reports to return (default: 100, max: 200)
    """
    safe_mgr = sanitize_odata_string(manager_id)

    params = {
        "$filter": f"manager eq '{safe_mgr}' and (status eq 'active' or status eq 't')",
        "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,division,location",
        "$format": "json",
        "$top": str(top),
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

    direct_reports = [
        {
            "user_id": e.get("userId"),
            "display_name": _display_name(e),
            "email": e.get("email"),
            "title": e.get("title"),
            "department": e.get("department"),
            "division": e.get("division"),
            "location": e.get("location"),
            "hire_date": e.get("hireDate"),
        }
        for e in result.get("d", {}).get("results", [])
    ]

    response_data = {
        "manager_id": manager_id,
        "direct_reports": direct_reports,
        "direct_report_count": len(direct_reports),
    }

    if include_indirect_reports and direct_reports:
        indirect_reports = []
        for dr in direct_reports[:10]:  # Cap at 10 sub-queries to avoid timeout
            dr_id = dr["user_id"]
            if not dr_id:
                continue
            sub_params = {
                "$filter": f"manager eq '{sanitize_odata_string(dr_id)}' and (status eq 'active' or status eq 't')",
                "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,location",
                "$format": "json",
                "$top": "50",
            }
            sub_result = make_odata_request(
                instance,
                "/odata/v2/User",
                data_center,
                environment,
                auth_user_id,
                auth_password,
                sub_params,
                request_id,
            )
            if "error" not in sub_result:
                for entry in sub_result.get("d", {}).get("results", []):
                    indirect_reports.append(
                        {
                            "user_id": entry.get("userId"),
                            "display_name": _display_name(entry),
                            "title": entry.get("title"),
                            "department": entry.get("department"),
                            "location": entry.get("location"),
                            "reports_to": dr_id,
                        }
                    )

        response_data["indirect_reports"] = indirect_reports
        response_data["indirect_report_count"] = len(indirect_reports)
        response_data["total_team_size"] = len(direct_reports) + len(indirect_reports)
    else:
        response_data["total_team_size"] = len(direct_reports)

    return response_data
