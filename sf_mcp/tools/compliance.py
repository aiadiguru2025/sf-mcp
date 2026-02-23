"""Compliance & reporting tools: terminations, missing data, anniversaries, performance, compensation."""

from datetime import date, datetime
from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string
from sf_mcp.xml_utils import parse_hire_date


def _display_name(entry: dict) -> str:
    return entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip()


@mcp.tool()
@sf_tool("get_terminations", max_top=500)
def get_terminations(
    instance: str,
    from_date: str,
    to_date: str,
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
    List terminated employees in a date range for exit processing and compliance.

    Args:
        instance: The SuccessFactors instance/company ID
        from_date: Start of date range (YYYY-MM-DD)
        to_date: End of date range (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    filters = [
        f"endDate ge datetime'{from_date}T00:00:00'",
        f"endDate le datetime'{to_date}T23:59:59'",
    ]

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,startDate,endDate,originalStartDate,lastDateWorked,payrollEndDate",
        "$expand": "userNav,personNav,jobInfoNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "endDate desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/EmpEmployment",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    terminations = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userNav", {}) or {}
        person_nav = entry.get("personNav", {}) or {}
        job_nav = entry.get("jobInfoNav", {}) or {}

        job_info = {}
        if isinstance(job_nav, dict) and "results" in job_nav:
            jobs = job_nav["results"]
            if jobs:
                job_info = jobs[0]
        elif isinstance(job_nav, dict):
            job_info = job_nav

        emp_department = job_info.get("department") or user_nav.get("department", "")

        if department and emp_department and department.lower() not in emp_department.lower():
            continue

        # Calculate tenure
        tenure_years = None
        orig_start = entry.get("originalStartDate") or entry.get("startDate")
        end_date_val = entry.get("endDate")
        if orig_start and end_date_val:
            try:
                start_str = str(orig_start)
                end_str = str(end_date_val)
                if "T" in start_str and "T" in end_str:
                    start_dt = datetime.strptime(start_str[:10], "%Y-%m-%d")
                    end_dt = datetime.strptime(end_str[:10], "%Y-%m-%d")
                    tenure_years = round((end_dt - start_dt).days / 365.25, 1)
            except (ValueError, TypeError):
                pass

        display = (
            user_nav.get("displayName")
            or f"{person_nav.get('firstName', '')} {person_nav.get('lastName', '')}".strip()
            or entry.get("userId")
        )

        terminations.append(
            {
                "user_id": entry.get("userId"),
                "display_name": display,
                "department": emp_department,
                "title": job_info.get("jobTitle"),
                "original_start_date": entry.get("originalStartDate"),
                "termination_date": entry.get("endDate"),
                "last_date_worked": entry.get("lastDateWorked"),
                "tenure_years": tenure_years,
            }
        )

    return {
        "terminations": terminations,
        "count": len(terminations),
        "date_range": {"from": from_date, "to": to_date},
        "filters_applied": {"department": department or None},
    }


@mcp.tool()
@sf_tool("get_employees_missing_data", max_top=500)
def get_employees_missing_data(
    instance: str,
    check_fields: str,
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
    Find employees with incomplete profiles for compliance audits.

    Checks for missing email, phone, address, or emergency contact data.

    Args:
        instance: The SuccessFactors instance/company ID
        check_fields: Comma-separated fields to check: 'email', 'phone', 'address', 'emergency_contact'
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    valid_fields = {"email", "phone", "address", "emergency_contact"}
    requested_fields = [f.strip().lower() for f in check_fields.split(",")]
    invalid = [f for f in requested_fields if f not in valid_fields]
    if invalid:
        return {
            "error": (f"Invalid check_fields: {', '.join(invalid)}. Valid options: {', '.join(sorted(valid_fields))}")
        }

    user_filters = ["status eq 'active' or status eq 't'"]
    if department:
        user_filters.append(f"department eq '{sanitize_odata_string(department)}'")

    user_params = {
        "$filter": " and ".join(user_filters),
        "$select": "userId,firstName,lastName,displayName,email,department,hireDate",
        "$format": "json",
        "$top": str(min(top * 2, 1000)),
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
    total_employees = len(users)

    field_entity_map = {
        "email": "PerEmail",
        "phone": "PerPhone",
        "address": "PerAddress",
        "emergency_contact": "PerEmergencyContacts",
    }

    employees_with_data = {}
    for field in requested_fields:
        entity = field_entity_map[field]
        data_params = {"$select": "personIdExternal", "$format": "json", "$top": "1000"}
        data_result = make_odata_request(
            instance,
            f"/odata/v2/{entity}",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            data_params,
            request_id,
        )
        if "error" not in data_result:
            ids_with_data = {
                e.get("personIdExternal")
                for e in data_result.get("d", {}).get("results", [])
                if e.get("personIdExternal")
            }
            employees_with_data[field] = ids_with_data
        else:
            employees_with_data[field] = set()

    employees_missing = []
    for user in users:
        uid = user.get("userId", "")
        missing_fields = []
        for field in requested_fields:
            if field == "email" and not user.get("email"):
                missing_fields.append("email")
            elif field != "email" and uid not in employees_with_data.get(field, set()):
                missing_fields.append(field)

        if missing_fields:
            employees_missing.append(
                {
                    "user_id": uid,
                    "display_name": _display_name(user),
                    "department": user.get("department"),
                    "hire_date": user.get("hireDate"),
                    "missing_fields": missing_fields,
                }
            )

    employees_missing = employees_missing[:top]
    if total_employees > 0:
        compliance_rate = round((total_employees - len(employees_missing)) / total_employees * 100, 1)
    else:
        compliance_rate = 100.0

    return {
        "employees_with_issues": employees_missing,
        "count": len(employees_missing),
        "total_employees_checked": total_employees,
        "compliance_rate_percent": compliance_rate,
        "fields_checked": requested_fields,
        "filters_applied": {"department": department or None},
    }


@mcp.tool()
@sf_tool("get_anniversary_employees", max_top=500)
def get_anniversary_employees(
    instance: str,
    from_date: str,
    to_date: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    milestone_years_only: bool = False,
    department: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Find employees with upcoming work anniversaries for recognition programs.

    Args:
        instance: The SuccessFactors instance/company ID
        from_date: Start of anniversary search range (YYYY-MM-DD)
        to_date: End of anniversary search range (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        milestone_years_only: If True, only show 1, 5, 10, 15, 20, 25+ year milestones
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    user_filters = ["status eq 'active' or status eq 't'"]
    if department:
        user_filters.append(f"department eq '{sanitize_odata_string(department)}'")

    params = {
        "$filter": " and ".join(user_filters),
        "$select": "userId,firstName,lastName,displayName,hireDate,department,title,manager",
        "$format": "json",
        "$top": "1000",
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

    from_dt = datetime.strptime(from_date, "%Y-%m-%d").date()
    to_dt = datetime.strptime(to_date, "%Y-%m-%d").date()
    target_year = from_dt.year
    milestone_years = {1, 5, 10, 15, 20, 25, 30, 35, 40}

    anniversaries = []
    for entry in result.get("d", {}).get("results", []):
        hire_dt = parse_hire_date(entry.get("hireDate"))
        if not hire_dt:
            continue

        try:
            anniversary_dt = hire_dt.replace(year=target_year)
        except ValueError:
            anniversary_dt = date(target_year, 3, 1)  # Feb 29 leap year edge case

        if from_dt <= anniversary_dt <= to_dt:
            years_of_service = target_year - hire_dt.year
            if years_of_service <= 0:
                continue

            is_milestone = years_of_service in milestone_years
            if milestone_years_only and not is_milestone:
                continue

            anniversaries.append(
                {
                    "user_id": entry.get("userId"),
                    "display_name": _display_name(entry),
                    "department": entry.get("department"),
                    "title": entry.get("title"),
                    "hire_date": entry.get("hireDate"),
                    "anniversary_date": anniversary_dt.isoformat(),
                    "years_of_service": years_of_service,
                    "is_milestone": is_milestone,
                    "manager_id": entry.get("manager"),
                }
            )

    anniversaries.sort(key=lambda x: x.get("anniversary_date", ""))
    anniversaries = anniversaries[:top]

    milestone_count = sum(1 for a in anniversaries if a.get("is_milestone"))

    return {
        "anniversaries": anniversaries,
        "count": len(anniversaries),
        "milestone_count": milestone_count,
        "date_range": {"from": from_date, "to": to_date},
        "filters_applied": {"milestone_years_only": milestone_years_only, "department": department or None},
    }


@mcp.tool()
@sf_tool("get_performance_review_status", max_top=500)
def get_performance_review_status(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    form_template_id: str = "",
    department: str = "",
    manager_id: str = "",
    status: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Track performance review form completion across the organization.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        form_template_id: Filter by form template ID
        department: Filter by department (applied client-side)
        manager_id: Filter by manager's user ID (applied client-side)
        status: Filter by form status: 'not_started', 'in_progress', 'completed', or '' for all
        top: Maximum results (default: 100, max: 500)
    """
    filters = []

    if form_template_id:
        filters.append(f"formTemplateId eq '{sanitize_odata_string(form_template_id)}'")

    status_map = {"not_started": "1", "in_progress": "2", "completed": "3"}
    if status and status in status_map:
        filters.append(f"formDataStatus eq {status_map[status]}")

    params = {
        "$select": (
            "formDataId,formTemplateId,formTemplateName,formSubjectId,formDataStatus,formLastModifiedDate,formDueDate"
        ),
        "$expand": "formSubjectIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "formLastModifiedDate desc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        "/odata/v2/FormHeader",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    status_labels = {"1": "Not Started", "2": "In Progress", "3": "Completed", "4": "Sent Back"}

    reviews = []
    status_counts = {}
    for entry in result.get("d", {}).get("results", []):
        subject_nav = entry.get("formSubjectIdNav", {}) or {}

        emp_department = subject_nav.get("department", "")
        emp_manager = subject_nav.get("manager", "")

        if department and emp_department and department.lower() not in emp_department.lower():
            continue
        if manager_id and emp_manager and manager_id != emp_manager:
            continue

        form_status = str(entry.get("formDataStatus", ""))
        status_label = status_labels.get(form_status, form_status)
        status_counts[status_label] = status_counts.get(status_label, 0) + 1

        reviews.append(
            {
                "form_id": entry.get("formDataId"),
                "template_name": entry.get("formTemplateName"),
                "subject_user_id": entry.get("formSubjectId"),
                "subject_name": _display_name(subject_nav) if subject_nav else entry.get("formSubjectId"),
                "department": emp_department,
                "status": status_label,
                "due_date": entry.get("formDueDate"),
                "last_modified": entry.get("formLastModifiedDate"),
            }
        )

    return {
        "reviews": reviews,
        "count": len(reviews),
        "by_status": status_counts,
        "filters_applied": {
            "form_template_id": form_template_id or None,
            "department": department or None,
            "manager_id": manager_id or None,
            "status": status or "all",
        },
    }


@mcp.tool()
@sf_tool("get_compensation_details")
def get_compensation_details(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    effective_date: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get compensation breakdown for employees including base pay and pay components.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) - single ID or comma-separated (max 20)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        effective_date: Show compensation as of this date (YYYY-MM-DD). Defaults to latest.
    """
    id_list = [uid.strip() for uid in user_ids.split(",")][:20]

    all_compensation = []
    for uid in id_list:
        safe_uid = sanitize_odata_string(uid)
        filter_expr = f"userId eq '{safe_uid}'"
        if effective_date:
            filter_expr += f" and startDate le datetime'{effective_date}T23:59:59'"

        params = {
            "$filter": filter_expr,
            "$select": "userId,startDate,payGroup,payGrade,compensatedHours",
            "$expand": "empPayCompRecurringNav,empPayCompNonRecurringNav",
            "$format": "json",
            "$top": "5",
            "$orderby": "startDate desc",
        }

        result = make_odata_request(
            instance,
            "/odata/v2/EmpCompensation",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )

        if "error" in result:
            all_compensation.append({"user_id": uid, "error": result.get("error")})
            continue

        records = result.get("d", {}).get("results", [])
        if not records:
            all_compensation.append({"user_id": uid, "compensation": None, "message": "No compensation records found"})
            continue

        latest = records[0]
        comp_data = {
            "user_id": uid,
            "effective_date": latest.get("startDate"),
            "pay_group": latest.get("payGroup"),
            "pay_grade": latest.get("payGrade"),
            "compensated_hours": latest.get("compensatedHours"),
        }

        recurring_nav = latest.get("empPayCompRecurringNav", {})
        if isinstance(recurring_nav, dict) and "results" in recurring_nav:
            comp_data["recurring_components"] = [
                {
                    "pay_component": r.get("payComponent"),
                    "amount": r.get("paycompvalue"),
                    "currency": r.get("currencyCode"),
                    "frequency": r.get("frequency"),
                }
                for r in recurring_nav["results"]
            ]

        non_recurring_nav = latest.get("empPayCompNonRecurringNav", {})
        if isinstance(non_recurring_nav, dict) and "results" in non_recurring_nav:
            comp_data["non_recurring_components"] = [
                {"pay_component": r.get("payComponent"), "amount": r.get("value"), "currency": r.get("currencyCode")}
                for r in non_recurring_nav["results"]
            ]

        all_compensation.append(comp_data)

    return {"employees": all_compensation, "count": len(all_compensation)}
