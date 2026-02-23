"""Data query tools: query_odata, get_picklist_values."""

from typing import Any

from sf_mcp.client import make_odata_request, make_paginated_odata_request
from sf_mcp.config import DEFAULT_MAX_PAGES
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import (
    sanitize_odata_string,
    validate_entity_path,
    validate_expand,
    validate_odata_filter,
    validate_orderby,
    validate_select,
)


@mcp.tool()
@sf_tool("query_odata", max_top=1000)
def query_odata(
    instance: str,
    entity: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    select: str = "",
    filter: str = "",
    orderby: str = "",
    expand: str = "",
    top: int = 100,
    skip: int = 0,
    paginate: bool = False,
    max_pages: int = DEFAULT_MAX_PAGES,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Query any OData entity with flexible filtering, sorting, and field selection.

    This is the most flexible tool - it can query any entity in the system.
    Use other specialized tools for common queries (employee profiles, etc.).

    Args:
        instance: The SuccessFactors instance/company ID
        entity: OData entity to query (e.g., "User", "EmpJob", "Position")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        select: Comma-separated fields to return (e.g., "userId,firstName,lastName")
        filter: OData filter expression (e.g., "department eq 'Engineering'")
        orderby: Sort order (e.g., "hireDate desc")
        expand: Navigation properties to expand (e.g., "manager,hr")
        top: Maximum records (default 100, max 1000). Used as page size when paginate=True.
        skip: Records to skip for pagination (default 0). Ignored when paginate=True.
        paginate: If True, automatically fetch all pages of results (default: False)
        max_pages: Maximum pages to fetch when paginate=True (default: 10, max: 50)
    """
    # Additional validation for query parameters
    try:
        validate_entity_path(entity, "entity")
        if select:
            validate_select(select, "select")
        if filter:
            validate_odata_filter(filter, "filter")
        if orderby:
            validate_orderby(orderby, "orderby")
        if expand:
            validate_expand(expand, "expand")
    except ValueError as e:
        return {"error": str(e)}

    params = {"$format": "json", "$top": str(top)}
    if select:
        params["$select"] = select
    if filter:
        params["$filter"] = filter
    if orderby:
        params["$orderby"] = orderby
    if expand:
        params["$expand"] = expand
    if skip > 0:
        params["$skip"] = str(skip)

    endpoint = f"/odata/v2/{entity}"

    if paginate:
        result = make_paginated_odata_request(
            instance,
            endpoint,
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
            page_size=top,
            max_pages=max_pages,
        )
        if "error" in result:
            return result
        result["entity"] = entity
        return result

    result = make_odata_request(
        instance,
        endpoint,
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    # Extract results
    if "d" in result:
        d = result["d"]
        if "results" in d:
            records = d["results"]
            record_count = len(records)
            response_data = {
                "entity": entity,
                "results": records,
                "count": record_count,
            }
            # Add pagination hints
            if record_count >= top:
                response_data["next_skip"] = skip + top
                response_data["has_more"] = True
            else:
                response_data["has_more"] = False
            return response_data
        else:
            return {"entity": entity, "result": d, "count": 1}
    else:
        return result


@mcp.tool()
@sf_tool("get_picklist_values", validate={"locale": "locale"})
def get_picklist_values(
    instance: str,
    picklist_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    include_inactive: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get all values for a specific picklist.

    Picklists are used throughout SuccessFactors for dropdown fields.
    This tool retrieves all options for a given picklist, which is essential
    for data validation and understanding available field values.

    Args:
        instance: The SuccessFactors instance/company ID
        picklist_id: The picklist identifier (e.g., "ecJobFunction", "nationality")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for labels (default: en-US)
        include_inactive: If True, includes inactive/expired values (default: False)

    Common picklists:
        - ecJobFunction: Job functions
        - ecJobCode: Job codes
        - ecPayGrade: Pay grades
        - ecDepartment: Departments
        - nationality: Countries/nationalities
        - maritalStatus: Marital status options
    """
    safe_picklist_id = sanitize_odata_string(picklist_id)

    params = {
        "$filter": f"PickListV2_id eq '{safe_picklist_id}'",
        "$expand": "picklistLabels",
        "$format": "json",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/PickListValueV2",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
        cache_category="picklist",
    )

    if "error" in result:
        # Try alternative endpoint (older PicklistOption)
        params_alt = {
            "$filter": f"picklistId eq '{safe_picklist_id}'",
            "$format": "json",
        }
        result = make_odata_request(
            instance,
            "/odata/v2/PicklistOption",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params_alt,
            request_id,
            cache_category="picklist",
        )
        if "error" in result:
            return result

    values, inactive_count = _extract_picklist_values(result, locale, include_inactive)

    values.sort(key=lambda x: (x.get("sortOrder", 999), x.get("label", "")))

    return {
        "picklist_id": picklist_id,
        "locale": locale,
        "values": values,
        "count": len(values),
        "has_inactive": inactive_count > 0,
        "inactive_count": inactive_count if include_inactive else None,
    }


def _extract_picklist_values(result: dict, locale: str, include_inactive: bool) -> tuple[list[dict], int]:
    """Extract and format picklist values from OData response."""
    values = []
    inactive_count = 0

    for entry in result.get("d", {}).get("results", []):
        status = entry.get("status", "A")
        is_active = status in ["A", "active", None]

        if not is_active:
            inactive_count += 1
            if not include_inactive:
                continue

        label = entry.get("optionValue", "")
        external_code = entry.get("externalCode", entry.get("optionId", ""))

        picklist_labels = entry.get("picklistLabels", {})
        if isinstance(picklist_labels, dict) and "results" in picklist_labels:
            for lbl in picklist_labels["results"]:
                if lbl.get("locale") == locale:
                    label = lbl.get("label", label)
                    break

        value_info = {
            "id": entry.get("optionId", external_code),
            "externalCode": external_code,
            "label": label,
            "status": "active" if is_active else "inactive",
        }

        if entry.get("parentPicklistValue"):
            value_info["parentValue"] = entry.get("parentPicklistValue")
        if entry.get("sortOrder"):
            value_info["sortOrder"] = entry.get("sortOrder")

        values.append(value_info)

    return values, inactive_count
