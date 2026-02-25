"""MDF (Metadata Framework) tools: object definitions, generic queries, foundation objects."""

from typing import Any

from sf_mcp.client import make_metadata_request, make_odata_request, make_service_doc_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_mdf_object_definitions")
def get_mdf_object_definitions(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    object_name: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List custom MDF objects and their fields from the instance.

    Discovers MDF/generic objects (prefixed with 'cust_') in the system.
    When an object_name is provided, returns detailed field definitions
    including types, nullability, and max lengths.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        object_name: Specific MDF object to inspect (e.g., 'cust_myObject'). If empty, lists all.
    """
    if object_name:
        # Fetch metadata for a specific MDF object
        safe_name = sanitize_odata_string(object_name)
        metadata = make_metadata_request(
            instance,
            safe_name,
            data_center,
            environment,
            auth_user_id,
            auth_password,
            request_id,
        )

        if metadata is None:
            return {
                "error": f"MDF object '{object_name}' not found",
                "message": "Check the object name. MDF objects typically start with 'cust_'.",
            }
        if "error" in metadata:
            return metadata

        fields = _extract_mdf_fields(metadata)
        return {
            "object_name": object_name,
            "field_count": len(fields),
            "fields": fields,
        }

    # List all MDF objects by filtering the service document for cust_ entities
    data = make_service_doc_request(
        instance,
        data_center,
        environment,
        auth_user_id,
        auth_password,
        request_id,
    )

    if "error" in data:
        return data

    all_entities = data.get("d", {}).get("EntitySets", [])
    mdf_objects = sorted(e for e in all_entities if e.startswith("cust_"))

    return {
        "mdf_objects": mdf_objects,
        "count": len(mdf_objects),
        "total_entities": len(all_entities),
        "message": "Use object_name parameter to get field details for a specific object.",
    }


def _extract_mdf_fields(metadata: dict) -> list[dict]:
    """Extract field definitions from OData metadata for an MDF object."""
    fields: list[dict] = []
    try:
        if "edmx:Edmx" in metadata:
            data_services = metadata["edmx:Edmx"].get("edmx:DataServices", {})
        elif "Edmx" in metadata:
            data_services = metadata["Edmx"].get("DataServices", {})
        else:
            return fields

        schema = data_services.get("Schema", {})
        if isinstance(schema, list):
            schema = schema[0] if schema else {}

        entity_types = schema.get("EntityType", [])
        if not isinstance(entity_types, list):
            entity_types = [entity_types]

        for et in entity_types:
            if not et or not isinstance(et, dict):
                continue
            props = et.get("Property", [])
            if not isinstance(props, list):
                props = [props]
            for prop in props:
                if not prop or not isinstance(prop, dict):
                    continue
                name = prop.get("@Name", "")
                if name:
                    field_info: dict[str, Any] = {
                        "name": name,
                        "type": prop.get("@Type", "unknown"),
                        "nullable": prop.get("@Nullable", "true"),
                    }
                    if prop.get("@MaxLength"):
                        field_info["max_length"] = prop["@MaxLength"]
                    fields.append(field_info)

        # Extract navigation properties
        for et in entity_types:
            if not et or not isinstance(et, dict):
                continue
            nav_props = et.get("NavigationProperty", [])
            if not isinstance(nav_props, list):
                nav_props = [nav_props]
            for nav in nav_props:
                if not nav or not isinstance(nav, dict):
                    continue
                name = nav.get("@Name", "")
                if name:
                    fields.append({
                        "name": name,
                        "type": "NavigationProperty",
                        "relationship": nav.get("@Relationship", ""),
                    })
    except (KeyError, TypeError, AttributeError):
        pass
    return fields


@mcp.tool()
@sf_tool("query_mdf_object", max_top=500)
def query_mdf_object(
    instance: str,
    object_name: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    select: str = "",
    filter: str = "",
    top: int = 100,
    skip: int = 0,
    orderby: str = "",
    effective_date: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Query data from any MDF/generic object (e.g., cust_myObject).

    Supports filtering, field selection, and pagination for custom MDF objects
    and standard generic objects. Use get_mdf_object_definitions first to
    discover available objects and their fields.

    Args:
        instance: The SuccessFactors instance/company ID
        object_name: MDF object name (e.g., 'cust_myObject', 'cust_trainingRecord')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        select: Comma-separated fields (e.g., 'externalCode,cust_field1')
        filter: OData filter (e.g., "cust_status eq 'active'")
        top: Maximum results (default: 100, max: 500)
        skip: Records to skip for pagination (default: 0)
        orderby: Sort order (e.g., 'lastModifiedDateTime desc')
        effective_date: Filter by effective date (YYYY-MM-DD) for dated objects
    """
    safe_name = sanitize_odata_string(object_name)
    endpoint = f"/odata/v2/{safe_name}"

    params: dict[str, str] = {
        "$format": "json",
        "$top": str(top),
    }

    if select:
        params["$select"] = select
    if filter:
        params["$filter"] = filter
    if skip > 0:
        params["$skip"] = str(skip)
    if orderby:
        params["$orderby"] = orderby
    if effective_date:
        safe_date = sanitize_odata_string(effective_date)
        if "$filter" in params:
            params["$filter"] += (
                f" and effectiveStartDate le datetime'{safe_date}T23:59:59'"
            )
        else:
            params["$filter"] = (
                f"effectiveStartDate le datetime'{safe_date}T23:59:59'"
            )

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
            response: dict[str, Any] = {
                "object_name": object_name,
                "results": records,
                "count": len(records),
            }
            if len(records) >= top:
                response["next_skip"] = skip + top
                response["has_more"] = True
            else:
                response["has_more"] = False
            return response
        else:
            return {"object_name": object_name, "result": d, "count": 1}
    return result


# Well-known foundation object entity mappings
_FOUNDATION_ENTITIES: dict[str, str] = {
    "company": "FOCompany",
    "department": "FODepartment",
    "division": "FODivision",
    "location": "FOLocation",
    "cost_center": "FOCostCenter",
    "job_code": "FOJobCode",
    "job_function": "FOJobFunction",
    "pay_grade": "FOPayGrade",
    "pay_group": "FOPayGroup",
    "business_unit": "FOBusinessUnit",
    "event_reason": "FOEventReason",
    "legal_entity": "FOLegalEntity",
}


@mcp.tool()
@sf_tool("get_foundation_objects", max_top=500)
def get_foundation_objects(
    instance: str,
    object_type: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    filter: str = "",
    top: int = 100,
    include_inactive: bool = False,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Query foundation objects (cost centers, departments, divisions, etc.).

    Foundation objects are the building blocks of the org structure in
    SuccessFactors. This tool provides a convenient way to query them
    without needing to know the FO entity names.

    Args:
        instance: The SuccessFactors instance/company ID
        object_type: Type of foundation object. Options: 'company', 'department',
            'division', 'location', 'cost_center', 'job_code', 'job_function',
            'pay_grade', 'pay_group', 'business_unit', 'event_reason', 'legal_entity'
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        filter: Additional OData filter (e.g., "country eq 'US'")
        top: Maximum results (default: 100, max: 500)
        include_inactive: Include inactive/end-dated records (default: false)
    """
    entity_name = _FOUNDATION_ENTITIES.get(object_type.lower())
    if not entity_name:
        return {
            "error": f"Unknown foundation object type: '{object_type}'",
            "valid_types": sorted(_FOUNDATION_ENTITIES.keys()),
        }

    endpoint = f"/odata/v2/{entity_name}"

    # Common FO fields across most foundation objects
    select_fields = (
        "externalCode,name,name_defaultValue,description,"
        "description_defaultValue,status,startDate,endDate,"
        "lastModifiedDateTime"
    )

    filters: list[str] = []
    if not include_inactive:
        filters.append("status eq 'A'")
    if filter:
        filters.append(filter)

    params: dict[str, str] = {
        "$select": select_fields,
        "$format": "json",
        "$top": str(top),
        "$orderby": "name_defaultValue asc",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_odata_request(
        instance,
        endpoint,
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
        cache_category="metadata",
    )

    if "error" in result:
        return result

    records = result.get("d", {}).get("results", [])

    objects = [
        {
            "external_code": r.get("externalCode"),
            "name": r.get("name_defaultValue") or r.get("name"),
            "description": r.get("description_defaultValue") or r.get("description"),
            "status": r.get("status"),
            "start_date": r.get("startDate"),
            "end_date": r.get("endDate"),
            "last_modified": r.get("lastModifiedDateTime"),
        }
        for r in records
    ]

    # Count by status
    status_counts: dict[str, int] = {}
    for obj in objects:
        s = obj.get("status") or "Unknown"
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "object_type": object_type,
        "entity_name": entity_name,
        "objects": objects,
        "count": len(objects),
        "by_status": status_counts,
        "filters_applied": {
            "include_inactive": include_inactive,
            "custom_filter": filter or None,
        },
    }
