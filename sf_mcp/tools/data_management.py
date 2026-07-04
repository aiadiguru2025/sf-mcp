"""Data management tools: bulk export, picklist usage audit, country-specific fields."""

from typing import Any

from sf_mcp.client import make_metadata_request, make_odata_request, make_paginated_odata_request
from sf_mcp.config import DEFAULT_MAX_PAGES
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.tools.mdf import _extract_mdf_fields
from sf_mcp.validation import sanitize_odata_string, validate_entity_path

# Entities commonly carrying picklist-backed fields; used as the default scan
# list for get_picklist_usage when the caller doesn't specify one.
_DEFAULT_PICKLIST_SCAN_ENTITIES = ["User", "EmpJob", "EmpEmployment", "Position", "PerPersonal", "PerNationalId"]


@mcp.tool()
@sf_tool("bulk_export_employees", max_top=1000)
def bulk_export_employees(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    select: str = "",
    department: str = "",
    status: str = "active",
    top: int = 500,
    max_pages: int = DEFAULT_MAX_PAGES,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Export all employees in bulk with automatic pagination, for downstream systems.

    Unlike search_employees (capped results for interactive lookups), this
    follows pagination automatically to return the full population.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        select: Comma-separated fields to return. Defaults to a standard field set.
        department: Optional filter by department
        status: Employee status filter: 'active', 'inactive', or 'all' (default: 'active')
        top: Records per page (default: 500, max: 1000)
        max_pages: Maximum pages to fetch (default: 10, max: 50)
    """
    filters = []
    if status == "active":
        filters.append("(status eq 'active' or status eq 't')")
    elif status == "inactive":
        filters.append("(status eq 'inactive' or status eq 'f')")
    if department:
        filters.append(f"department eq '{sanitize_odata_string(department)}'")

    params = {
        "$select": select
        or "userId,firstName,lastName,displayName,email,hireDate,status,title,department,division,location,manager",
        "$format": "json",
    }
    if filters:
        params["$filter"] = " and ".join(filters)

    result = make_paginated_odata_request(
        instance,
        "/odata/v2/User",
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

    result["filters_applied"] = {"department": department or None, "status": status}
    return result


def _scan_entity_picklist_fields(metadata: dict) -> list[dict]:
    """Scan entity metadata for properties carrying a picklist annotation."""
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
                if not name:
                    continue
                for attr_key, attr_value in prop.items():
                    if attr_key == "@Name" or not attr_key.startswith("@"):
                        continue
                    if "picklist" in attr_key.lower():
                        fields.append({"field": name, "attribute": attr_key.lstrip("@"), "picklist_id": attr_value})
    except (KeyError, TypeError, AttributeError):
        pass
    return fields


@mcp.tool()
@sf_tool("get_picklist_usage")
def get_picklist_usage(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    entities: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Discover which picklists are used on which entity fields, for config audits.

    Scans entity metadata for picklist annotations. Coverage depends on whether
    the instance's metadata exposes picklist bindings for a given entity.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        entities: Comma-separated entity names to scan. Defaults to a common set
            (User, EmpJob, EmpEmployment, Position, PerPersonal, PerNationalId).
    """
    entity_list = [e.strip() for e in entities.split(",") if e.strip()] if entities else _DEFAULT_PICKLIST_SCAN_ENTITIES

    validated_entities = []
    for entity in entity_list:
        try:
            validate_entity_path(entity, "entities")
            validated_entities.append(entity)
        except ValueError:
            continue

    usage_by_entity = {}
    errors = {}
    for entity in validated_entities:
        metadata = make_metadata_request(
            instance,
            entity,
            data_center,
            environment,
            auth_user_id,
            auth_password,
            request_id,
        )
        if metadata is None or "error" in metadata:
            errors[entity] = metadata.get("error") if isinstance(metadata, dict) else "Failed to fetch metadata"
            continue
        picklist_fields = _scan_entity_picklist_fields(metadata)
        usage_by_entity[entity] = picklist_fields

    total_picklist_fields = sum(len(v) for v in usage_by_entity.values())

    return {
        "entities_scanned": validated_entities,
        "picklist_usage": usage_by_entity,
        "total_picklist_fields_found": total_picklist_fields,
        "errors": errors or None,
    }


@mcp.tool()
@sf_tool("get_country_specific_fields", validate={"entity": "entity_path"})
def get_country_specific_fields(
    instance: str,
    entity: str,
    country: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    sample_size: int = 50,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Analyze which fields of an entity are actually populated for a given country.

    Fetches the entity's field definitions, then samples records filtered by
    country to compute a population rate per field. Useful for understanding
    country-specific data requirements (e.g. PerNationalId, PerPersonal, PerAddress
    tend to vary meaningfully by country).

    Args:
        instance: The SuccessFactors instance/company ID
        entity: OData entity to analyze (e.g., 'PerPersonal', 'PerNationalId', 'PerAddress')
        country: ISO country code to filter the sample (e.g., 'US', 'DE', 'IN')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        sample_size: Number of records to sample for population rates (default: 50, max: 200)
    """
    sample_size = max(1, min(sample_size, 200))

    metadata = make_metadata_request(
        instance,
        entity,
        data_center,
        environment,
        auth_user_id,
        auth_password,
        request_id,
    )

    if metadata is None:
        return {"error": f"Failed to fetch metadata for entity '{entity}'"}
    if "error" in metadata:
        return metadata

    fields = _extract_mdf_fields(metadata)
    field_names = [f["name"] for f in fields if f.get("type") != "NavigationProperty"]

    if not field_names:
        return {
            "entity": entity,
            "country": country,
            "fields": fields,
            "message": "No fields discovered in metadata; cannot sample population rates.",
        }

    safe_country = sanitize_odata_string(country)
    sample_params = {
        "$filter": f"country eq '{safe_country}'",
        "$select": ",".join(field_names[:50]),
        "$format": "json",
        "$top": str(sample_size),
    }

    sample_result = make_odata_request(
        instance,
        f"/odata/v2/{entity}",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        sample_params,
        request_id,
    )

    if "error" in sample_result:
        return {
            "entity": entity,
            "country": country,
            "fields": fields,
            "sampling_error": sample_result.get("error"),
        }

    records = sample_result.get("d", {}).get("results", [])
    sample_count = len(records)

    population: dict[str, dict[str, Any]] = {}
    for name in field_names[:50]:
        populated = sum(1 for r in records if r.get(name) not in (None, ""))
        population[name] = {
            "populated_count": populated,
            "sample_size": sample_count,
            "population_rate_percent": round(populated / sample_count * 100, 1) if sample_count else None,
        }

    return {
        "entity": entity,
        "country": country,
        "sample_size": sample_count,
        "field_count": len(field_names),
        "fields": fields,
        "population_by_field": population,
    }
