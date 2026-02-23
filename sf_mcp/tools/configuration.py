"""Configuration and metadata tools: get_configuration, compare_configurations, list_entities."""

from typing import Any

from sf_mcp.client import make_metadata_request, make_service_doc_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp


def _extract_entity_fields(metadata: dict) -> dict[str, dict]:
    """Extract field information from OData metadata."""
    fields = {}
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
            if et and isinstance(et, dict):
                props = et.get("Property", [])
                if not isinstance(props, list):
                    props = [props]
                for prop in props:
                    if prop and isinstance(prop, dict):
                        name = prop.get("@Name", "")
                        if name:
                            fields[name] = {
                                "type": prop.get("@Type", "unknown"),
                                "nullable": prop.get("@Nullable", "true"),
                                "maxLength": prop.get("@MaxLength", ""),
                            }
    except (KeyError, TypeError, AttributeError):
        pass
    return fields


def _categorize_entities(entities: list[str]) -> dict[str, list[str]]:
    """Group OData entity names by category."""
    categories = {
        "foundation": [],
        "employee": [],
        "talent": [],
        "platform": [],
        "other": [],
    }
    for entity in entities:
        entity_lower = entity.lower()
        if entity.startswith("FO") or entity.startswith("fo"):
            categories["foundation"].append(entity)
        elif any(entity_lower.startswith(p) for p in ["emp", "per", "user", "person"]):
            categories["employee"].append(entity)
        elif any(entity_lower.startswith(p) for p in ["goal", "performance", "learning", "competency", "talent"]):
            categories["talent"].append(entity)
        elif any(entity_lower.startswith(p) for p in ["rbp", "picklist", "background", "photo", "attachment"]):
            categories["platform"].append(entity)
        else:
            categories["other"].append(entity)
    return categories


@mcp.tool()
@sf_tool("get_configuration")
def get_configuration(
    instance: str,
    entity: str,
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
    Retrieve OData entity metadata/configuration from a SuccessFactors instance.

    This tool fetches the $metadata document for a specific entity, showing
    all available fields, their types, and constraints.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: OData entity to inspect (e.g., "User", "EmpEmployment", "Position")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)

    Returns:
        dict containing entity metadata with field definitions
    """
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

    fields = _extract_entity_fields(metadata)

    return {
        "entity": entity,
        "instance": instance,
        "field_count": len(fields),
        "fields": fields,
    }


@mcp.tool()
@sf_tool("compare_configurations")
def compare_configurations(
    instance1: str,
    instance2: str,
    entity: str,
    data_center1: str,
    environment1: str,
    data_center2: str,
    environment2: str,
    auth_user_id: str,
    auth_password: str,
    # Note: 'instance' is required by sf_tool but this tool uses instance1/instance2.
    # We pass instance1 as 'instance' for validation, but the tool uses both.
    instance: str = "",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Compare entity configuration/metadata between two SuccessFactors instances.

    This is useful for verifying that dev/test/production environments are aligned
    before deployments, or for auditing configuration drift.

    Args:
        instance1: First SF instance/company ID (e.g., dev instance)
        instance2: Second SF instance/company ID (e.g., prod instance)
        entity: OData entity to compare (e.g., "User", "EmpEmployment", "Position")
        data_center1: SAP data center for instance1 (e.g., 'DC55')
        environment1: Environment for instance1 ('preview', 'production')
        data_center2: SAP data center for instance2 (e.g., 'DC55')
        environment2: Environment for instance2 ('preview', 'production')
        auth_user_id: SuccessFactors user ID for authentication (required, used for both instances)
        auth_password: SuccessFactors password for authentication (required, used for both instances)

    Returns:
        dict containing comparison results with match percentage and field differences
    """
    # Fetch metadata from both instances
    metadata1 = make_metadata_request(
        instance1,
        entity,
        data_center1,
        environment1,
        auth_user_id,
        auth_password,
        request_id,
    )
    metadata2 = make_metadata_request(
        instance2,
        entity,
        data_center2,
        environment2,
        auth_user_id,
        auth_password,
        request_id,
    )

    if metadata1 is None or (isinstance(metadata1, dict) and "error" in metadata1):
        return {"error": f"Failed to fetch metadata from instance1 ({instance1})"}
    if metadata2 is None or (isinstance(metadata2, dict) and "error" in metadata2):
        return {"error": f"Failed to fetch metadata from instance2 ({instance2})"}

    fields1 = _extract_entity_fields(metadata1)
    fields2 = _extract_entity_fields(metadata2)

    fields1_names = set(fields1.keys())
    fields2_names = set(fields2.keys())

    only_in_1 = sorted(fields1_names - fields2_names)
    only_in_2 = sorted(fields2_names - fields1_names)
    in_both = fields1_names & fields2_names

    type_differences = []
    for field in sorted(in_both):
        if fields1[field]["type"] != fields2[field]["type"]:
            type_differences.append(
                {
                    "field": field,
                    f"{instance1}_type": fields1[field]["type"],
                    f"{instance2}_type": fields2[field]["type"],
                }
            )

    total_unique_fields = len(fields1_names | fields2_names)
    matching_fields = len(in_both) - len(type_differences)
    match_percentage = round((matching_fields / total_unique_fields * 100), 1) if total_unique_fields > 0 else 100

    return {
        "entity": entity,
        "instance1": {
            "name": instance1,
            "data_center": data_center1,
            "environment": environment1,
            "field_count": len(fields1),
        },
        "instance2": {
            "name": instance2,
            "data_center": data_center2,
            "environment": environment2,
            "field_count": len(fields2),
        },
        "comparison": {
            "fields_only_in_instance1": only_in_1,
            "fields_only_in_instance2": only_in_2,
            "fields_in_both": len(in_both),
            "type_differences": type_differences,
            "match_percentage": match_percentage,
        },
        "summary": {
            "is_identical": len(only_in_1) == 0 and len(only_in_2) == 0 and len(type_differences) == 0,
            "differences_found": len(only_in_1) + len(only_in_2) + len(type_differences),
        },
    }


@mcp.tool()
@sf_tool("list_entities")
def list_entities(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    category: str | None = None,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List all available OData entities in the SuccessFactors instance.

    This discovery tool helps users understand what data is available to query.
    It fetches the service document which lists all entity sets.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        category: Optional filter - 'foundation', 'employee', 'talent', 'platform', 'all' (default: all)

    Returns:
        dict containing entity list, count, and optional category breakdown
    """
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

    entities = sorted(data.get("d", {}).get("EntitySets", []))

    categories_dict = _categorize_entities(entities)

    if category and category.lower() != "all":
        filtered_entities = categories_dict.get(category.lower(), entities)
    else:
        filtered_entities = entities

    response_data = {
        "entities": filtered_entities,
        "count": len(filtered_entities),
        "total_available": len(entities),
    }

    if not category or category.lower() == "all":
        response_data["by_category"] = {k: len(v) for k, v in categories_dict.items()}

    return response_data
