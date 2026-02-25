"""Position management tools: position details, vacancies, org chart."""

from datetime import date
from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_position_details")
def get_position_details(
    instance: str,
    position_code: str,
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
    Get details for a specific position including incumbent, department, and job info.

    Returns the position's title, department, cost center, location, job classification,
    FTE, incumbent employee, and parent position. Useful for headcount planning and
    understanding the organizational structure.

    Args:
        instance: The SuccessFactors instance/company ID
        position_code: The position code/ID (e.g., 'POS_001')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        effective_date: Filter by effective date (YYYY-MM-DD). Defaults to today.
    """
    safe_code = sanitize_odata_string(position_code)
    eff_date = effective_date or date.today().isoformat()

    params = {
        "$filter": (
            f"code eq '{safe_code}' and "
            f"effectiveStartDate le datetime'{eff_date}T23:59:59'"
        ),
        "$select": (
            "code,positionTitle,department,costCenter,jobCode,jobTitle,"
            "incumbent,effectiveStartDate,effectiveEndDate,company,location,"
            "standardHours,targetFTE,vacant,parentPosition,positionCriticality,"
            "changeReason,createdDateTime,lastModifiedDateTime"
        ),
        "$expand": "parentPosition,incumbentNav",
        "$format": "json",
        "$top": "1",
        "$orderby": "effectiveStartDate desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/Position",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    positions = result.get("d", {}).get("results", [])
    if not positions:
        return {
            "error": f"Position '{position_code}' not found",
            "message": "Check the position code and try again.",
        }

    pos = positions[0]

    position = {
        "code": pos.get("code"),
        "title": pos.get("positionTitle"),
        "department": pos.get("department"),
        "cost_center": pos.get("costCenter"),
        "job_code": pos.get("jobCode"),
        "job_title": pos.get("jobTitle"),
        "company": pos.get("company"),
        "location": pos.get("location"),
        "standard_hours": pos.get("standardHours"),
        "target_fte": pos.get("targetFTE"),
        "vacant": pos.get("vacant"),
        "criticality": pos.get("positionCriticality"),
        "effective_start_date": pos.get("effectiveStartDate"),
        "effective_end_date": pos.get("effectiveEndDate"),
        "change_reason": pos.get("changeReason"),
        "created_date": pos.get("createdDateTime"),
        "last_modified": pos.get("lastModifiedDateTime"),
    }

    # Extract incumbent info
    incumbent_nav = pos.get("incumbentNav", {})
    if isinstance(incumbent_nav, dict) and "results" in incumbent_nav:
        incumbents = incumbent_nav["results"]
        if incumbents:
            inc = incumbents[0]
            position["incumbent"] = {
                "user_id": inc.get("userId"),
                "name": (
                    inc.get("displayName")
                    or f"{inc.get('firstName', '')} {inc.get('lastName', '')}".strip()
                ),
            }
    elif pos.get("incumbent"):
        position["incumbent_id"] = pos.get("incumbent")

    # Extract parent position
    parent_nav = pos.get("parentPosition", {})
    if isinstance(parent_nav, dict) and parent_nav.get("code"):
        position["parent_position"] = {
            "code": parent_nav.get("code"),
            "title": parent_nav.get("positionTitle"),
        }

    return {"position": position}


@mcp.tool()
@sf_tool("get_vacant_positions", max_top=500)
def get_vacant_positions(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    location: str = "",
    cost_center: str = "",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    List positions with no current incumbent for headcount planning.

    Shows all vacant positions with their title, department, cost center, and
    location. Essential for workforce planning and identifying open headcount.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department name or code
        location: Filter by work location
        cost_center: Filter by cost center
        top: Maximum results to return (default: 100, max: 500)
    """
    today = date.today().isoformat()
    filters = [
        "vacant eq true",
        f"effectiveStartDate le datetime'{today}T23:59:59'",
    ]

    if department:
        filters.append(f"department eq '{sanitize_odata_string(department)}'")
    if location:
        filters.append(f"location eq '{sanitize_odata_string(location)}'")
    if cost_center:
        filters.append(f"costCenter eq '{sanitize_odata_string(cost_center)}'")

    params = {
        "$filter": " and ".join(filters),
        "$select": (
            "code,positionTitle,department,costCenter,jobCode,jobTitle,"
            "company,location,targetFTE,positionCriticality,"
            "effectiveStartDate,createdDateTime,lastModifiedDateTime"
        ),
        "$format": "json",
        "$top": str(top),
        "$orderby": "lastModifiedDateTime desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/Position",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    vacancies = [
        {
            "code": p.get("code"),
            "title": p.get("positionTitle"),
            "department": p.get("department"),
            "cost_center": p.get("costCenter"),
            "job_code": p.get("jobCode"),
            "job_title": p.get("jobTitle"),
            "company": p.get("company"),
            "location": p.get("location"),
            "target_fte": p.get("targetFTE"),
            "criticality": p.get("positionCriticality"),
            "effective_date": p.get("effectiveStartDate"),
            "last_modified": p.get("lastModifiedDateTime"),
        }
        for p in result.get("d", {}).get("results", [])
    ]

    # Count by department for summary
    dept_counts: dict[str, int] = {}
    for v in vacancies:
        dept = v.get("department") or "Unknown"
        dept_counts[dept] = dept_counts.get(dept, 0) + 1

    return {
        "vacant_positions": vacancies,
        "count": len(vacancies),
        "by_department": dept_counts,
        "filters_applied": {
            "department": department or None,
            "location": location or None,
            "cost_center": cost_center or None,
        },
    }


@mcp.tool()
@sf_tool("get_org_chart")
def get_org_chart(
    instance: str,
    position_code: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    max_depth: int = 2,
    direction: str = "down",
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Build org hierarchy from a position showing parent/children with incumbents.

    Traverses the position hierarchy downward (children) or upward (parents) from
    a starting position. Useful for visualizing org structure and reporting lines.

    Args:
        instance: The SuccessFactors instance/company ID
        position_code: The starting position code (e.g., 'POS_001')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        max_depth: How many levels deep to traverse (default: 2, max: 4)
        direction: 'down' for children/reports, 'up' for parent chain (default: 'down')
    """
    max_depth = max(1, min(max_depth, 4))
    if direction not in ("down", "up"):
        return {"error": "Invalid direction: must be 'down' or 'up'"}

    today = date.today().isoformat()

    def _fetch_position(code: str) -> dict | None:
        """Fetch a single position's details."""
        safe_code = sanitize_odata_string(code)
        params = {
            "$filter": (
                f"code eq '{safe_code}' and "
                f"effectiveStartDate le datetime'{today}T23:59:59'"
            ),
            "$select": (
                "code,positionTitle,department,incumbent,vacant,"
                "parentPosition,location,targetFTE"
            ),
            "$format": "json",
            "$top": "1",
            "$orderby": "effectiveStartDate desc",
        }
        result = make_odata_request(
            instance,
            "/odata/v2/Position",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )
        if "error" in result:
            return None
        positions = result.get("d", {}).get("results", [])
        if not positions:
            return None
        p = positions[0]
        return {
            "code": p.get("code"),
            "title": p.get("positionTitle"),
            "department": p.get("department"),
            "incumbent_id": p.get("incumbent"),
            "vacant": p.get("vacant"),
            "location": p.get("location"),
            "target_fte": p.get("targetFTE"),
            "parent_position_code": p.get("parentPosition"),
        }

    def _fetch_children(parent_code: str) -> list[dict]:
        """Fetch child positions of a parent."""
        safe_code = sanitize_odata_string(parent_code)
        params = {
            "$filter": (
                f"parentPosition eq '{safe_code}' and "
                f"effectiveStartDate le datetime'{today}T23:59:59'"
            ),
            "$select": (
                "code,positionTitle,department,incumbent,vacant,"
                "parentPosition,location,targetFTE"
            ),
            "$format": "json",
            "$top": "50",
            "$orderby": "positionTitle asc",
        }
        result = make_odata_request(
            instance,
            "/odata/v2/Position",
            data_center,
            environment,
            auth_user_id,
            auth_password,
            params,
            request_id,
        )
        if "error" in result:
            return []
        return [
            {
                "code": p.get("code"),
                "title": p.get("positionTitle"),
                "department": p.get("department"),
                "incumbent_id": p.get("incumbent"),
                "vacant": p.get("vacant"),
                "location": p.get("location"),
                "target_fte": p.get("targetFTE"),
                "parent_position_code": p.get("parentPosition"),
            }
            for p in result.get("d", {}).get("results", [])
        ]

    # Fetch the root position
    root = _fetch_position(position_code)
    if not root:
        return {
            "error": f"Position '{position_code}' not found",
            "message": "Check the position code and try again.",
        }

    total_api_calls = 1
    total_positions = 1

    if direction == "up":
        # Walk up the parent chain
        chain = [root]
        current = root
        for _ in range(max_depth):
            parent_code = current.get("parent_position_code")
            if not parent_code:
                break
            parent = _fetch_position(parent_code)
            total_api_calls += 1
            if not parent:
                break
            chain.append(parent)
            total_positions += 1
            current = parent

        return {
            "direction": "up",
            "starting_position": position_code,
            "parent_chain": list(reversed(chain)),
            "levels_traversed": len(chain) - 1,
            "total_positions": total_positions,
            "total_api_calls": total_api_calls,
        }

    # Direction: down — BFS traversal
    root["children"] = []
    queue = [(root, 0)]
    visited = {root["code"]}

    while queue:
        node, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        children = _fetch_children(node["code"])
        total_api_calls += 1

        # Cap children per node to avoid runaway queries
        for child in children[:10]:
            child_code = child.get("code")
            if not child_code or child_code in visited:
                continue
            visited.add(child_code)
            total_positions += 1
            child["children"] = []
            node["children"].append(child)
            queue.append((child, depth + 1))

    return {
        "direction": "down",
        "starting_position": position_code,
        "org_tree": root,
        "max_depth": max_depth,
        "total_positions": total_positions,
        "total_api_calls": total_api_calls,
    }
