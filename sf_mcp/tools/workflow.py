"""Workflow & approval tools: pending approvals, workflow history."""

from typing import Any

from sf_mcp.client import make_odata_request
from sf_mcp.decorators import sf_tool
from sf_mcp.dependencies import ApiHost, RequestId, StartTime
from sf_mcp.server import mcp
from sf_mcp.validation import sanitize_odata_string


@mcp.tool()
@sf_tool("get_pending_approvals", max_top=500)
def get_pending_approvals(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    user_id: str = "",
    category: str = "workflow",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    Get pending workflow approval items for a user or globally.

    Shows all pending to-do items that require action, such as workflow approvals
    for hire, termination, transfer, compensation changes, and other HR transactions.
    Essential for admins and managers tracking approval backlogs.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        user_id: Filter to a specific approver's pending items (optional, shows all if empty)
        category: 'workflow' for approval workflows only, 'all' for all to-dos (default: 'workflow')
        top: Maximum results to return (default: 100, max: 500)
    """
    # status eq 2 = active/pending items
    filters = ["status eq '2'"]

    if user_id:
        filters.append(f"userId eq '{sanitize_odata_string(user_id)}'")

    # categoryId 14 = EC workflow, 17 = MDF workflow
    if category == "workflow":
        filters.append("(categoryId eq '14' or categoryId eq '17')")

    params = {
        "$filter": " and ".join(filters),
        "$select": (
            "todoEntryId,todoEntryName,categoryId,categoryLabel,"
            "subjectId,status,completedDateTime,createdDate,dueDate,"
            "linkUrl"
        ),
        "$expand": "wfRequestNav",
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

    pending_items = []
    category_counts: dict[str, int] = {}

    for entry in result.get("d", {}).get("results", []):
        cat_label = entry.get("categoryLabel") or entry.get("categoryId") or "Unknown"
        category_counts[cat_label] = category_counts.get(cat_label, 0) + 1

        item = {
            "todo_entry_id": entry.get("todoEntryId"),
            "subject": entry.get("todoEntryName"),
            "category_id": entry.get("categoryId"),
            "category_label": entry.get("categoryLabel"),
            "subject_user_id": entry.get("subjectId"),
            "status": entry.get("status"),
            "created_date": entry.get("createdDate"),
            "due_date": entry.get("dueDate"),
            "link_url": entry.get("linkUrl"),
        }

        # Extract workflow request details if expanded
        wf_nav = entry.get("wfRequestNav", {})
        if isinstance(wf_nav, dict) and wf_nav.get("wfRequestId"):
            item["workflow"] = {
                "request_id": wf_nav.get("wfRequestId"),
                "status": wf_nav.get("status"),
                "created_date": wf_nav.get("createdDateTime"),
                "last_modified": wf_nav.get("lastModifiedDateTime"),
            }

        pending_items.append(item)

    return {
        "pending_items": pending_items,
        "count": len(pending_items),
        "by_category": category_counts,
        "filters_applied": {
            "user_id": user_id or None,
            "category": category,
        },
    }


@mcp.tool()
@sf_tool("get_workflow_history", max_top=500)
def get_workflow_history(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    wf_request_id: str = "",
    subject_user_id: str = "",
    status: str = "all",
    top: int = 100,
    *,
    request_id: str = RequestId(),
    start_time: float = StartTime(),
    api_host: str = ApiHost(),
) -> dict[str, Any]:
    """
    View the audit trail of approval steps for workflow requests.

    Shows workflow requests with their approval steps, who approved or rejected,
    and when. Useful for auditing approval chains and tracking stuck workflows.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        wf_request_id: Filter to a specific workflow request ID (optional)
        subject_user_id: Filter to workflows for a specific employee (optional)
        status: Filter by status: 'pending', 'approved', 'denied', 'cancelled', or 'all' (default: 'all')
        top: Maximum results to return (default: 100, max: 500)
    """
    if not wf_request_id and not subject_user_id:
        return {
            "error": "At least one of wf_request_id or subject_user_id is required",
            "message": "Provide a workflow request ID or a subject user ID to query workflow history.",
        }

    filters = []
    if wf_request_id:
        filters.append(f"wfRequestId eq {sanitize_odata_string(wf_request_id)}L")
    if subject_user_id:
        filters.append(f"subjectUserId eq '{sanitize_odata_string(subject_user_id)}'")

    status_map = {
        "pending": "PENDING",
        "approved": "APPROVED",
        "denied": "DENIED",
        "cancelled": "CANCELLED",
    }
    if status != "all" and status in status_map:
        filters.append(f"status eq '{status_map[status]}'")

    params = {
        "$filter": " and ".join(filters),
        "$select": (
            "wfRequestId,status,createdDateTime,lastModifiedDateTime,"
            "subjectUserId,description,module"
        ),
        "$expand": "wfRequestStepNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "lastModifiedDateTime desc",
    }

    result = make_odata_request(
        instance,
        "/odata/v2/WfRequest",
        data_center,
        environment,
        auth_user_id,
        auth_password,
        params,
        request_id,
    )

    if "error" in result:
        return result

    workflows = []
    status_counts: dict[str, int] = {}

    for entry in result.get("d", {}).get("results", []):
        wf_status = entry.get("status") or "Unknown"
        status_counts[wf_status] = status_counts.get(wf_status, 0) + 1

        workflow = {
            "request_id": entry.get("wfRequestId"),
            "status": wf_status,
            "subject_user_id": entry.get("subjectUserId"),
            "description": entry.get("description"),
            "module": entry.get("module"),
            "created_date": entry.get("createdDateTime"),
            "last_modified": entry.get("lastModifiedDateTime"),
        }

        # Extract approval steps
        steps_nav = entry.get("wfRequestStepNav", {})
        if isinstance(steps_nav, dict) and "results" in steps_nav:
            workflow["steps"] = [
                {
                    "step_id": step.get("wfRequestStepId"),
                    "step_order": step.get("stepOrder"),
                    "status": step.get("status"),
                    "approver_id": step.get("ownerId"),
                    "approver_type": step.get("ownerType"),
                    "role": step.get("role"),
                    "action_date": step.get("actionDateTime"),
                    "created_date": step.get("createdDateTime"),
                }
                for step in steps_nav["results"]
            ]
        else:
            workflow["steps"] = []

        workflows.append(workflow)

    return {
        "workflows": workflows,
        "count": len(workflows),
        "by_status": status_counts,
        "filters_applied": {
            "wf_request_id": wf_request_id or None,
            "subject_user_id": subject_user_id or None,
            "status": status,
        },
    }
