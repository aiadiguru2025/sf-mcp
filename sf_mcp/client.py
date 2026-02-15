"""SuccessFactors OData API client with audit logging."""

import time
import uuid
from typing import Any

import requests

from sf_mcp.config import DEFAULT_TIMEOUT, get_api_host
from sf_mcp.logging_config import audit_log
from sf_mcp.auth import resolve_credentials
from sf_mcp.xml_utils import xml_to_dict


def make_odata_request(
    instance: str,
    endpoint: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    params: dict | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    Make an OData API request to SuccessFactors (JSON format).

    Args:
        instance: The SuccessFactors instance/company ID
        endpoint: The OData endpoint path (e.g., "/odata/v2/RBPRole")
        data_center: SAP data center code (e.g., 'DC55', 'DC10')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        params: Optional query parameters
        request_id: Optional request ID for tracing

    Returns:
        dict with either the JSON response data or an error dict
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    try:
        api_host = get_api_host(data_center, environment)
    except ValueError as e:
        audit_log(
            event_type="validation_error",
            instance=instance,
            status="failure",
            details={"reason": "invalid_data_center_or_environment", "error": str(e)},
            request_id=req_id,
        )
        return {"error": str(e)}

    user_id, password = resolve_credentials(auth_user_id, auth_password)

    if not user_id or not password:
        audit_log(
            event_type="authentication",
            instance=instance,
            status="failure",
            details={"reason": "missing_credentials", "endpoint": endpoint},
            request_id=req_id,
        )
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}{endpoint}"
    credentials = (username, password)
    headers = {"Accept": "application/json"}

    try:
        response = requests.get(url, auth=credentials, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        duration_ms = (time.time() - start_time) * 1000

        if response.status_code == 401:
            audit_log(
                event_type="authentication",
                instance=instance,
                user_id=user_id,
                status="failure",
                details={"reason": "invalid_credentials", "endpoint": endpoint, "http_status": 401},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": f"HTTP {response.status_code}", "message": "Authentication failed. Check credentials."}

        if response.status_code != 200:
            audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"endpoint": endpoint, "http_status": response.status_code},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": f"HTTP {response.status_code}", "message": response.text[:500]}

        if not response.text.strip():
            audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"reason": "empty_response", "endpoint": endpoint},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": "Empty response from API"}

        audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="success",
            details={"endpoint": endpoint, "http_status": 200},
            request_id=req_id,
            duration_ms=duration_ms,
        )

        return response.json()
    except requests.exceptions.RequestException as e:
        duration_ms = (time.time() - start_time) * 1000
        audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="error",
            details={"reason": "request_exception", "endpoint": endpoint, "error": str(e)},
            request_id=req_id,
            duration_ms=duration_ms,
        )
        return {"error": f"Request failed: {str(e)}"}
    except ValueError as e:
        duration_ms = (time.time() - start_time) * 1000
        audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="error",
            details={"reason": "json_parse_error", "endpoint": endpoint},
            request_id=req_id,
            duration_ms=duration_ms,
        )
        return {"error": f"JSON parse error: {str(e)}", "response_preview": response.text[:500]}


def make_metadata_request(
    instance: str,
    entity: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    request_id: str | None = None,
) -> dict | None:
    """
    Fetch XML $metadata for an entity and return parsed dict.

    Used by get_configuration and compare_configurations.
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    try:
        api_host = get_api_host(data_center, environment)
    except ValueError as e:
        return {"error": str(e)}

    user_id, password = resolve_credentials(auth_user_id, auth_password)
    if not user_id or not password:
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}/odata/v2/{entity}/$metadata"

    try:
        response = requests.get(url, auth=(username, password), timeout=DEFAULT_TIMEOUT)
        duration_ms = (time.time() - start_time) * 1000

        if response.status_code == 401:
            audit_log(
                event_type="authentication",
                instance=instance,
                user_id=user_id,
                status="failure",
                details={"reason": "invalid_credentials", "http_status": 401},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": "HTTP 401", "message": "Authentication failed. Check credentials."}

        if response.status_code != 200:
            audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"http_status": response.status_code, "entity": entity},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": f"HTTP {response.status_code}", "message": "Request failed. Check instance and entity parameters."}

        if not response.text.strip():
            return {"error": "Empty response from API"}

        return xml_to_dict(response.text.encode("UTF-8"))
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"XML parse error: {str(e)}"}


def make_service_doc_request(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    Fetch the OData service document (entity list).

    Used by list_entities.
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    try:
        api_host = get_api_host(data_center, environment)
    except ValueError as e:
        return {"error": str(e)}

    user_id, password = resolve_credentials(auth_user_id, auth_password)
    if not user_id or not password:
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}/odata/v2/"

    try:
        response = requests.get(
            url,
            auth=(username, password),
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
        duration_ms = (time.time() - start_time) * 1000

        if response.status_code == 401:
            audit_log(
                event_type="authentication",
                instance=instance,
                status="failure",
                details={"reason": "invalid_credentials", "http_status": 401},
                request_id=req_id,
                duration_ms=duration_ms,
            )
            return {"error": "HTTP 401", "message": "Authentication failed. Check credentials."}

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "message": response.text[:500]}

        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
