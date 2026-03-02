"""SuccessFactors OData API client with audit logging, rate limiting, and caching."""

import threading
import time
import uuid
from typing import Any

import requests

from sf_mcp.auth import resolve_credentials
from sf_mcp.cache import get_cache
from sf_mcp.config import (
    DEFAULT_MAX_PAGES,
    DEFAULT_TIMEOUT,
    DEFAULT_TOP,
    MAX_PAGINATION_PAGES,
    MAX_TOP_QUERY,
    RATE_LIMIT_MAX_RETRIES,
    RATE_LIMIT_RETRY_AFTER_SECONDS,
    get_api_host,
)
from sf_mcp.logging_config import audit_log
from sf_mcp.rate_limiter import RateLimitExceeded, get_rate_limiter
from sf_mcp.xml_utils import xml_to_dict

# Module-level session singleton for connection pooling
_session: requests.Session | None = None
_session_lock = threading.Lock()


def get_session() -> requests.Session:
    """Get or create the global requests.Session singleton for connection pooling."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                _session = requests.Session()
    return _session


def _execute_with_rate_limit(
    instance: str,
    user_id: str,
    req_id: str,
    endpoint: str,
    request_fn,
) -> requests.Response | dict:
    """Execute an HTTP request with rate limiting and 429 retry logic.

    Returns either a requests.Response on success, or an error dict.
    """
    try:
        get_rate_limiter().check_and_record(instance, request_id=req_id)
    except RateLimitExceeded as e:
        return {"error": str(e), "retry_after_seconds": RATE_LIMIT_RETRY_AFTER_SECONDS}

    retries = 0
    while True:
        response = request_fn()
        if response.status_code == 429:
            retries += 1
            retry_after = int(response.headers.get("Retry-After", RATE_LIMIT_RETRY_AFTER_SECONDS))
            if retries > RATE_LIMIT_MAX_RETRIES:
                audit_log(
                    event_type="api_request",
                    instance=instance,
                    user_id=user_id,
                    status="rate_limited",
                    details={"endpoint": endpoint, "http_status": 429, "retries_exhausted": True},
                    request_id=req_id,
                )
                return {
                    "error": "API rate limit exceeded (HTTP 429). Retries exhausted.",
                    "retry_after_seconds": retry_after,
                }
            audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="rate_limited",
                details={"endpoint": endpoint, "retry_attempt": retries, "retry_after": retry_after},
                request_id=req_id,
            )
            time.sleep(retry_after)
            continue
        return response


def make_odata_request(
    instance: str,
    endpoint: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    params: dict | None = None,
    request_id: str | None = None,
    *,
    cache_category: str | None = None,
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
        cache_category: Optional cache category for TTL-based caching

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

    # Check cache before making HTTP call
    if cache_category:
        cached = get_cache().get(instance, endpoint, params, request_id=req_id)
        if cached is not None:
            return cached

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
        response = _execute_with_rate_limit(
            instance,
            user_id,
            req_id,
            endpoint,
            lambda: get_session().get(url, auth=credentials, headers=headers, params=params, timeout=DEFAULT_TIMEOUT),
        )

        # Rate limiter returned an error dict
        if isinstance(response, dict):
            return response

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

        data = response.json()

        # Store in cache if category specified
        if cache_category:
            get_cache().put(instance, endpoint, params, data, category=cache_category, request_id=req_id)

        return data
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

    Results are automatically cached (metadata changes infrequently).
    Used by get_configuration and compare_configurations.
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    try:
        api_host = get_api_host(data_center, environment)
    except ValueError as e:
        return {"error": str(e)}

    # Check cache (metadata is always cached)
    cache_endpoint = f"/odata/v2/{entity}/$metadata"
    cached = get_cache().get(instance, cache_endpoint, None, request_id=req_id)
    if cached is not None:
        return cached

    user_id, password = resolve_credentials(auth_user_id, auth_password)
    if not user_id or not password:
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}{cache_endpoint}"

    try:
        response = _execute_with_rate_limit(
            instance,
            user_id,
            req_id,
            cache_endpoint,
            lambda: get_session().get(url, auth=(username, password), timeout=DEFAULT_TIMEOUT),
        )

        if isinstance(response, dict):
            return response

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
            return {
                "error": f"HTTP {response.status_code}",
                "message": "Request failed. Check instance and entity parameters.",
            }

        if not response.text.strip():
            return {"error": "Empty response from API"}

        parsed = xml_to_dict(response.text.encode("UTF-8"))
        get_cache().put(instance, cache_endpoint, None, parsed, category="metadata", request_id=req_id)
        return parsed
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

    Results are automatically cached (entity list changes infrequently).
    Used by list_entities.
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    try:
        api_host = get_api_host(data_center, environment)
    except ValueError as e:
        return {"error": str(e)}

    # Check cache (service doc is always cached)
    cache_endpoint = "/odata/v2/"
    cached = get_cache().get(instance, cache_endpoint, None, request_id=req_id)
    if cached is not None:
        return cached

    user_id, password = resolve_credentials(auth_user_id, auth_password)
    if not user_id or not password:
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}{cache_endpoint}"

    try:
        response = _execute_with_rate_limit(
            instance,
            user_id,
            req_id,
            cache_endpoint,
            lambda: get_session().get(
                url,
                auth=(username, password),
                headers={"Accept": "application/json"},
                timeout=DEFAULT_TIMEOUT,
            ),
        )

        if isinstance(response, dict):
            return response

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

        data = response.json()
        get_cache().put(instance, cache_endpoint, None, data, category="service_doc", request_id=req_id)
        return data
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}


def make_paginated_odata_request(
    instance: str,
    endpoint: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    params: dict | None = None,
    request_id: str | None = None,
    page_size: int = DEFAULT_TOP,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> dict[str, Any]:
    """
    Fetch all pages of an OData query by automatically following pagination.

    Repeatedly calls make_odata_request with increasing $skip until no more
    results or max_pages is reached.

    Args:
        instance: The SuccessFactors instance/company ID
        endpoint: The OData endpoint path
        data_center: SAP data center code
        environment: Environment type
        auth_user_id: Authentication user ID
        auth_password: Authentication password
        params: Base query parameters ($top/$skip will be managed automatically)
        request_id: Request ID for tracing
        page_size: Records per page (default 100, max 1000)
        max_pages: Maximum pages to fetch (default 10, max 50)

    Returns:
        dict with accumulated results, total count, and pagination metadata
    """
    req_id = request_id or str(uuid.uuid4())[:8]

    page_size = max(1, min(page_size, MAX_TOP_QUERY))
    max_pages = max(1, min(max_pages, MAX_PAGINATION_PAGES))

    all_results: list[dict] = []
    current_skip = 0
    pages_fetched = 0
    total_api_calls = 0

    base_params = dict(params) if params else {}
    # Remove any existing $top/$skip from base_params since we manage them
    base_params.pop("$top", None)
    base_params.pop("$skip", None)

    while pages_fetched < max_pages:
        page_params = dict(base_params)
        page_params["$top"] = str(page_size)
        if current_skip > 0:
            page_params["$skip"] = str(current_skip)

        audit_log(
            event_type="pagination",
            instance=instance,
            status="in_progress",
            details={
                "endpoint": endpoint,
                "page": pages_fetched + 1,
                "skip": current_skip,
                "page_size": page_size,
            },
            request_id=req_id,
        )

        result = make_odata_request(
            instance,
            endpoint,
            data_center,
            environment,
            auth_user_id,
            auth_password,
            page_params,
            req_id,
        )
        total_api_calls += 1

        if "error" in result:
            if all_results:
                return {
                    "results": all_results,
                    "count": len(all_results),
                    "pagination": {
                        "pages_fetched": pages_fetched,
                        "total_api_calls": total_api_calls,
                        "complete": False,
                        "has_more": True,
                        "stopped_reason": "error_on_page",
                        "error_on_page": pages_fetched + 1,
                        "error": result["error"],
                    },
                }
            return result

        # Extract results from this page
        page_results: list[dict] = []
        if "d" in result:
            d = result["d"]
            if "results" in d:
                page_results = d["results"]
            elif d:
                page_results = [d]

        all_results.extend(page_results)
        pages_fetched += 1

        audit_log(
            event_type="pagination",
            instance=instance,
            status="page_complete",
            details={
                "endpoint": endpoint,
                "page": pages_fetched,
                "page_records": len(page_results),
                "total_records_so_far": len(all_results),
            },
            request_id=req_id,
        )

        # Fewer results than requested means no more data
        if len(page_results) < page_size:
            break

        current_skip += page_size

    is_complete = len(page_results) < page_size if pages_fetched > 0 else True

    audit_log(
        event_type="pagination",
        instance=instance,
        status="complete",
        details={
            "endpoint": endpoint,
            "total_pages": pages_fetched,
            "total_records": len(all_results),
            "complete": is_complete,
        },
        request_id=req_id,
    )

    return {
        "results": all_results,
        "count": len(all_results),
        "pagination": {
            "pages_fetched": pages_fetched,
            "page_size": page_size,
            "total_api_calls": total_api_calls,
            "complete": is_complete,
            "has_more": not is_complete,
        },
    }
