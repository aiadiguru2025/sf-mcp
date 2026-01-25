import os
import re
import asyncio
import logging
import json
import time
import uuid
from typing import Any
from dotenv import load_dotenv
from fastmcp import FastMCP
import requests
import defusedxml.ElementTree as DefusedET

# Load environment variables from .env file
load_dotenv()


# =============================================================================
# SECURITY: Structured Logging Configuration (Cloud Logging compatible)
# =============================================================================

class CloudLoggingFormatter(logging.Formatter):
    """JSON formatter compatible with Google Cloud Logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }

        # Add extra fields if present
        if hasattr(record, "audit_data"):
            log_entry["audit"] = record.audit_data
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "tool_name"):
            log_entry["tool_name"] = record.tool_name
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def _setup_logging() -> logging.Logger:
    """Configure structured logging for the application."""
    logger = logging.getLogger("sf-mcp")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(CloudLoggingFormatter())
        logger.addHandler(handler)

    return logger


# Initialize logger
logger = _setup_logging()


def _mask_sensitive_data(data: dict) -> dict:
    """Mask sensitive fields in data for logging."""
    sensitive_fields = {"auth_password", "password", "SF_PASSWORD", "credentials"}
    masked = {}
    for key, value in data.items():
        if key.lower() in {f.lower() for f in sensitive_fields}:
            masked[key] = "***MASKED***" if value else None
        elif isinstance(value, dict):
            masked[key] = _mask_sensitive_data(value)
        else:
            masked[key] = value
    return masked


def _audit_log(
    event_type: str,
    tool_name: str | None = None,
    instance: str | None = None,
    user_id: str | None = None,
    status: str = "success",
    details: dict | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None
) -> None:
    """
    Log an audit event with structured data.

    Args:
        event_type: Type of event (tool_invocation, authentication, validation_error, api_request)
        tool_name: Name of the MCP tool being called
        instance: SuccessFactors instance ID
        user_id: User ID making the request (masked for auth events)
        status: Event status (success, failure, error)
        details: Additional event details (sensitive data will be masked)
        request_id: Unique request identifier for tracing
        duration_ms: Request duration in milliseconds
    """
    audit_data = {
        "event_type": event_type,
        "status": status,
        "instance": instance,
    }

    if tool_name:
        audit_data["tool_name"] = tool_name
    if user_id:
        # Only log first 4 chars of user ID for privacy
        audit_data["user_id_prefix"] = user_id[:4] + "***" if len(user_id) > 4 else "***"
    if details:
        audit_data["details"] = _mask_sensitive_data(details)

    # Create log record with extra fields
    extra = {
        "audit_data": audit_data,
        "request_id": request_id or str(uuid.uuid4())[:8],
    }
    if tool_name:
        extra["tool_name"] = tool_name
    if duration_ms is not None:
        extra["duration_ms"] = round(duration_ms, 2)

    level = logging.INFO if status == "success" else logging.WARNING
    logger.log(level, f"AUDIT: {event_type} - {status}", extra=extra)


# =============================================================================
# SECURITY: Input Validation Functions
# =============================================================================

# Patterns for validating OData input parameters
SAFE_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')
SAFE_IDS_PATTERN = re.compile(r'^[a-zA-Z0-9_\-,]+$')
SAFE_LOCALE_PATTERN = re.compile(r'^[a-zA-Z]{2}(-[a-zA-Z]{2})?$')
VALID_ENVIRONMENTS = {"preview", "production"}

# Pattern for OData entity paths (e.g., "User", "User('admin')", "EmpEmployment")
SAFE_ENTITY_PATH_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\('[a-zA-Z0-9_\-]+'\))?$")

# Pattern for OData $select fields (comma-separated field names)
SAFE_SELECT_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_,/]*$')

# Pattern for OData $orderby (field names with optional asc/desc)
SAFE_ORDERBY_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_,/ ]*(asc|desc)?$', re.IGNORECASE)

# Pattern for OData $expand (navigation properties)
SAFE_EXPAND_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_,/]*$')

# Dangerous OData filter keywords that could indicate injection attempts
ODATA_FILTER_BLOCKLIST = {
    '$batch', '$metadata', '$value', '$count', '$ref', '$links',
    'javascript:', 'script>', '<script', 'onerror', 'onload'
}


def _validate_identifier(value: str, field_name: str) -> str:
    """Validate that a value contains only safe identifier characters."""
    if not value or not SAFE_IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, underscores, and hyphens")
    return value


def _validate_ids(value: str, field_name: str) -> str:
    """Validate comma-separated IDs contain only safe characters."""
    if not value or not SAFE_IDS_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, underscores, hyphens, and commas")
    return value


def _validate_locale(value: str) -> str:
    """Validate locale format (e.g., 'en-US', 'de')."""
    if not SAFE_LOCALE_PATTERN.match(value):
        raise ValueError(f"Invalid locale format: {value}. Expected format like 'en-US' or 'en'")
    return value


def _validate_environment(value: str) -> str:
    """Validate environment is one of the allowed values."""
    if value not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid environment: {value}. Must be one of: {VALID_ENVIRONMENTS}")
    return value


def _sanitize_odata_string(value: str) -> str:
    """Sanitize a string value for use in OData queries by escaping single quotes."""
    # Escape single quotes by doubling them (OData standard)
    return value.replace("'", "''")


def _validate_entity_path(value: str) -> str:
    """Validate OData entity path (e.g., 'User', 'User('admin')')."""
    if not value or not SAFE_ENTITY_PATH_PATTERN.match(value):
        raise ValueError(f"Invalid entity: must be a valid OData entity name (e.g., 'User', 'Position')")
    return value


def _validate_select(value: str) -> str:
    """Validate OData $select parameter."""
    if not SAFE_SELECT_PATTERN.match(value):
        raise ValueError("Invalid select: must contain only valid field names separated by commas")
    return value


def _validate_orderby(value: str) -> str:
    """Validate OData $orderby parameter."""
    if not SAFE_ORDERBY_PATTERN.match(value):
        raise ValueError("Invalid orderby: must contain valid field names with optional 'asc' or 'desc'")
    return value


def _validate_expand(value: str) -> str:
    """Validate OData $expand parameter."""
    if not SAFE_EXPAND_PATTERN.match(value):
        raise ValueError("Invalid expand: must contain valid navigation property names")
    return value


def _validate_odata_filter(value: str) -> str:
    """
    Validate and sanitize OData $filter parameter.

    Checks for potentially dangerous patterns while allowing legitimate filter expressions.
    """
    # Check for blocklisted keywords
    value_lower = value.lower()
    for blocked in ODATA_FILTER_BLOCKLIST:
        if blocked in value_lower:
            raise ValueError(f"Invalid filter: contains blocked keyword '{blocked}'")

    # Check for excessive length (potential DoS)
    if len(value) > 2000:
        raise ValueError("Invalid filter: expression too long (max 2000 characters)")

    # Sanitize quotes in string literals
    return value


def _xml_to_dict(xml_content: bytes) -> dict:
    """
    Safely parse XML to dictionary using defusedxml to prevent XXE attacks.

    Args:
        xml_content: XML content as bytes

    Returns:
        Dictionary representation of the XML
    """
    def element_to_dict(element):
        """Recursively convert an XML element to a dictionary."""
        result = {}

        # Add attributes with @ prefix
        if element.attrib:
            for key, value in element.attrib.items():
                result[f"@{key}"] = value

        # Process child elements
        children = list(element)
        if children:
            child_dict = {}
            for child in children:
                child_data = element_to_dict(child)
                tag = child.tag
                # Handle namespace in tag
                if '}' in tag:
                    tag = tag.split('}')[1]

                if tag in child_dict:
                    # Convert to list if multiple children with same tag
                    if not isinstance(child_dict[tag], list):
                        child_dict[tag] = [child_dict[tag]]
                    child_dict[tag].append(child_data if child_data else child.text)
                else:
                    child_dict[tag] = child_data if child_data else child.text
            result.update(child_dict)
        elif element.text and element.text.strip():
            # If no children but has text content
            if result:  # Has attributes
                result['#text'] = element.text.strip()
            else:
                return element.text.strip()

        return result if result else None

    # Parse with defusedxml (prevents XXE, billion laughs, etc.)
    root = DefusedET.fromstring(xml_content)

    # Get root tag (handle namespace)
    root_tag = root.tag
    if '}' in root_tag:
        root_tag = root_tag.split('}')[1]

    return {root_tag: element_to_dict(root)}


# API host configuration for different environments
SF_API_HOSTS = {
    "production": "api55.sapsf.eu",
    "preview": "api55preview.sapsf.eu"
}


def _get_api_host(environment: str = "preview") -> str:
    """Return the appropriate API host based on environment."""
    return SF_API_HOSTS.get(environment, SF_API_HOSTS["preview"])


def _resolve_credentials(
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> tuple[str | None, str | None]:
    """Resolve credentials from parameters or fall back to environment variables."""
    resolved_user_id = auth_user_id if auth_user_id else os.environ.get("SF_USER_ID")
    resolved_password = auth_password if auth_password else os.environ.get("SF_PASSWORD")
    return resolved_user_id, resolved_password


#Init Server
mcp = FastMCP("SFgetConfig")


def _make_sf_odata_request(
    instance: str,
    endpoint: str,
    params: dict | None = None,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None,
    request_id: str | None = None
) -> dict[str, Any]:
    """
    Make an OData API request to SuccessFactors (JSON format).

    Args:
        instance: The SuccessFactors instance/company ID
        endpoint: The OData endpoint path (e.g., "/odata/v2/RBPRole")
        params: Optional query parameters
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)
        request_id: Optional request ID for tracing

    Returns:
        dict with either the JSON response data or an error dict
    """
    req_id = request_id or str(uuid.uuid4())[:8]
    start_time = time.time()

    user_id, password = _resolve_credentials(auth_user_id, auth_password)
    api_host = _get_api_host(environment)

    if not user_id or not password:
        _audit_log(
            event_type="authentication",
            instance=instance,
            status="failure",
            details={"reason": "missing_credentials", "endpoint": endpoint},
            request_id=req_id
        )
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters, or set SF_USER_ID and SF_PASSWORD environment variables."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}{endpoint}"
    credentials = (username, password)
    headers = {"Accept": "application/json"}

    try:
        response = requests.get(url, auth=credentials, headers=headers, params=params, timeout=30)
        duration_ms = (time.time() - start_time) * 1000

        if response.status_code == 401:
            _audit_log(
                event_type="authentication",
                instance=instance,
                user_id=user_id,
                status="failure",
                details={"reason": "invalid_credentials", "endpoint": endpoint, "http_status": 401},
                request_id=req_id,
                duration_ms=duration_ms
            )
            return {
                "error": f"HTTP {response.status_code}",
                "message": "Authentication failed. Check credentials."
            }

        if response.status_code != 200:
            _audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"endpoint": endpoint, "http_status": response.status_code},
                request_id=req_id,
                duration_ms=duration_ms
            )
            return {
                "error": f"HTTP {response.status_code}",
                "message": response.text[:500]
            }

        if not response.text.strip():
            _audit_log(
                event_type="api_request",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"reason": "empty_response", "endpoint": endpoint},
                request_id=req_id,
                duration_ms=duration_ms
            )
            return {"error": "Empty response from API"}

        # Log successful API request
        _audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="success",
            details={"endpoint": endpoint, "http_status": 200},
            request_id=req_id,
            duration_ms=duration_ms
        )

        return response.json()
    except requests.exceptions.RequestException as e:
        duration_ms = (time.time() - start_time) * 1000
        _audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="error",
            details={"reason": "request_exception", "endpoint": endpoint, "error": str(e)},
            request_id=req_id,
            duration_ms=duration_ms
        )
        return {"error": f"Request failed: {str(e)}"}
    except ValueError as e:
        duration_ms = (time.time() - start_time) * 1000
        _audit_log(
            event_type="api_request",
            instance=instance,
            user_id=user_id,
            status="error",
            details={"reason": "json_parse_error", "endpoint": endpoint},
            request_id=req_id,
            duration_ms=duration_ms
        )
        return {"error": f"JSON parse error: {str(e)}", "response_preview": response.text[:500]}

@mcp.tool()
def get_configuration(
    instance: str,
    entity: str,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get Configuration metadata details for the entity within the instance.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: The OData entity name (e.g., "User", "EmpEmployment")
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_configuration",
        instance=instance,
        status="started",
        details={"entity": entity, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(entity, "entity")
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_configuration",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    user_id, password = _resolve_credentials(auth_user_id, auth_password)
    api_host = _get_api_host(environment)

    if not user_id or not password:
        _audit_log(
            event_type="authentication",
            tool_name="get_configuration",
            instance=instance,
            status="failure",
            details={"reason": "missing_credentials"},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters, or set SF_USER_ID and SF_PASSWORD environment variables."}

    username = f"{user_id}@{instance}"
    apiUrl = f"https://{api_host}/odata/v2/{entity}/$metadata"
    credentials = (username, password)

    try:
        meta_response = requests.get(apiUrl, auth=credentials, timeout=30)
        duration_ms = (time.time() - start_time) * 1000

        # Check if request was successful
        if meta_response.status_code == 401:
            _audit_log(
                event_type="authentication",
                tool_name="get_configuration",
                instance=instance,
                user_id=user_id,
                status="failure",
                details={"reason": "invalid_credentials", "http_status": 401},
                request_id=request_id,
                duration_ms=duration_ms
            )
            return {"error": "HTTP 401", "message": "Authentication failed. Check credentials."}

        if meta_response.status_code != 200:
            _audit_log(
                event_type="tool_invocation",
                tool_name="get_configuration",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"http_status": meta_response.status_code},
                request_id=request_id,
                duration_ms=duration_ms
            )
            return {
                "error": f"HTTP {meta_response.status_code}",
                "message": "Request failed. Check instance and entity parameters."
            }

        # Check if response is empty
        if not meta_response.text.strip():
            _audit_log(
                event_type="tool_invocation",
                tool_name="get_configuration",
                instance=instance,
                user_id=user_id,
                status="error",
                details={"reason": "empty_response"},
                request_id=request_id,
                duration_ms=duration_ms
            )
            return {"error": "Empty response from API"}

        # Try to parse XML safely (prevents XXE attacks)
        meta_json = _xml_to_dict(meta_response.text.encode("UTF-8"))

        _audit_log(
            event_type="tool_invocation",
            tool_name="get_configuration",
            instance=instance,
            user_id=user_id,
            status="success",
            details={"entity": entity},
            request_id=request_id,
            duration_ms=duration_ms
        )

        return meta_json
    except requests.exceptions.RequestException as e:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_configuration",
            instance=instance,
            status="error",
            details={"reason": "request_exception", "error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_configuration",
            instance=instance,
            status="error",
            details={"reason": "xml_parse_error", "error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": f"XML parse error: {str(e)}"}


@mcp.tool()
def get_rbp_roles(
    instance: str,
    include_description: bool = False,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all RBP (Role-Based Permission) roles in the SuccessFactors instance.

    Args:
        instance: The SuccessFactors instance/company ID
        include_description: If True, includes role descriptions
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing list of roles with roleId, roleName, userType, lastModifiedDate
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_rbp_roles",
        instance=instance,
        status="started",
        details={"include_description": include_description, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_rbp_roles",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    select_fields = "roleId,roleName,userType,lastModifiedDate"
    if include_description:
        select_fields += ",roleDesc"

    params = {"$select": select_fields, "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/RBPRole", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_rbp_roles",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Extract results from OData response
    if "d" in result and "results" in result["d"]:
        role_count = len(result["d"]["results"])
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_rbp_roles",
            instance=instance,
            status="success",
            details={"roles_returned": role_count},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"roles": result["d"]["results"], "count": role_count}

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_rbp_roles",
        instance=instance,
        status="success",
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )
    return result


@mcp.tool()
def get_dynamic_groups(
    instance: str,
    group_type: str | None = None,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get dynamic groups (permission groups) used in RBP rules.

    Args:
        instance: The SuccessFactors instance/company ID
        group_type: Optional filter for group type
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing list of dynamic groups
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_dynamic_groups",
        instance=instance,
        status="started",
        details={"group_type": group_type, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_environment(environment)
        if group_type:
            _validate_identifier(group_type, "group_type")
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_dynamic_groups",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    params = {"$format": "json"}
    if group_type:
        # Sanitize to prevent OData injection
        safe_group_type = _sanitize_odata_string(group_type)
        params["$filter"] = f"groupType eq '{safe_group_type}'"

    result = _make_sf_odata_request(instance, "/odata/v2/DynamicGroup", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_dynamic_groups",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Extract results from OData response
    if "d" in result and "results" in result["d"]:
        group_count = len(result["d"]["results"])
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_dynamic_groups",
            instance=instance,
            status="success",
            details={"groups_returned": group_count},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"groups": result["d"]["results"], "count": group_count}

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_dynamic_groups",
        instance=instance,
        status="success",
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )
    return result


@mcp.tool()
def get_role_permissions(
    instance: str,
    role_ids: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all permissions assigned to one or more RBP roles.

    Args:
        instance: The SuccessFactors instance/company ID
        role_ids: Role ID(s) - single ID ("10") or comma-separated ("10,20,30")
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing role details and permissions
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_permissions",
        instance=instance,
        status="started",
        details={"role_ids": role_ids, "locale": locale, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(role_ids, "role_ids")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_role_permissions",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Sanitize role_ids for OData query
    safe_role_ids = _sanitize_odata_string(role_ids)
    params = {"locale": locale, "roleIds": f"'{safe_role_ids}'", "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/getRolesPermissions", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_role_permissions",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_permissions",
        instance=instance,
        status="success",
        details={"role_ids": role_ids},
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )
    return {"role_ids": role_ids, "permissions": result}


@mcp.tool()
def get_user_permissions(
    instance: str,
    user_ids: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all permissions for one or more users based on their assigned roles.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: User ID(s) - single ID ("admin") or comma-separated ("admin,user2,user3")
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing the users' effective permissions from all assigned roles
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_user_permissions",
        instance=instance,
        status="started",
        details={"user_ids_count": len(user_ids.split(",")), "locale": locale, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(user_ids, "user_ids")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_user_permissions",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Sanitize user_ids for OData query
    safe_user_ids = _sanitize_odata_string(user_ids)
    params = {"locale": locale, "userIds": f"'{safe_user_ids}'", "$format": "json"}
    result = _make_sf_odata_request(instance, "/odata/v2/getUsersPermissions", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_user_permissions",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_user_permissions",
        instance=instance,
        status="success",
        details={"user_ids_count": len(user_ids.split(","))},
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )
    return {"user_ids": user_ids, "permissions": result}


@mcp.tool()
def get_permission_metadata(
    instance: str,
    locale: str = "en-US",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get permission metadata mapping UI labels to permission types and values.

    This API helps map the UI text to the permission type and permission string value,
    which are needed for the checkUserPermission API.

    Args:
        instance: The SuccessFactors instance/company ID
        locale: Locale for permission labels (default: en-US)
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing permission metadata with field-id, perm-type, and permission-string-value
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_permission_metadata",
        instance=instance,
        status="started",
        details={"locale": locale, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_locale(locale)
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_permission_metadata",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    params = {"locale": locale}
    result = _make_sf_odata_request(instance, "/odata/v2/getPermissionMetadata", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_permission_metadata",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
    else:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_permission_metadata",
            instance=instance,
            status="success",
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )

    return result


@mcp.tool()
def check_user_permission(
    instance: str,
    access_user_id: str,
    target_user_id: str,
    perm_type: str,
    perm_string_value: str,
    perm_long_value: str = "-1L",
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Check if a user has a specific permission for a target user.

    Args:
        instance: The SuccessFactors instance/company ID
        access_user_id: The user making the permission check
        target_user_id: The user whose data access is being verified
        perm_type: Permission category (e.g., "EmployeeFilesViews_type")
        perm_string_value: Permission identifier (e.g., "$_payrollIntegration_view")
        perm_long_value: Long value representation (default: "-1L")
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication (falls back to SF_USER_ID env var)
        auth_password: Optional SF password for authentication (falls back to SF_PASSWORD env var)

    Returns:
        dict containing boolean permission status (true/false)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="check_user_permission",
        instance=instance,
        status="started",
        details={
            "access_user_id": access_user_id,
            "target_user_id": target_user_id,
            "perm_type": perm_type,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(access_user_id, "access_user_id")
        _validate_identifier(target_user_id, "target_user_id")
        _validate_environment(environment)
        # perm_type and perm_string_value can have special chars like $ and _, so we sanitize instead
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="check_user_permission",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Sanitize all string values for OData query to prevent injection
    params = {
        "accessUserId": f"'{_sanitize_odata_string(access_user_id)}'",
        "targetUserId": f"'{_sanitize_odata_string(target_user_id)}'",
        "permType": f"'{_sanitize_odata_string(perm_type)}'",
        "permStringValue": f"'{_sanitize_odata_string(perm_string_value)}'",
        "permLongValue": _sanitize_odata_string(perm_long_value),
        "$format": "json"
    }
    result = _make_sf_odata_request(instance, "/odata/v2/checkUserPermission", params, environment, auth_user_id, auth_password, request_id)

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="check_user_permission",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
    else:
        _audit_log(
            event_type="tool_invocation",
            tool_name="check_user_permission",
            instance=instance,
            status="success",
            details={
                "access_user_id": access_user_id,
                "target_user_id": target_user_id,
                "perm_type": perm_type
            },
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )

    return result


@mcp.tool()
def query_odata(
    instance: str,
    entity: str,
    select: str | None = None,
    filter: str | None = None,
    expand: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Execute a flexible OData query against any SuccessFactors entity.

    This is a powerful generic query tool that enables querying any OData entity
    while maintaining security controls and audit logging.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: OData entity name (e.g., "User", "Position", "EmpEmployment")
                Can include key for single record: "User('admin')"
        select: Fields to return, comma-separated (e.g., "userId,firstName,lastName")
        filter: OData filter expression (e.g., "status eq 'active'")
        expand: Navigation properties to expand (e.g., "empInfo,jobInfoNav")
        top: Maximum records to return (default 100, max 1000)
        skip: Number of records to skip for pagination (default 0)
        orderby: Sort expression (e.g., "lastName asc" or "hireDate desc")
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication
        auth_password: Optional SF password for authentication

    Returns:
        dict containing query results or error information

    Examples:
        - Get active users: entity="User", filter="status eq 'active'", select="userId,firstName,lastName"
        - Get single user: entity="User('admin')", expand="empInfo"
        - Get positions: entity="Position", select="code,name,department", top=50
        - Paginate: entity="User", top=100, skip=100 (gets records 101-200)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    # Enforce reasonable limits
    if top > 1000:
        top = 1000
    if top < 1:
        top = 1
    if skip < 0:
        skip = 0

    _audit_log(
        event_type="tool_invocation",
        tool_name="query_odata",
        instance=instance,
        status="started",
        details={
            "entity": entity,
            "select": select,
            "filter": filter[:100] if filter else None,  # Truncate for logging
            "expand": expand,
            "top": top,
            "skip": skip,
            "orderby": orderby,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_entity_path(entity)
        _validate_environment(environment)

        if select:
            _validate_select(select)
        if orderby:
            _validate_orderby(orderby)
        if expand:
            _validate_expand(expand)
        if filter:
            _validate_odata_filter(filter)

    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="query_odata",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Build OData query parameters
    params = {"$format": "json", "$top": str(top)}

    if skip > 0:
        params["$skip"] = str(skip)
    if select:
        params["$select"] = select
    if filter:
        params["$filter"] = filter
    if expand:
        params["$expand"] = expand
    if orderby:
        params["$orderby"] = orderby

    # Build endpoint path
    endpoint = f"/odata/v2/{entity}"

    result = _make_sf_odata_request(
        instance, endpoint, params, environment,
        auth_user_id, auth_password, request_id
    )

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="query_odata",
            instance=instance,
            status="error",
            details={"error": result.get("error"), "entity": entity},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Extract results from OData response
    record_count = 0
    if "d" in result:
        if "results" in result["d"]:
            # Collection response
            record_count = len(result["d"]["results"])
            response_data = {
                "entity": entity,
                "results": result["d"]["results"],
                "count": record_count
            }
            # Include next link for pagination if present
            if "__next" in result["d"]:
                response_data["next_skip"] = skip + top
        else:
            # Single entity response
            record_count = 1
            response_data = {
                "entity": entity,
                "result": result["d"],
                "count": 1
            }
    else:
        response_data = result

    _audit_log(
        event_type="tool_invocation",
        tool_name="query_odata",
        instance=instance,
        status="success",
        details={
            "entity": entity,
            "records_returned": record_count,
            "top": top,
            "skip": skip
        },
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_user_roles(
    instance: str,
    user_id: str,
    include_permissions: bool = False,
    environment: str = "preview",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Get all RBP roles assigned to a specific user.

    This tool complements get_user_permissions by showing which roles
    are assigned to a user, not just the resulting permissions.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The user ID to look up roles for
        include_permissions: If True, also fetches permissions for each role
        environment: API environment - 'preview' or 'production' (default: preview)
        auth_user_id: Optional SF user ID for authentication
        auth_password: Optional SF password for authentication

    Returns:
        dict containing:
        - user_id: The queried user
        - roles: List of roles with roleId, roleName, roleDesc
        - role_count: Number of roles assigned
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_user_roles",
        instance=instance,
        status="started",
        details={"user_id": user_id, "include_permissions": include_permissions},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(user_id, "user_id")
        _validate_environment(environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_user_roles",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Query RBPBasicUserPermission to get role assignments for the user
    safe_user_id = _sanitize_odata_string(user_id)
    params = {
        "$filter": f"userId eq '{safe_user_id}'",
        "$format": "json"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/RBPBasicUserPermission", params,
        environment, auth_user_id, auth_password, request_id
    )

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_user_roles",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Extract role information
    roles = []
    if "d" in result and "results" in result["d"]:
        for entry in result["d"]["results"]:
            role_info = {
                "roleId": entry.get("roleId"),
                "roleName": entry.get("roleName"),
                "roleDesc": entry.get("roleDesc"),
                "userType": entry.get("userType")
            }
            roles.append(role_info)

    # Optionally fetch permissions for each role
    if include_permissions and roles:
        role_ids = ",".join(str(r["roleId"]) for r in roles if r["roleId"])
        if role_ids:
            perm_params = {
                "locale": "en-US",
                "roleIds": f"'{role_ids}'",
                "$format": "json"
            }
            perm_result = _make_sf_odata_request(
                instance, "/odata/v2/getRolesPermissions", perm_params,
                environment, auth_user_id, auth_password, request_id
            )
            if "error" not in perm_result:
                # Add permissions to response
                for role in roles:
                    role["permissions"] = perm_result

    response_data = {
        "user_id": user_id,
        "roles": roles,
        "role_count": len(roles)
    }

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_user_roles",
        instance=instance,
        status="success",
        details={"user_id": user_id, "role_count": len(roles)},
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def compare_configurations(
    instance1: str,
    instance2: str,
    entity: str,
    environment1: str = "preview",
    environment2: str = "production",
    auth_user_id: str | None = None,
    auth_password: str | None = None
) -> dict[str, Any]:
    """
    Compare entity configuration/metadata between two SuccessFactors instances.

    This is useful for verifying that dev/test/production environments are aligned
    before deployments, or for auditing configuration drift.

    Args:
        instance1: First SF instance/company ID (e.g., dev instance)
        instance2: Second SF instance/company ID (e.g., prod instance)
        entity: OData entity to compare (e.g., "User", "EmpEmployment", "Position")
        environment1: API environment for instance1 (default: preview)
        environment2: API environment for instance2 (default: production)
        auth_user_id: Optional SF user ID for authentication (used for both)
        auth_password: Optional SF password for authentication (used for both)

    Returns:
        dict containing:
        - entity: The compared entity name
        - instance1/instance2: Instance identifiers
        - fields_only_in_instance1: Fields present only in first instance
        - fields_only_in_instance2: Fields present only in second instance
        - fields_in_both: Count of fields present in both
        - type_differences: Fields with different types between instances
        - match_percentage: Overall configuration match percentage
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="compare_configurations",
        instance=f"{instance1} vs {instance2}",
        status="started",
        details={
            "entity": entity,
            "instance1": instance1,
            "instance2": instance2,
            "environment1": environment1,
            "environment2": environment2
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance1, "instance1")
        _validate_identifier(instance2, "instance2")
        _validate_identifier(entity, "entity")
        _validate_environment(environment1)
        _validate_environment(environment2)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="compare_configurations",
            instance=f"{instance1} vs {instance2}",
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    user_id, password = _resolve_credentials(auth_user_id, auth_password)

    if not user_id or not password:
        _audit_log(
            event_type="authentication",
            tool_name="compare_configurations",
            instance=f"{instance1} vs {instance2}",
            status="failure",
            details={"reason": "missing_credentials"},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": "Missing credentials. Provide auth_user_id and auth_password parameters."}

    def fetch_metadata(instance: str, environment: str) -> dict | None:
        """Fetch and parse metadata for an instance."""
        api_host = _get_api_host(environment)
        username = f"{user_id}@{instance}"
        url = f"https://{api_host}/odata/v2/{entity}/$metadata"

        try:
            response = requests.get(url, auth=(username, password), timeout=30)
            if response.status_code != 200:
                return None
            return _xml_to_dict(response.text.encode("UTF-8"))
        except Exception:
            return None

    def extract_fields(metadata: dict) -> dict[str, dict]:
        """Extract field information from metadata."""
        fields = {}
        try:
            # Navigate the metadata structure to find EntityType properties
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
                                    "maxLength": prop.get("@MaxLength", "")
                                }
        except Exception:
            pass
        return fields

    # Fetch metadata from both instances
    metadata1 = fetch_metadata(instance1, environment1)
    metadata2 = fetch_metadata(instance2, environment2)

    if metadata1 is None:
        _audit_log(
            event_type="tool_invocation",
            tool_name="compare_configurations",
            instance=f"{instance1} vs {instance2}",
            status="error",
            details={"error": f"Failed to fetch metadata from {instance1}"},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": f"Failed to fetch metadata from instance1 ({instance1})"}

    if metadata2 is None:
        _audit_log(
            event_type="tool_invocation",
            tool_name="compare_configurations",
            instance=f"{instance1} vs {instance2}",
            status="error",
            details={"error": f"Failed to fetch metadata from {instance2}"},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": f"Failed to fetch metadata from instance2 ({instance2})"}

    # Extract fields from both
    fields1 = extract_fields(metadata1)
    fields2 = extract_fields(metadata2)

    # Compare fields
    fields1_names = set(fields1.keys())
    fields2_names = set(fields2.keys())

    only_in_1 = list(fields1_names - fields2_names)
    only_in_2 = list(fields2_names - fields1_names)
    in_both = fields1_names & fields2_names

    # Check for type differences in common fields
    type_differences = []
    for field in in_both:
        if fields1[field]["type"] != fields2[field]["type"]:
            type_differences.append({
                "field": field,
                f"{instance1}_type": fields1[field]["type"],
                f"{instance2}_type": fields2[field]["type"]
            })

    # Calculate match percentage
    total_unique_fields = len(fields1_names | fields2_names)
    matching_fields = len(in_both) - len(type_differences)
    match_percentage = round((matching_fields / total_unique_fields * 100), 1) if total_unique_fields > 0 else 100

    response_data = {
        "entity": entity,
        "instance1": {"name": instance1, "environment": environment1, "field_count": len(fields1)},
        "instance2": {"name": instance2, "environment": environment2, "field_count": len(fields2)},
        "comparison": {
            "fields_only_in_instance1": sorted(only_in_1),
            "fields_only_in_instance2": sorted(only_in_2),
            "fields_in_both": len(in_both),
            "type_differences": type_differences,
            "match_percentage": match_percentage
        },
        "summary": {
            "is_identical": len(only_in_1) == 0 and len(only_in_2) == 0 and len(type_differences) == 0,
            "differences_found": len(only_in_1) + len(only_in_2) + len(type_differences)
        }
    }

    _audit_log(
        event_type="tool_invocation",
        tool_name="compare_configurations",
        instance=f"{instance1} vs {instance2}",
        status="success",
        details={
            "entity": entity,
            "match_percentage": match_percentage,
            "differences_found": response_data["summary"]["differences_found"]
        },
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


if __name__ == "__main__":
    # Get port from environment (Cloud Run sets PORT)
    port = int(os.environ.get("PORT", 8080))

    # Use streamable-http transport for Cloud Run deployment
    asyncio.run(
        mcp.run_async(
            transport="streamable-http",
            host="0.0.0.0",
            port=port,
        )
    )
