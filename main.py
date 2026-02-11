import os
import re
import asyncio
import logging
import json
import time
import uuid
from datetime import datetime, date
from typing import Any
from dotenv import load_dotenv
from fastmcp import FastMCP
import requests
import defusedxml.ElementTree as DefusedET
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

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

# =============================================================================
# Data Center to API Host Mapping (from SAP official documentation)
# =============================================================================
# Format: {(data_center, environment): api_host}
# Includes both primary data centers and their "New Data Center" aliases

DC_API_HOST_MAP = {
    # DC10 / DC66 - Sydney, Australia (Azure)
    ("DC10", "production"): "api10.successfactors.com",
    ("DC10", "preview"): "api10preview.sapsf.com",
    ("DC66", "production"): "api10.successfactors.com",
    ("DC66", "preview"): "api10preview.sapsf.com",

    # DC12 / DC33 - Rot, Germany
    ("DC12", "production"): "api012.successfactors.eu",
    ("DC12", "preview"): "api12preview.sapsf.eu",
    ("DC33", "production"): "api012.successfactors.eu",
    ("DC33", "preview"): "api12preview.sapsf.eu",

    # DC15 / DC30 - Shanghai, China
    ("DC15", "production"): "api15.sapsf.cn",
    ("DC15", "preview"): "api15preview.sapsf.cn",
    ("DC30", "production"): "api15.sapsf.cn",
    ("DC30", "preview"): "api15preview.sapsf.cn",

    # DC17 / DC60 - Toronto, Canada (Azure)
    ("DC17", "production"): "api17.sapsf.com",
    ("DC17", "preview"): "api17preview.sapsf.com",
    ("DC60", "production"): "api17.sapsf.com",
    ("DC60", "preview"): "api17preview.sapsf.com",

    # DC19 / DC62 - Sao Paulo, Brazil (Azure)
    ("DC19", "production"): "api19.sapsf.com",
    ("DC19", "preview"): "api19preview.sapsf.com",
    ("DC62", "production"): "api19.sapsf.com",
    ("DC62", "preview"): "api19preview.sapsf.com",

    # DC2 / DC57 - Eemshaven, Netherlands (GCP)
    ("DC2", "production"): "api2.successfactors.eu",
    ("DC2", "preview"): "api2preview.sapsf.eu",
    ("DC2", "sales_demo"): "apisalesdemo2.successfactors.eu",
    ("DC57", "production"): "api2.successfactors.eu",
    ("DC57", "preview"): "api2preview.sapsf.eu",
    ("DC57", "sales_demo"): "apisalesdemo2.successfactors.eu",

    # DC22 - Dubai, UAE
    ("DC22", "production"): "api22.sapsf.com",
    ("DC22", "preview"): "api22preview.sapsf.com",

    # DC23 / DC84 - Riyadh, Saudi Arabia
    ("DC23", "production"): "api23.sapsf.com",
    ("DC23", "preview"): "api23preview.sapsf.com",
    ("DC84", "production"): "api23.sapsf.com",
    ("DC84", "preview"): "api23preview.sapsf.com",

    # DC4 / DC68 - Virginia, US (Azure)
    ("DC4", "production"): "api4.successfactors.com",
    ("DC4", "preview"): "api4preview.sapsf.com",
    ("DC4", "sales_demo"): "api68sales.successfactors.com",
    ("DC68", "production"): "api4.successfactors.com",
    ("DC68", "preview"): "api4preview.sapsf.com",
    ("DC68", "sales_demo"): "api68sales.successfactors.com",

    # DC40 - Sales Demo (Azure)
    ("DC40", "sales_demo"): "api40sales.sapsf.com",

    # DC41 - Virginia, US (Azure)
    ("DC41", "production"): "api41.sapsf.com",
    ("DC41", "preview"): "api41preview.sapsf.com",

    # DC44 / DC52 - Singapore (GCP)
    ("DC44", "production"): "api44.sapsf.com",
    ("DC44", "preview"): "api44preview.sapsf.com",
    ("DC52", "production"): "api44.sapsf.com",
    ("DC52", "preview"): "api44preview.sapsf.com",

    # DC47 - Canada Central (Azure)
    ("DC47", "production"): "api47.sapsf.com",
    ("DC47", "preview"): "api47preview.sapsf.com",

    # DC50 - Tokyo, Japan (GCP)
    ("DC50", "production"): "api50.sapsf.com",
    ("DC50", "preview"): "api50preview.sapsf.com",

    # DC55 - Frankfurt, Germany (GCP)
    ("DC55", "production"): "api55.sapsf.eu",
    ("DC55", "preview"): "api55preview.sapsf.eu",

    # DC74 - Zurich, Switzerland (Azure)
    ("DC74", "production"): "api74.sapsf.eu",
    ("DC74", "preview"): "api74preview.sapsf.eu",

    # DC8 / DC70 - Ashburn, Virginia, US (Azure)
    ("DC8", "production"): "api8.successfactors.com",
    ("DC8", "preview"): "api8preview.sapsf.com",
    ("DC8", "sales_demo"): "apisalesdemo8.successfactors.com",
    ("DC70", "production"): "api8.successfactors.com",
    ("DC70", "preview"): "api8preview.sapsf.com",
    ("DC70", "sales_demo"): "apisalesdemo8.successfactors.com",

    # DC80 - Mumbai, India (GCP)
    ("DC80", "production"): "api-in10.hr.cloud.sap",
    ("DC80", "preview"): "api-in10-preview.hr.cloud.sap",

    # DC82 - Riyadh, Saudi Arabia (GCP)
    ("DC82", "production"): "api-sa20.hr.cloud.sap",
    ("DC82", "preview"): "api-sa20-preview.hr.cloud.sap",
}

# Extract valid data centers and environments from the map
VALID_DATA_CENTERS = set(dc for dc, _ in DC_API_HOST_MAP.keys())
VALID_ENVIRONMENTS = {"production", "preview", "sales_demo"}


def _get_api_host(data_center: str, environment: str) -> str:
    """
    Map data center and environment to API host.

    Args:
        data_center: SAP data center code (e.g., "DC55", "DC10")
        environment: Environment type ("preview", "production", "sales_demo")

    Returns:
        API host string (without https:// prefix)

    Raises:
        ValueError: If invalid data_center or environment, or combination not available
    """
    dc_upper = data_center.upper()
    env_lower = environment.lower()

    if dc_upper not in VALID_DATA_CENTERS:
        valid_dcs = ", ".join(sorted(VALID_DATA_CENTERS, key=lambda x: (int(x[2:]) if x[2:].isdigit() else 999, x)))
        raise ValueError(f"Invalid data_center '{data_center}'. Valid options: {valid_dcs}")

    if env_lower not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid environment '{environment}'. Valid options: production, preview, sales_demo")

    key = (dc_upper, env_lower)
    if key not in DC_API_HOST_MAP:
        # Find available environments for this DC
        available_envs = [env for (dc, env) in DC_API_HOST_MAP.keys() if dc == dc_upper]
        raise ValueError(f"Environment '{environment}' not available for {data_center}. Available: {', '.join(available_envs)}")

    return DC_API_HOST_MAP[key]


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


def _validate_date(value: str, field_name: str) -> str:
    """Validate that a value is a valid YYYY-MM-DD date string."""
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Invalid {field_name}: must be in YYYY-MM-DD format (e.g., '2026-01-15')")
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


def _resolve_credentials(
    auth_user_id: str,
    auth_password: str
) -> tuple[str, str]:
    """Return credentials provided by caller. Credentials are required on every tool call."""
    return auth_user_id, auth_password


# =============================================================================
# SECURITY: API Key Authentication for MCP Endpoint
# =============================================================================

def _get_mcp_api_key() -> str | None:
    """
    Get MCP API key from environment or GCP Secret Manager.

    Priority:
    1. MCP_API_KEY environment variable
    2. GCP Secret Manager (if GCP_PROJECT_ID is set)

    Returns:
        API key string or None if not configured
    """
    # Try environment variable first
    api_key = os.environ.get("MCP_API_KEY")
    if api_key:
        return api_key

    # Try GCP Secret Manager
    try:
        from google.cloud import secretmanager
        project_id = os.environ.get("GCP_PROJECT_ID")
        if project_id:
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/mcp-api-key/versions/latest"
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
    except Exception:
        pass

    return None


# Initialize API key at startup
MCP_API_KEY = _get_mcp_api_key()
if MCP_API_KEY:
    logger.info("MCP API key authentication enabled")
else:
    logger.warning("MCP API key not configured - endpoint is unprotected")


#Init Server
mcp = FastMCP("SFgetConfig")


def _make_sf_odata_request(
    instance: str,
    endpoint: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    params: dict | None = None,
    request_id: str | None = None
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

    # Resolve API host from data center and environment
    try:
        api_host = _get_api_host(data_center, environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            instance=instance,
            status="failure",
            details={"reason": "invalid_data_center_or_environment", "error": str(e)},
            request_id=req_id
        )
        return {"error": str(e)}

    user_id, password = _resolve_credentials(auth_user_id, auth_password)

    if not user_id or not password:
        _audit_log(
            event_type="authentication",
            instance=instance,
            status="failure",
            details={"reason": "missing_credentials", "endpoint": endpoint},
            request_id=req_id
        )
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str
) -> dict[str, Any]:
    """
    Get Configuration metadata details for the entity within the instance.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: The OData entity name (e.g., "User", "EmpEmployment")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_configuration",
        instance=instance,
        status="started",
        details={"entity": entity, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(entity, "entity")
        api_host = _get_api_host(data_center, environment)
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
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_description: bool = False
) -> dict[str, Any]:
    """
    Get all RBP (Role-Based Permission) roles in the SuccessFactors instance.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_description: If True, includes role descriptions

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
        details={"include_description": include_description, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
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
    result = _make_sf_odata_request(instance, "/odata/v2/RBPRole", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    group_type: str | None = None
) -> dict[str, Any]:
    """
    Get dynamic groups (permission groups) used in RBP rules.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        group_type: Optional filter for group type

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
        details={"group_type": group_type, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
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

    result = _make_sf_odata_request(instance, "/odata/v2/DynamicGroup", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US"
) -> dict[str, Any]:
    """
    Get all permissions assigned to one or more RBP roles.

    Args:
        instance: The SuccessFactors instance/company ID
        role_ids: Role ID(s) - single ID ("10") or comma-separated ("10,20,30")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for permission labels (default: en-US)

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
        details={"role_ids": role_ids, "locale": locale, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(role_ids, "role_ids")
        _validate_locale(locale)
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
    result = _make_sf_odata_request(instance, "/odata/v2/getRolesPermissions", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US"
) -> dict[str, Any]:
    """
    Get all permissions for one or more users based on their assigned roles.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: User ID(s) - single ID ("admin") or comma-separated ("admin,user2,user3")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for permission labels (default: en-US)

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
        details={"user_ids_count": len(user_ids.split(",")), "locale": locale, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_ids(user_ids, "user_ids")
        _validate_locale(locale)
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
    result = _make_sf_odata_request(instance, "/odata/v2/getUsersPermissions", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US"
) -> dict[str, Any]:
    """
    Get permission metadata mapping UI labels to permission types and values.

    This API helps map the UI text to the permission type and permission string value,
    which are needed for the checkUserPermission API.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        locale: Locale for permission labels (default: en-US)

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
        details={"locale": locale, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_locale(locale)
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
    result = _make_sf_odata_request(instance, "/odata/v2/getPermissionMetadata", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    perm_long_value: str = "-1L"
) -> dict[str, Any]:
    """
    Check if a user has a specific permission for a target user.

    Args:
        instance: The SuccessFactors instance/company ID
        access_user_id: The user making the permission check
        target_user_id: The user whose data access is being verified
        perm_type: Permission category (e.g., "EmployeeFilesViews_type")
        perm_string_value: Permission identifier (e.g., "$_payrollIntegration_view")
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        perm_long_value: Long value representation (default: "-1L")

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
            "data_center": data_center,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(access_user_id, "access_user_id")
        _validate_identifier(target_user_id, "target_user_id")
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
    result = _make_sf_odata_request(instance, "/odata/v2/checkUserPermission", data_center, environment, auth_user_id, auth_password, params, request_id)

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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    select: str | None = None,
    filter: str | None = None,
    expand: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None
) -> dict[str, Any]:
    """
    Execute a flexible OData query against any SuccessFactors entity.

    This is a powerful generic query tool that enables querying any OData entity
    while maintaining security controls and audit logging.

    Args:
        instance: The SuccessFactors instance/company ID
        entity: OData entity name (e.g., "User", "Position", "EmpEmployment")
                Can include key for single record: "User('admin')"
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        select: Fields to return, comma-separated (e.g., "userId,firstName,lastName")
        filter: OData filter expression (e.g., "status eq 'active'")
        expand: Navigation properties to expand (e.g., "empInfo,jobInfoNav")
        top: Maximum records to return (default 100, max 1000)
        skip: Number of records to skip for pagination (default 0)
        orderby: Sort expression (e.g., "lastName asc" or "hireDate desc")

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
            "data_center": data_center,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_entity_path(entity)

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
        instance, endpoint, data_center, environment,
        auth_user_id, auth_password, params, request_id
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
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_permissions: bool = False
) -> dict[str, Any]:
    """
    Get all RBP roles assigned to a specific user.

    This tool complements get_user_permissions by showing which roles
    are assigned to a user, not just the resulting permissions.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The user ID to look up roles for
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_permissions: If True, also fetches permissions for each role

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
        details={"user_id": user_id, "include_permissions": include_permissions, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(user_id, "user_id")
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
        instance, "/odata/v2/RBPBasicUserPermission", data_center, environment,
        auth_user_id, auth_password, params, request_id
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
                instance, "/odata/v2/getRolesPermissions", data_center, environment,
                auth_user_id, auth_password, perm_params, request_id
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
    data_center1: str,
    environment1: str,
    data_center2: str,
    environment2: str,
    auth_user_id: str,
    auth_password: str
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
            "data_center1": data_center1,
            "environment1": environment1,
            "data_center2": data_center2,
            "environment2": environment2
        },
        request_id=request_id
    )

    # Input validation and get API hosts
    try:
        _validate_identifier(instance1, "instance1")
        _validate_identifier(instance2, "instance2")
        _validate_identifier(entity, "entity")
        api_host1 = _get_api_host(data_center1, environment1)
        api_host2 = _get_api_host(data_center2, environment2)
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
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    def fetch_metadata(instance: str, api_host: str) -> dict | None:
        """Fetch and parse metadata for an instance."""
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
    metadata1 = fetch_metadata(instance1, api_host1)
    metadata2 = fetch_metadata(instance2, api_host2)

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
        "instance1": {"name": instance1, "data_center": data_center1, "environment": environment1, "field_count": len(fields1)},
        "instance2": {"name": instance2, "data_center": data_center2, "environment": environment2, "field_count": len(fields2)},
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


@mcp.tool()
def list_entities(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    category: str | None = None
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
        dict containing:
        - entities: List of entity names with their URLs
        - count: Total number of entities
        - categories: Grouped entities by common prefixes (if category='all')
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="list_entities",
        instance=instance,
        status="started",
        details={"category": category, "data_center": data_center, "environment": environment},
        request_id=request_id
    )

    # Input validation and get API host
    try:
        _validate_identifier(instance, "instance")
        api_host = _get_api_host(data_center, environment)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="list_entities",
            instance=instance,
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
            tool_name="list_entities",
            instance=instance,
            status="failure",
            details={"reason": "missing_credentials"},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": "Missing credentials. auth_user_id and auth_password parameters are required."}

    username = f"{user_id}@{instance}"
    url = f"https://{api_host}/odata/v2/"

    try:
        response = requests.get(
            url,
            auth=(username, password),
            headers={"Accept": "application/json"},
            timeout=30
        )
        duration_ms = (time.time() - start_time) * 1000

        if response.status_code == 401:
            _audit_log(
                event_type="authentication",
                tool_name="list_entities",
                instance=instance,
                status="failure",
                details={"reason": "invalid_credentials", "http_status": 401},
                request_id=request_id,
                duration_ms=duration_ms
            )
            return {"error": "HTTP 401", "message": "Authentication failed. Check credentials."}

        if response.status_code != 200:
            _audit_log(
                event_type="tool_invocation",
                tool_name="list_entities",
                instance=instance,
                status="error",
                details={"http_status": response.status_code},
                request_id=request_id,
                duration_ms=duration_ms
            )
            return {"error": f"HTTP {response.status_code}", "message": response.text[:500]}

        data = response.json()

        # Extract entity sets from the service document
        entities = []
        if "d" in data and "EntitySets" in data["d"]:
            entity_sets = data["d"]["EntitySets"]
            for entity_name in entity_sets:
                entities.append(entity_name)

        # Sort entities alphabetically
        entities = sorted(entities)

        # Categorize entities by common prefixes
        categories_dict = {
            "foundation": [],  # FOxxxx entities
            "employee": [],    # Emp, Per, User entities
            "talent": [],      # Goal, Performance, Learning entities
            "platform": [],    # RBP, Picklist, Background entities
            "other": []
        }

        for entity in entities:
            entity_lower = entity.lower()
            if entity.startswith("FO") or entity.startswith("fo"):
                categories_dict["foundation"].append(entity)
            elif any(entity_lower.startswith(p) for p in ["emp", "per", "user", "person"]):
                categories_dict["employee"].append(entity)
            elif any(entity_lower.startswith(p) for p in ["goal", "performance", "learning", "competency", "talent"]):
                categories_dict["talent"].append(entity)
            elif any(entity_lower.startswith(p) for p in ["rbp", "picklist", "background", "photo", "attachment"]):
                categories_dict["platform"].append(entity)
            else:
                categories_dict["other"].append(entity)

        # Filter by category if specified
        if category and category.lower() != "all":
            category_lower = category.lower()
            if category_lower in categories_dict:
                filtered_entities = categories_dict[category_lower]
            else:
                filtered_entities = entities
        else:
            filtered_entities = entities

        response_data = {
            "entities": filtered_entities,
            "count": len(filtered_entities),
            "total_available": len(entities)
        }

        if not category or category.lower() == "all":
            response_data["by_category"] = {
                "foundation": len(categories_dict["foundation"]),
                "employee": len(categories_dict["employee"]),
                "talent": len(categories_dict["talent"]),
                "platform": len(categories_dict["platform"]),
                "other": len(categories_dict["other"])
            }

        _audit_log(
            event_type="tool_invocation",
            tool_name="list_entities",
            instance=instance,
            status="success",
            details={"entity_count": len(filtered_entities), "category": category},
            request_id=request_id,
            duration_ms=duration_ms
        )

        return response_data

    except requests.exceptions.RequestException as e:
        _audit_log(
            event_type="tool_invocation",
            tool_name="list_entities",
            instance=instance,
            status="error",
            details={"reason": "request_exception", "error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": f"Request failed: {str(e)}"}


@mcp.tool()
def get_role_history(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    role_id: str | None = None,
    role_name: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    top: int = 100
) -> dict[str, Any]:
    """
    Get modification history for RBP roles.

    Returns who modified the role, when, and what changes were made.
    This helps audit role configuration changes over time.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        role_id: Optional role ID to filter (e.g., "10")
        role_name: Optional role name to filter (alternative to role_id)
        from_date: Optional start date filter (ISO format: YYYY-MM-DD)
        to_date: Optional end date filter (ISO format: YYYY-MM-DD)
        top: Maximum records to return (default 100, max 500)

    Returns:
        dict containing:
        - filters_applied: The filters used for the query
        - history: List of role change records with modifiedBy, modifiedDate, roleId, roleName
        - count: Number of records returned
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    # Enforce reasonable limits
    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_history",
        instance=instance,
        status="started",
        details={
            "role_id": role_id,
            "role_name": role_name,
            "from_date": from_date,
            "to_date": to_date,
            "top": top,
            "data_center": data_center,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        if role_id:
            _validate_identifier(role_id, "role_id")
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_role_history",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Build filter for RBPRole query with audit fields
    filters = []
    if role_id:
        safe_role_id = _sanitize_odata_string(role_id)
        filters.append(f"roleId eq {safe_role_id}")
    if role_name:
        safe_role_name = _sanitize_odata_string(role_name)
        filters.append(f"roleName eq '{safe_role_name}'")
    if from_date:
        # OData datetime filter format
        filters.append(f"lastModifiedDate ge datetime'{from_date}T00:00:00'")
    if to_date:
        filters.append(f"lastModifiedDate le datetime'{to_date}T23:59:59'")

    # Query RBPRole with audit fields
    params = {
        "$select": "roleId,roleName,roleDesc,userType,lastModifiedBy,lastModifiedDate,createdBy,createdDate",
        "$orderby": "lastModifiedDate desc",
        "$top": str(top),
        "$format": "json"
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/RBPRole", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_role_history",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Process results
    history = []
    if "d" in result and "results" in result["d"]:
        for entry in result["d"]["results"]:
            # Parse SAP date format: /Date(timestamp)/
            last_modified = entry.get("lastModifiedDate", "")
            created_date = entry.get("createdDate", "")

            # Convert SAP date format to ISO
            def parse_sap_date(date_str: str) -> str:
                if not date_str:
                    return ""
                # Format: /Date(1234567890000)/
                match = re.search(r'/Date\((\d+)\)/', str(date_str))
                if match:
                    timestamp_ms = int(match.group(1))
                    from datetime import datetime, timezone
                    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
                    return dt.isoformat()
                return str(date_str)

            history_record = {
                "role_id": entry.get("roleId"),
                "role_name": entry.get("roleName"),
                "role_description": entry.get("roleDesc"),
                "user_type": entry.get("userType"),
                "last_modified_by": entry.get("lastModifiedBy"),
                "last_modified_date": parse_sap_date(last_modified),
                "created_by": entry.get("createdBy"),
                "created_date": parse_sap_date(created_date)
            }
            history.append(history_record)

    # Build response
    response_data = {
        "filters_applied": {
            "role_id": role_id,
            "role_name": role_name,
            "from_date": from_date,
            "to_date": to_date
        },
        "history": history,
        "count": len(history)
    }

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_history",
        instance=instance,
        status="success",
        details={"records_returned": len(history)},
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_role_assignment_history(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    role_id: str | None = None,
    user_id: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    top: int = 100
) -> dict[str, Any]:
    """
    Get history of role assignments - who was granted roles and when.

    This tool shows the assignment history of RBP roles to users,
    helping audit who has been given access and by whom.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        role_id: Optional role ID to filter assignments for a specific role
        user_id: Optional user ID to filter assignments for a specific user
        from_date: Optional start date filter (ISO format: YYYY-MM-DD)
        to_date: Optional end date filter (ISO format: YYYY-MM-DD)
        top: Maximum records to return (default 100, max 500)

    Returns:
        dict containing:
        - filters_applied: The filters used for the query
        - assignments: List of role assignment records
        - count: Number of records returned

    Example:
        - Get all assignments for a role: role_id="10"
        - Get all roles for a user: user_id="admin"
        - Audit recent assignments: from_date="2024-01-01"
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    # Enforce reasonable limits
    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_assignment_history",
        instance=instance,
        status="started",
        details={
            "role_id": role_id,
            "user_id": user_id,
            "from_date": from_date,
            "to_date": to_date,
            "top": top,
            "data_center": data_center,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        if role_id:
            _validate_identifier(role_id, "role_id")
        if user_id:
            _validate_identifier(user_id, "user_id")
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_role_assignment_history",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # Build filter for RBPBasicUserPermission query
    filters = []
    if role_id:
        safe_role_id = _sanitize_odata_string(role_id)
        filters.append(f"roleId eq {safe_role_id}")
    if user_id:
        safe_user_id = _sanitize_odata_string(user_id)
        filters.append(f"userId eq '{safe_user_id}'")
    if from_date:
        filters.append(f"lastModifiedDate ge datetime'{from_date}T00:00:00'")
    if to_date:
        filters.append(f"lastModifiedDate le datetime'{to_date}T23:59:59'")

    # Query RBPBasicUserPermission for assignment records
    params = {
        "$select": "userId,roleId,roleName,roleDesc,userType,lastModifiedBy,lastModifiedDate,createdBy,createdDate",
        "$orderby": "lastModifiedDate desc",
        "$top": str(top),
        "$format": "json"
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/RBPBasicUserPermission", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(
            event_type="tool_invocation",
            tool_name="get_role_assignment_history",
            instance=instance,
            status="error",
            details={"error": result.get("error")},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return result

    # Process results
    assignments = []
    if "d" in result and "results" in result["d"]:
        for entry in result["d"]["results"]:
            # Parse SAP date format
            last_modified = entry.get("lastModifiedDate", "")
            created_date = entry.get("createdDate", "")

            def parse_sap_date(date_str: str) -> str:
                if not date_str:
                    return ""
                match = re.search(r'/Date\((\d+)\)/', str(date_str))
                if match:
                    timestamp_ms = int(match.group(1))
                    from datetime import datetime, timezone
                    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
                    return dt.isoformat()
                return str(date_str)

            assignment_record = {
                "user_id": entry.get("userId"),
                "role_id": entry.get("roleId"),
                "role_name": entry.get("roleName"),
                "role_description": entry.get("roleDesc"),
                "user_type": entry.get("userType"),
                "assigned_by": entry.get("createdBy"),
                "assigned_date": parse_sap_date(created_date),
                "last_modified_by": entry.get("lastModifiedBy"),
                "last_modified_date": parse_sap_date(last_modified)
            }
            assignments.append(assignment_record)

    # Build response
    response_data = {
        "filters_applied": {
            "role_id": role_id,
            "user_id": user_id,
            "from_date": from_date,
            "to_date": to_date
        },
        "assignments": assignments,
        "count": len(assignments)
    }

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_role_assignment_history",
        instance=instance,
        status="success",
        details={"records_returned": len(assignments)},
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_picklist_values(
    instance: str,
    picklist_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    locale: str = "en-US",
    include_inactive: bool = False
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

    Returns:
        dict containing:
        - picklist_id: The queried picklist
        - values: List of picklist options with id, label, externalCode
        - count: Number of values
        - has_inactive: Whether inactive values exist

    Common picklists:
        - ecJobFunction: Job functions
        - ecJobCode: Job codes
        - ecPayGrade: Pay grades
        - ecDepartment: Departments
        - nationality: Countries/nationalities
        - maritalStatus: Marital status options
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_picklist_values",
        instance=instance,
        status="started",
        details={
            "picklist_id": picklist_id,
            "locale": locale,
            "include_inactive": include_inactive,
            "data_center": data_center,
            "environment": environment
        },
        request_id=request_id
    )

    # Input validation
    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(picklist_id, "picklist_id")
        _validate_locale(locale)
    except ValueError as e:
        _audit_log(
            event_type="validation_error",
            tool_name="get_picklist_values",
            instance=instance,
            status="failure",
            details={"error": str(e)},
            request_id=request_id,
            duration_ms=(time.time() - start_time) * 1000
        )
        return {"error": str(e)}

    # First, get the picklist metadata
    safe_picklist_id = _sanitize_odata_string(picklist_id)
    params = {
        "$filter": f"PickListV2_id eq '{safe_picklist_id}'",
        "$expand": "picklistLabels",
        "$format": "json"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/PickListValueV2", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        # Try alternative endpoint (older PicklistOption)
        params_alt = {
            "$filter": f"picklistId eq '{safe_picklist_id}'",
            "$format": "json"
        }
        result = _make_sf_odata_request(
            instance, "/odata/v2/PicklistOption", data_center, environment,
            auth_user_id, auth_password, params_alt, request_id
        )

        if "error" in result:
            _audit_log(
                event_type="tool_invocation",
                tool_name="get_picklist_values",
                instance=instance,
                status="error",
                details={"error": result.get("error"), "picklist_id": picklist_id},
                request_id=request_id,
                duration_ms=(time.time() - start_time) * 1000
            )
            return result

    # Extract picklist values
    values = []
    inactive_count = 0

    if "d" in result and "results" in result["d"]:
        for entry in result["d"]["results"]:
            # Check status for V2 format
            status = entry.get("status", "A")
            is_active = status in ["A", "active", None]

            if not is_active:
                inactive_count += 1
                if not include_inactive:
                    continue

            # Extract label based on locale
            label = entry.get("optionValue", "")
            external_code = entry.get("externalCode", entry.get("optionId", ""))

            # Try to get localized label from picklistLabels
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
                "status": "active" if is_active else "inactive"
            }

            # Add optional fields if present
            if entry.get("parentPicklistValue"):
                value_info["parentValue"] = entry.get("parentPicklistValue")
            if entry.get("sortOrder"):
                value_info["sortOrder"] = entry.get("sortOrder")

            values.append(value_info)

    # Sort by sortOrder if available, otherwise by label
    values.sort(key=lambda x: (x.get("sortOrder", 999), x.get("label", "")))

    response_data = {
        "picklist_id": picklist_id,
        "locale": locale,
        "values": values,
        "count": len(values),
        "has_inactive": inactive_count > 0,
        "inactive_count": inactive_count if include_inactive else None
    }

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_picklist_values",
        instance=instance,
        status="success",
        details={
            "picklist_id": picklist_id,
            "value_count": len(values),
            "inactive_count": inactive_count
        },
        request_id=request_id,
        duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# HR OPERATIONS TOOLS: Employee Lookup
# =============================================================================


@mcp.tool()
def get_employee_profile(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_compensation: bool = False
) -> dict[str, Any]:
    """
    Get a complete employee profile including job info, contact details, and manager.

    Returns the employee's current job title, department, location, manager,
    email, phone, and hire date in a single call. Optionally includes compensation.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID (e.g., 'jsmith')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_compensation: If True, also fetches current compensation details
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation",
        tool_name="get_employee_profile",
        instance=instance,
        status="started",
        details={"user_id": user_id, "include_compensation": include_compensation},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(user_id, "user_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_employee_profile",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    safe_user_id = _sanitize_odata_string(user_id)

    # Get user profile with job info and manager
    params = {
        "$filter": f"userId eq '{safe_user_id}'",
        "$select": "userId,username,firstName,lastName,displayName,email,hireDate,status,hr,manager,department,division,location,title",
        "$expand": "manager,hr",
        "$format": "json",
        "$top": "1"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_employee_profile",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    # Extract user data
    users = result.get("d", {}).get("results", [])
    if not users:
        return {"error": f"Employee '{user_id}' not found", "message": "Check the user ID and try again."}

    user = users[0]

    # Build profile
    profile = {
        "user_id": user.get("userId"),
        "display_name": user.get("displayName") or f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
        "first_name": user.get("firstName"),
        "last_name": user.get("lastName"),
        "email": user.get("email"),
        "hire_date": user.get("hireDate"),
        "status": user.get("status"),
        "title": user.get("title"),
        "department": user.get("department"),
        "division": user.get("division"),
        "location": user.get("location"),
    }

    # Extract manager info
    manager_data = user.get("manager", {})
    if isinstance(manager_data, dict) and "results" in manager_data:
        mgrs = manager_data["results"]
        if mgrs:
            mgr = mgrs[0]
            profile["manager"] = {
                "user_id": mgr.get("userId"),
                "name": mgr.get("displayName") or f"{mgr.get('firstName', '')} {mgr.get('lastName', '')}".strip()
            }
    elif isinstance(manager_data, dict) and manager_data.get("userId"):
        profile["manager"] = {
            "user_id": manager_data.get("userId"),
            "name": manager_data.get("displayName") or f"{manager_data.get('firstName', '')} {manager_data.get('lastName', '')}".strip()
        }

    # Extract HR info
    hr_data = user.get("hr", {})
    if isinstance(hr_data, dict) and hr_data.get("userId"):
        profile["hr_rep"] = {
            "user_id": hr_data.get("userId"),
            "name": hr_data.get("displayName") or f"{hr_data.get('firstName', '')} {hr_data.get('lastName', '')}".strip()
        }

    # Optionally fetch compensation
    if include_compensation:
        comp_params = {
            "$filter": f"userId eq '{safe_user_id}'",
            "$select": "userId,startDate,payGroup,payGrade,compensatedHours",
            "$expand": "empPayCompRecurringNav",
            "$format": "json",
            "$top": "5",
            "$orderby": "startDate desc"
        }
        comp_result = _make_sf_odata_request(
            instance, "/odata/v2/EmpCompensation", data_center, environment,
            auth_user_id, auth_password, comp_params, request_id
        )
        if "error" not in comp_result:
            comp_records = comp_result.get("d", {}).get("results", [])
            if comp_records:
                latest = comp_records[0]
                comp_info = {
                    "pay_group": latest.get("payGroup"),
                    "pay_grade": latest.get("payGrade"),
                    "effective_date": latest.get("startDate"),
                }
                # Extract recurring pay components
                recurring = latest.get("empPayCompRecurringNav", {})
                if isinstance(recurring, dict) and "results" in recurring:
                    comp_info["pay_components"] = [
                        {
                            "pay_component": r.get("payComponent"),
                            "amount": r.get("paycompvalue"),
                            "currency": r.get("currencyCode"),
                            "frequency": r.get("frequency"),
                        }
                        for r in recurring["results"]
                    ]
                profile["compensation"] = comp_info

    _audit_log(
        event_type="tool_invocation", tool_name="get_employee_profile",
        instance=instance, status="success",
        details={"user_id": user_id, "include_compensation": include_compensation},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return {"profile": profile}


@mcp.tool()
def search_employees(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    search_text: str = "",
    department: str = "",
    location: str = "",
    manager_id: str = "",
    status: str = "active",
    top: int = 50
) -> dict[str, Any]:
    """
    Search for employees by name, department, location, or manager.

    Find employees without knowing their exact user IDs. Supports partial name
    matching and filtering by department, location, or manager.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        search_text: Partial name to search (searches first name and last name)
        department: Filter by department name or code
        location: Filter by work location
        manager_id: Filter to show only this manager's direct reports
        status: Employee status filter: 'active', 'inactive', or 'all' (default: 'active')
        top: Maximum number of results to return (default: 50, max: 200)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 200:
        top = 200
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="search_employees",
        instance=instance, status="started",
        details={"search_text": search_text[:50] if search_text else None, "department": department, "top": top},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        if manager_id:
            _validate_identifier(manager_id, "manager_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="search_employees",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Build filter
    filters = []

    if search_text:
        safe_text = _sanitize_odata_string(search_text)
        filters.append(f"(substringof('{safe_text}',firstName) or substringof('{safe_text}',lastName) or substringof('{safe_text}',displayName))")

    if department:
        safe_dept = _sanitize_odata_string(department)
        filters.append(f"department eq '{safe_dept}'")

    if location:
        safe_loc = _sanitize_odata_string(location)
        filters.append(f"location eq '{safe_loc}'")

    if manager_id:
        safe_mgr = _sanitize_odata_string(manager_id)
        filters.append(f"manager eq '{safe_mgr}'")

    if status == "active":
        filters.append("status eq 'active' or status eq 't'")
    elif status == "inactive":
        filters.append("status eq 'inactive' or status eq 'f'")

    params = {
        "$select": "userId,firstName,lastName,displayName,email,hireDate,status,title,department,division,location,manager",
        "$format": "json",
        "$top": str(top)
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="search_employees",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    employees = []
    for entry in result.get("d", {}).get("results", []):
        employees.append({
            "user_id": entry.get("userId"),
            "display_name": entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip(),
            "email": entry.get("email"),
            "title": entry.get("title"),
            "department": entry.get("department"),
            "division": entry.get("division"),
            "location": entry.get("location"),
            "hire_date": entry.get("hireDate"),
            "status": entry.get("status"),
        })

    response_data = {
        "employees": employees,
        "count": len(employees),
        "search_criteria": {
            "search_text": search_text or None,
            "department": department or None,
            "location": location or None,
            "manager_id": manager_id or None,
            "status": status,
        }
    }

    _audit_log(
        event_type="tool_invocation", tool_name="search_employees",
        instance=instance, status="success",
        details={"records_returned": len(employees)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_employee_history(
    instance: str,
    user_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_compensation_changes: bool = False
) -> dict[str, Any]:
    """
    View an employee's job history including promotions, transfers, and title changes.

    Shows chronological job records with title, department, location, and manager
    for each period. Useful for reviewing career progression during reviews or
    retention conversations.

    Args:
        instance: The SuccessFactors instance/company ID
        user_id: The employee's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_compensation_changes: If True, also fetches salary history
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation", tool_name="get_employee_history",
        instance=instance, status="started",
        details={"user_id": user_id},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(user_id, "user_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_employee_history",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    safe_user_id = _sanitize_odata_string(user_id)

    params = {
        "$filter": f"userId eq '{safe_user_id}'",
        "$select": "userId,startDate,endDate,jobTitle,department,location,position,managerId,employeeClass,eventReason,emplStatus",
        "$orderby": "startDate desc",
        "$format": "json",
        "$top": "100"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/EmpJob", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_employee_history",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    history = []
    for entry in result.get("d", {}).get("results", []):
        history.append({
            "start_date": entry.get("startDate"),
            "end_date": entry.get("endDate"),
            "job_title": entry.get("jobTitle"),
            "department": entry.get("department"),
            "location": entry.get("location"),
            "position": entry.get("position"),
            "manager_id": entry.get("managerId"),
            "employee_class": entry.get("employeeClass"),
            "event_reason": entry.get("eventReason"),
            "employment_status": entry.get("emplStatus"),
        })

    response_data = {
        "user_id": user_id,
        "job_history": history,
        "record_count": len(history),
    }

    # Optionally fetch compensation history
    if include_compensation_changes:
        comp_params = {
            "$filter": f"userId eq '{safe_user_id}'",
            "$select": "userId,startDate,payGroup,payGrade",
            "$expand": "empPayCompRecurringNav",
            "$orderby": "startDate desc",
            "$format": "json",
            "$top": "50"
        }
        comp_result = _make_sf_odata_request(
            instance, "/odata/v2/EmpCompensation", data_center, environment,
            auth_user_id, auth_password, comp_params, request_id
        )
        if "error" not in comp_result:
            comp_history = []
            for entry in comp_result.get("d", {}).get("results", []):
                comp_record = {
                    "effective_date": entry.get("startDate"),
                    "pay_group": entry.get("payGroup"),
                    "pay_grade": entry.get("payGrade"),
                }
                recurring = entry.get("empPayCompRecurringNav", {})
                if isinstance(recurring, dict) and "results" in recurring:
                    comp_record["pay_components"] = [
                        {
                            "pay_component": r.get("payComponent"),
                            "amount": r.get("paycompvalue"),
                            "currency": r.get("currencyCode"),
                            "frequency": r.get("frequency"),
                        }
                        for r in recurring["results"]
                    ]
                comp_history.append(comp_record)
            response_data["compensation_history"] = comp_history

    _audit_log(
        event_type="tool_invocation", tool_name="get_employee_history",
        instance=instance, status="success",
        details={"user_id": user_id, "records_returned": len(history)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_team_roster(
    instance: str,
    manager_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_indirect_reports: bool = False,
    top: int = 100
) -> dict[str, Any]:
    """
    Get a manager's team roster with direct (and optionally indirect) reports.

    Shows all active team members with their job title, department, location,
    and hire date. Useful for org chart views, team planning, and 1-on-1 prep.

    Args:
        instance: The SuccessFactors instance/company ID
        manager_id: The manager's user ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_indirect_reports: If True, also fetches reports-of-reports (1 level deep)
        top: Maximum direct reports to return (default: 100, max: 200)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 200:
        top = 200
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_team_roster",
        instance=instance, status="started",
        details={"manager_id": manager_id, "include_indirect_reports": include_indirect_reports},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(manager_id, "manager_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_team_roster",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    safe_mgr = _sanitize_odata_string(manager_id)

    # Get direct reports
    params = {
        "$filter": f"manager eq '{safe_mgr}' and (status eq 'active' or status eq 't')",
        "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,division,location",
        "$format": "json",
        "$top": str(top)
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_team_roster",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    direct_reports = []
    for entry in result.get("d", {}).get("results", []):
        direct_reports.append({
            "user_id": entry.get("userId"),
            "display_name": entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip(),
            "email": entry.get("email"),
            "title": entry.get("title"),
            "department": entry.get("department"),
            "division": entry.get("division"),
            "location": entry.get("location"),
            "hire_date": entry.get("hireDate"),
        })

    response_data = {
        "manager_id": manager_id,
        "direct_reports": direct_reports,
        "direct_report_count": len(direct_reports),
    }

    # Optionally fetch indirect reports (1 level)
    if include_indirect_reports and direct_reports:
        indirect_reports = []
        # Query reports for each direct report (cap at 10 sub-queries to avoid timeout)
        for dr in direct_reports[:10]:
            dr_id = dr["user_id"]
            if not dr_id:
                continue
            safe_dr = _sanitize_odata_string(dr_id)
            sub_params = {
                "$filter": f"manager eq '{safe_dr}' and (status eq 'active' or status eq 't')",
                "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,location",
                "$format": "json",
                "$top": "50"
            }
            sub_result = _make_sf_odata_request(
                instance, "/odata/v2/User", data_center, environment,
                auth_user_id, auth_password, sub_params, request_id
            )
            if "error" not in sub_result:
                for entry in sub_result.get("d", {}).get("results", []):
                    indirect_reports.append({
                        "user_id": entry.get("userId"),
                        "display_name": entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip(),
                        "title": entry.get("title"),
                        "department": entry.get("department"),
                        "location": entry.get("location"),
                        "reports_to": dr_id,
                    })

        response_data["indirect_reports"] = indirect_reports
        response_data["indirect_report_count"] = len(indirect_reports)
        response_data["total_team_size"] = len(direct_reports) + len(indirect_reports)
    else:
        response_data["total_team_size"] = len(direct_reports)

    _audit_log(
        event_type="tool_invocation", tool_name="get_team_roster",
        instance=instance, status="success",
        details={"manager_id": manager_id, "direct_count": len(direct_reports), "total": response_data["total_team_size"]},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# HR OPERATIONS TOOLS: Time Off & Leave Management
# =============================================================================


@mcp.tool()
def get_time_off_balances(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    as_of_date: str = ""
) -> dict[str, Any]:
    """
    Check vacation, PTO, and sick leave balances for one or more employees.

    Quickly answer 'How much PTO do I have?' for any employee. Supports
    checking multiple employees at once.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) - single ID or comma-separated (max 50)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        as_of_date: Check balance as of this date (YYYY-MM-DD). Defaults to today.
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation", tool_name="get_time_off_balances",
        instance=instance, status="started",
        details={"user_ids_count": len(user_ids.split(","))},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_ids(user_ids, "user_ids")
        if as_of_date:
            _validate_date(as_of_date, "as_of_date")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_time_off_balances",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    id_list = [uid.strip() for uid in user_ids.split(",")][:50]

    all_balances = []
    for uid in id_list:
        safe_uid = _sanitize_odata_string(uid)
        params = {
            "$filter": f"userId eq '{safe_uid}'",
            "$format": "json",
            "$top": "100"
        }

        result = _make_sf_odata_request(
            instance, "/odata/v2/EmpTimeAccountBalance", data_center, environment,
            auth_user_id, auth_password, params, request_id
        )

        if "error" in result:
            all_balances.append({"user_id": uid, "error": result.get("error")})
            continue

        balances = []
        for entry in result.get("d", {}).get("results", []):
            balances.append({
                "account_type": entry.get("timeAccountType") or entry.get("timeAccount"),
                "balance": entry.get("balance"),
                "as_of_date": entry.get("asOfAccountingPeriodEnd") or as_of_date or str(date.today()),
            })

        all_balances.append({
            "user_id": uid,
            "balances": balances,
            "account_count": len(balances),
        })

    response_data = {
        "employees": all_balances,
        "count": len(all_balances),
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_time_off_balances",
        instance=instance, status="success",
        details={"employees_queried": len(all_balances)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_upcoming_time_off(
    instance: str,
    start_date: str,
    end_date: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    manager_id: str = "",
    status: str = "approved",
    top: int = 200
) -> dict[str, Any]:
    """
    See who is out or taking time off in a date range (team absence calendar).

    Shows all approved (or pending) absences for a period. Filter by department
    or manager to see just your team. Useful for scheduling meetings and
    planning coverage.

    Args:
        instance: The SuccessFactors instance/company ID
        start_date: Start of date range (YYYY-MM-DD)
        end_date: End of date range (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department name or code
        manager_id: Filter to a specific manager's team
        status: Filter by approval status: 'approved', 'pending', or 'all' (default: 'approved')
        top: Maximum results (default: 200, max: 500)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time_ts = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_upcoming_time_off",
        instance=instance, status="started",
        details={"start_date": start_date, "end_date": end_date, "department": department},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_date(start_date, "start_date")
        _validate_date(end_date, "end_date")
        if manager_id:
            _validate_identifier(manager_id, "manager_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_upcoming_time_off",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time_ts) * 1000)
        return {"error": str(e)}

    # Build filter for EmployeeTime
    filters = [
        f"startDate le datetime'{end_date}T23:59:59'",
        f"endDate ge datetime'{start_date}T00:00:00'"
    ]

    if status == "approved":
        filters.append("approvalStatus eq 'APPROVED'")
    elif status == "pending":
        filters.append("approvalStatus eq 'PENDING'")

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,startDate,endDate,timeType,approvalStatus,quantityInDays,quantityInHours",
        "$expand": "userIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "startDate asc"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/EmployeeTime", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_upcoming_time_off",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time_ts) * 1000)
        return result

    absences = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userIdNav", {}) or {}
        emp_department = user_nav.get("department", "")
        emp_manager = user_nav.get("manager", "")

        # Apply client-side filters if needed
        if department and emp_department and department.lower() not in emp_department.lower():
            continue
        if manager_id and emp_manager and manager_id != emp_manager:
            continue

        absences.append({
            "user_id": entry.get("userId"),
            "employee_name": user_nav.get("displayName") or f"{user_nav.get('firstName', '')} {user_nav.get('lastName', '')}".strip() if user_nav else entry.get("userId"),
            "department": emp_department,
            "start_date": entry.get("startDate"),
            "end_date": entry.get("endDate"),
            "time_type": entry.get("timeType"),
            "status": entry.get("approvalStatus"),
            "days": entry.get("quantityInDays"),
            "hours": entry.get("quantityInHours"),
        })

    response_data = {
        "date_range": {"start": start_date, "end": end_date},
        "absences": absences,
        "count": len(absences),
        "filters_applied": {
            "status": status,
            "department": department or None,
            "manager_id": manager_id or None,
        }
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_upcoming_time_off",
        instance=instance, status="success",
        details={"absences_returned": len(absences)},
        request_id=request_id, duration_ms=(time.time() - start_time_ts) * 1000
    )

    return response_data


@mcp.tool()
def get_time_off_requests(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    user_id: str = "",
    status: str = "pending",
    from_date: str = "",
    top: int = 50
) -> dict[str, Any]:
    """
    View time-off requests for approval tracking.

    Shows pending, approved, or rejected time-off requests. Filter by employee
    or view all requests visible to you. Useful for managers reviewing approvals.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        user_id: Filter to a specific employee's requests (optional)
        status: Filter by status: 'pending', 'approved', 'rejected', 'cancelled', or 'all' (default: 'pending')
        from_date: Only show requests created on or after this date (YYYY-MM-DD)
        top: Maximum results (default: 50, max: 200)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 200:
        top = 200
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_time_off_requests",
        instance=instance, status="started",
        details={"user_id": user_id or "all", "status": status},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        if user_id:
            _validate_identifier(user_id, "user_id")
        if from_date:
            _validate_date(from_date, "from_date")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_time_off_requests",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Build filter
    filters = []

    if user_id:
        safe_uid = _sanitize_odata_string(user_id)
        filters.append(f"userId eq '{safe_uid}'")

    status_map = {
        "pending": "PENDING",
        "approved": "APPROVED",
        "rejected": "REJECTED",
        "cancelled": "CANCELLED",
    }
    if status != "all" and status in status_map:
        filters.append(f"approvalStatus eq '{status_map[status]}'")

    if from_date:
        filters.append(f"createdDate ge datetime'{from_date}T00:00:00'")

    params = {
        "$select": "userId,startDate,endDate,timeType,approvalStatus,quantityInDays,quantityInHours,createdDate",
        "$expand": "userIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "createdDate desc"
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/EmployeeTime", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_time_off_requests",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    requests_list = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userIdNav", {}) or {}
        requests_list.append({
            "user_id": entry.get("userId"),
            "employee_name": user_nav.get("displayName") or f"{user_nav.get('firstName', '')} {user_nav.get('lastName', '')}".strip() if user_nav else entry.get("userId"),
            "start_date": entry.get("startDate"),
            "end_date": entry.get("endDate"),
            "time_type": entry.get("timeType"),
            "status": entry.get("approvalStatus"),
            "days": entry.get("quantityInDays"),
            "hours": entry.get("quantityInHours"),
            "submitted_date": entry.get("createdDate"),
        })

    response_data = {
        "requests": requests_list,
        "count": len(requests_list),
        "filters_applied": {
            "user_id": user_id or None,
            "status": status,
            "from_date": from_date or None,
        }
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_time_off_requests",
        instance=instance, status="success",
        details={"requests_returned": len(requests_list)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# HR OPERATIONS TOOLS: Hiring & Onboarding
# =============================================================================


@mcp.tool()
def get_open_requisitions(
    instance: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    hiring_manager_id: str = "",
    location: str = "",
    status: str = "open",
    top: int = 100
) -> dict[str, Any]:
    """
    List job requisitions with status and hiring manager.

    Shows open (or all) job requisitions for tracking the hiring pipeline.
    Filter by department, hiring manager, or location.

    Args:
        instance: The SuccessFactors instance/company ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        hiring_manager_id: Filter by hiring manager's user ID
        location: Filter by work location
        status: Requisition status: 'open', 'filled', 'closed', or 'all' (default: 'open')
        top: Maximum results (default: 100, max: 500)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_open_requisitions",
        instance=instance, status="started",
        details={"department": department, "status": status},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        if hiring_manager_id:
            _validate_identifier(hiring_manager_id, "hiring_manager_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_open_requisitions",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Build filter
    filters = []

    status_map = {
        "open": "Open",
        "filled": "Filled",
        "closed": "Closed",
    }
    if status != "all" and status in status_map:
        safe_status = _sanitize_odata_string(status_map[status])
        filters.append(f"status eq '{safe_status}'")

    if department:
        safe_dept = _sanitize_odata_string(department)
        filters.append(f"department eq '{safe_dept}'")

    if hiring_manager_id:
        safe_hm = _sanitize_odata_string(hiring_manager_id)
        filters.append(f"hiringManagerId eq '{safe_hm}'")

    if location:
        safe_loc = _sanitize_odata_string(location)
        filters.append(f"location eq '{safe_loc}'")

    params = {
        "$select": "jobReqId,jobTitle,department,location,status,numberOpenings,hiringManagerId,recruiterName,createdDateTime,lastModifiedDateTime",
        "$format": "json",
        "$top": str(top),
        "$orderby": "createdDateTime desc"
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/JobRequisition", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_open_requisitions",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    requisitions = []
    for entry in result.get("d", {}).get("results", []):
        requisitions.append({
            "requisition_id": entry.get("jobReqId"),
            "job_title": entry.get("jobTitle"),
            "department": entry.get("department"),
            "location": entry.get("location"),
            "status": entry.get("status"),
            "openings": entry.get("numberOpenings"),
            "hiring_manager_id": entry.get("hiringManagerId"),
            "recruiter": entry.get("recruiterName"),
            "created_date": entry.get("createdDateTime"),
            "last_modified": entry.get("lastModifiedDateTime"),
        })

    response_data = {
        "requisitions": requisitions,
        "count": len(requisitions),
        "filters_applied": {
            "status": status,
            "department": department or None,
            "hiring_manager_id": hiring_manager_id or None,
            "location": location or None,
        }
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_open_requisitions",
        instance=instance, status="success",
        details={"requisitions_returned": len(requisitions)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_candidate_pipeline(
    instance: str,
    requisition_id: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    include_rejected: bool = False,
    top: int = 100
) -> dict[str, Any]:
    """
    Track candidates for a job requisition through hiring stages.

    Shows all applicants for a specific job requisition with their current
    stage, application date, and status. Useful for hiring managers to see
    the candidate funnel at a glance.

    Args:
        instance: The SuccessFactors instance/company ID
        requisition_id: The job requisition ID
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        include_rejected: If True, include rejected candidates (default: False)
        top: Maximum results (default: 100, max: 500)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_candidate_pipeline",
        instance=instance, status="started",
        details={"requisition_id": requisition_id},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_identifier(requisition_id, "requisition_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_candidate_pipeline",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    safe_req_id = _sanitize_odata_string(requisition_id)
    filter_expr = f"jobReqId eq '{safe_req_id}'"

    if not include_rejected:
        filter_expr += " and statusId ne 3"  # 3 is commonly Rejected

    params = {
        "$filter": filter_expr,
        "$select": "applicationId,candidateId,jobReqId,statusId,applicationDate,lastModifiedDateTime",
        "$expand": "candidateNav,statusNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "lastModifiedDateTime desc"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/JobApplication", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_candidate_pipeline",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    candidates = []
    stage_counts = {}
    for entry in result.get("d", {}).get("results", []):
        candidate_nav = entry.get("candidateNav", {}) or {}
        status_nav = entry.get("statusNav", {}) or {}
        stage = status_nav.get("label") or status_nav.get("appStatusName") or str(entry.get("statusId", "Unknown"))

        stage_counts[stage] = stage_counts.get(stage, 0) + 1

        candidates.append({
            "application_id": entry.get("applicationId"),
            "candidate_id": entry.get("candidateId"),
            "candidate_name": f"{candidate_nav.get('firstName', '')} {candidate_nav.get('lastName', '')}".strip() if candidate_nav else "Unknown",
            "email": candidate_nav.get("email") if candidate_nav else None,
            "current_stage": stage,
            "application_date": entry.get("applicationDate"),
            "last_updated": entry.get("lastModifiedDateTime"),
        })

    response_data = {
        "requisition_id": requisition_id,
        "candidates": candidates,
        "count": len(candidates),
        "by_stage": stage_counts,
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_candidate_pipeline",
        instance=instance, status="success",
        details={"requisition_id": requisition_id, "candidates_returned": len(candidates)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_new_hires(
    instance: str,
    start_date_from: str,
    start_date_to: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    top: int = 100
) -> dict[str, Any]:
    """
    List recent and upcoming new hires for onboarding planning.

    Shows employees hired within a date range with their job details. Useful for
    HR coordinators planning onboarding, equipment, and access provisioning.

    Args:
        instance: The SuccessFactors instance/company ID
        start_date_from: Show hires starting on or after this date (YYYY-MM-DD)
        start_date_to: Show hires starting on or before this date (YYYY-MM-DD)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_new_hires",
        instance=instance, status="started",
        details={"start_date_from": start_date_from, "start_date_to": start_date_to},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_date(start_date_from, "start_date_from")
        _validate_date(start_date_to, "start_date_to")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_new_hires",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Query users by hire date range
    filters = [
        f"hireDate ge datetime'{start_date_from}T00:00:00'",
        f"hireDate le datetime'{start_date_to}T23:59:59'"
    ]

    if department:
        safe_dept = _sanitize_odata_string(department)
        filters.append(f"department eq '{safe_dept}'")

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,firstName,lastName,displayName,email,hireDate,title,department,division,location,manager",
        "$format": "json",
        "$top": str(top),
        "$orderby": "hireDate asc"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_new_hires",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    new_hires = []
    for entry in result.get("d", {}).get("results", []):
        new_hires.append({
            "user_id": entry.get("userId"),
            "display_name": entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip(),
            "email": entry.get("email"),
            "hire_date": entry.get("hireDate"),
            "title": entry.get("title"),
            "department": entry.get("department"),
            "division": entry.get("division"),
            "location": entry.get("location"),
            "manager_id": entry.get("manager"),
        })

    response_data = {
        "new_hires": new_hires,
        "count": len(new_hires),
        "date_range": {"from": start_date_from, "to": start_date_to},
        "filters_applied": {"department": department or None},
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_new_hires",
        instance=instance, status="success",
        details={"new_hires_returned": len(new_hires)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# HR OPERATIONS TOOLS: Compliance & Reporting
# =============================================================================


@mcp.tool()
def get_terminations(
    instance: str,
    from_date: str,
    to_date: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    top: int = 100
) -> dict[str, Any]:
    """
    List terminated employees in a date range for exit processing and compliance.

    Shows employees whose employment ended within the specified period. Useful for
    exit processing, compliance reporting, and attrition analysis.

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
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_terminations",
        instance=instance, status="started",
        details={"from_date": from_date, "to_date": to_date},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_date(from_date, "from_date")
        _validate_date(to_date, "to_date")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_terminations",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Query EmpEmployment for terminated records
    filters = [
        f"endDate ge datetime'{from_date}T00:00:00'",
        f"endDate le datetime'{to_date}T23:59:59'"
    ]

    params = {
        "$filter": " and ".join(filters),
        "$select": "userId,startDate,endDate,originalStartDate,lastDateWorked,payrollEndDate",
        "$expand": "userNav,personNav,jobInfoNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "endDate desc"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/EmpEmployment", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_terminations",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    terminations = []
    for entry in result.get("d", {}).get("results", []):
        user_nav = entry.get("userNav", {}) or {}
        person_nav = entry.get("personNav", {}) or {}
        job_nav = entry.get("jobInfoNav", {}) or {}

        # Handle jobInfoNav which may be a collection
        job_info = {}
        if isinstance(job_nav, dict) and "results" in job_nav:
            jobs = job_nav["results"]
            if jobs:
                job_info = jobs[0]  # Most recent
        elif isinstance(job_nav, dict):
            job_info = job_nav

        emp_department = job_info.get("department") or user_nav.get("department", "")

        # Apply department filter if specified
        if department and emp_department and department.lower() not in emp_department.lower():
            continue

        # Calculate tenure if possible
        tenure_years = None
        orig_start = entry.get("originalStartDate") or entry.get("startDate")
        end_date_val = entry.get("endDate")
        if orig_start and end_date_val:
            try:
                # Try parsing SAP date formats
                start_str = orig_start if isinstance(orig_start, str) else str(orig_start)
                end_str = end_date_val if isinstance(end_date_val, str) else str(end_date_val)
                if "T" in start_str and "T" in end_str:
                    start_dt = datetime.strptime(start_str[:10], "%Y-%m-%d")
                    end_dt = datetime.strptime(end_str[:10], "%Y-%m-%d")
                    tenure_years = round((end_dt - start_dt).days / 365.25, 1)
            except (ValueError, TypeError):
                pass

        terminations.append({
            "user_id": entry.get("userId"),
            "display_name": user_nav.get("displayName") or f"{person_nav.get('firstName', '')} {person_nav.get('lastName', '')}".strip() or entry.get("userId"),
            "department": emp_department,
            "title": job_info.get("jobTitle"),
            "original_start_date": entry.get("originalStartDate"),
            "termination_date": entry.get("endDate"),
            "last_date_worked": entry.get("lastDateWorked"),
            "tenure_years": tenure_years,
        })

    response_data = {
        "terminations": terminations,
        "count": len(terminations),
        "date_range": {"from": from_date, "to": to_date},
        "filters_applied": {"department": department or None},
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_terminations",
        instance=instance, status="success",
        details={"terminations_returned": len(terminations)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_employees_missing_data(
    instance: str,
    check_fields: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    department: str = "",
    top: int = 100
) -> dict[str, Any]:
    """
    Find employees with incomplete profiles for compliance audits.

    Checks for missing email, phone, address, or emergency contact data across
    active employees. Returns a list of employees with gaps and a compliance rate.

    Args:
        instance: The SuccessFactors instance/company ID
        check_fields: Comma-separated fields to check: 'email', 'phone', 'address', 'emergency_contact' (e.g., 'email,phone')
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        department: Filter by department
        top: Maximum results (default: 100, max: 500)
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_employees_missing_data",
        instance=instance, status="started",
        details={"check_fields": check_fields},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_employees_missing_data",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    valid_fields = {"email", "phone", "address", "emergency_contact"}
    requested_fields = [f.strip().lower() for f in check_fields.split(",")]
    invalid = [f for f in requested_fields if f not in valid_fields]
    if invalid:
        return {"error": f"Invalid check_fields: {', '.join(invalid)}. Valid options: {', '.join(sorted(valid_fields))}"}

    # Get active employees
    user_filters = ["status eq 'active' or status eq 't'"]
    if department:
        safe_dept = _sanitize_odata_string(department)
        user_filters.append(f"department eq '{safe_dept}'")

    user_params = {
        "$filter": " and ".join(user_filters),
        "$select": "userId,firstName,lastName,displayName,email,department,hireDate",
        "$format": "json",
        "$top": str(min(top * 2, 1000))  # Fetch more to account for filtering
    }

    user_result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, user_params, request_id
    )

    if "error" in user_result:
        _audit_log(event_type="tool_invocation", tool_name="get_employees_missing_data",
                   instance=instance, status="error", details={"error": user_result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return user_result

    users = user_result.get("d", {}).get("results", [])
    total_employees = len(users)

    # Map fields to entities
    field_entity_map = {
        "email": "PerEmail",
        "phone": "PerPhone",
        "address": "PerAddress",
        "emergency_contact": "PerEmergencyContacts",
    }

    # For each field, get employees who have data
    employees_with_data = {}
    for field in requested_fields:
        entity = field_entity_map[field]
        data_params = {
            "$select": "personIdExternal",
            "$format": "json",
            "$top": "1000"
        }
        data_result = _make_sf_odata_request(
            instance, f"/odata/v2/{entity}", data_center, environment,
            auth_user_id, auth_password, data_params, request_id
        )
        if "error" not in data_result:
            ids_with_data = set()
            for entry in data_result.get("d", {}).get("results", []):
                pid = entry.get("personIdExternal")
                if pid:
                    ids_with_data.add(pid)
            employees_with_data[field] = ids_with_data
        else:
            employees_with_data[field] = set()

    # Find employees missing data
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
            employees_missing.append({
                "user_id": uid,
                "display_name": user.get("displayName") or f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                "department": user.get("department"),
                "hire_date": user.get("hireDate"),
                "missing_fields": missing_fields,
            })

    # Cap results
    employees_missing = employees_missing[:top]

    compliance_rate = round(((total_employees - len(employees_missing)) / total_employees * 100), 1) if total_employees > 0 else 100.0

    response_data = {
        "employees_with_issues": employees_missing,
        "count": len(employees_missing),
        "total_employees_checked": total_employees,
        "compliance_rate_percent": compliance_rate,
        "fields_checked": requested_fields,
        "filters_applied": {"department": department or None},
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_employees_missing_data",
        instance=instance, status="success",
        details={"issues_found": len(employees_missing), "compliance_rate": compliance_rate},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
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
    top: int = 100
) -> dict[str, Any]:
    """
    Find employees with upcoming work anniversaries for recognition programs.

    Searches for active employees whose hire date anniversary falls within the
    specified date range. Optionally filter to milestone years only (1, 5, 10, 15, 20, 25+).

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
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_anniversary_employees",
        instance=instance, status="started",
        details={"from_date": from_date, "to_date": to_date, "milestone_years_only": milestone_years_only},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_date(from_date, "from_date")
        _validate_date(to_date, "to_date")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_anniversary_employees",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Get active employees with hire dates
    user_filters = ["status eq 'active' or status eq 't'"]
    if department:
        safe_dept = _sanitize_odata_string(department)
        user_filters.append(f"department eq '{safe_dept}'")

    params = {
        "$filter": " and ".join(user_filters),
        "$select": "userId,firstName,lastName,displayName,hireDate,department,title,manager",
        "$format": "json",
        "$top": "1000"
    }

    result = _make_sf_odata_request(
        instance, "/odata/v2/User", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_anniversary_employees",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    # Parse target date range
    from_dt = datetime.strptime(from_date, "%Y-%m-%d").date()
    to_dt = datetime.strptime(to_date, "%Y-%m-%d").date()
    target_year = from_dt.year

    milestone_years = {1, 5, 10, 15, 20, 25, 30, 35, 40}

    anniversaries = []
    for entry in result.get("d", {}).get("results", []):
        hire_date_raw = entry.get("hireDate")
        if not hire_date_raw:
            continue

        # Parse hire date (may be in various formats)
        hire_dt = None
        try:
            if isinstance(hire_date_raw, str):
                if "/Date(" in hire_date_raw:
                    # SAP date format: /Date(timestamp)/
                    ts = int(hire_date_raw.split("(")[1].split(")")[0].split("+")[0].split("-")[0])
                    hire_dt = date.fromtimestamp(ts / 1000)
                elif "T" in hire_date_raw:
                    hire_dt = datetime.strptime(hire_date_raw[:10], "%Y-%m-%d").date()
                else:
                    hire_dt = datetime.strptime(hire_date_raw[:10], "%Y-%m-%d").date()
        except (ValueError, TypeError, IndexError):
            continue

        if not hire_dt:
            continue

        # Calculate anniversary date in target year
        try:
            anniversary_dt = hire_dt.replace(year=target_year)
        except ValueError:
            # Handle Feb 29 leap year edge case
            anniversary_dt = date(target_year, 3, 1)

        # Check if anniversary falls in the range
        if from_dt <= anniversary_dt <= to_dt:
            years_of_service = target_year - hire_dt.year
            if years_of_service <= 0:
                continue

            is_milestone = years_of_service in milestone_years

            if milestone_years_only and not is_milestone:
                continue

            anniversaries.append({
                "user_id": entry.get("userId"),
                "display_name": entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip(),
                "department": entry.get("department"),
                "title": entry.get("title"),
                "hire_date": hire_date_raw,
                "anniversary_date": anniversary_dt.isoformat(),
                "years_of_service": years_of_service,
                "is_milestone": is_milestone,
                "manager_id": entry.get("manager"),
            })

    # Sort by anniversary date
    anniversaries.sort(key=lambda x: x.get("anniversary_date", ""))
    anniversaries = anniversaries[:top]

    milestone_count = sum(1 for a in anniversaries if a.get("is_milestone"))

    response_data = {
        "anniversaries": anniversaries,
        "count": len(anniversaries),
        "milestone_count": milestone_count,
        "date_range": {"from": from_date, "to": to_date},
        "filters_applied": {
            "milestone_years_only": milestone_years_only,
            "department": department or None,
        },
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_anniversary_employees",
        instance=instance, status="success",
        details={"anniversaries_found": len(anniversaries), "milestone_count": milestone_count},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# HR OPERATIONS TOOLS: Performance & Compensation
# =============================================================================


@mcp.tool()
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
    top: int = 100
) -> dict[str, Any]:
    """
    Track performance review form completion across the organization.

    Shows the status of performance review forms (not started, in progress,
    completed). Useful for HR to monitor review cycle progress and follow up
    with managers who haven't completed reviews.

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
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    if top > 500:
        top = 500
    if top < 1:
        top = 1

    _audit_log(
        event_type="tool_invocation", tool_name="get_performance_review_status",
        instance=instance, status="started",
        details={"form_template_id": form_template_id or "all", "status": status or "all"},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        if form_template_id:
            _validate_identifier(form_template_id, "form_template_id")
        if manager_id:
            _validate_identifier(manager_id, "manager_id")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_performance_review_status",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    # Build filter for FormHeader
    filters = []

    if form_template_id:
        safe_template = _sanitize_odata_string(form_template_id)
        filters.append(f"formTemplateId eq '{safe_template}'")

    # Map status to formDataStatus values
    # Common values: 1=Not Started, 2=In Progress, 3=Completed, 4=Sent Back
    status_map = {
        "not_started": "1",
        "in_progress": "2",
        "completed": "3",
    }
    if status and status in status_map:
        filters.append(f"formDataStatus eq {status_map[status]}")

    params = {
        "$select": "formDataId,formTemplateId,formTemplateName,formSubjectId,formDataStatus,formLastModifiedDate,formDueDate",
        "$expand": "formSubjectIdNav",
        "$format": "json",
        "$top": str(top),
        "$orderby": "formLastModifiedDate desc"
    }

    if filters:
        params["$filter"] = " and ".join(filters)

    result = _make_sf_odata_request(
        instance, "/odata/v2/FormHeader", data_center, environment,
        auth_user_id, auth_password, params, request_id
    )

    if "error" in result:
        _audit_log(event_type="tool_invocation", tool_name="get_performance_review_status",
                   instance=instance, status="error", details={"error": result.get("error")},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return result

    # Map status codes to labels
    status_labels = {"1": "Not Started", "2": "In Progress", "3": "Completed", "4": "Sent Back"}

    reviews = []
    status_counts = {}
    for entry in result.get("d", {}).get("results", []):
        subject_nav = entry.get("formSubjectIdNav", {}) or {}

        # Apply client-side filters
        emp_department = subject_nav.get("department", "")
        emp_manager = subject_nav.get("manager", "")

        if department and emp_department and department.lower() not in emp_department.lower():
            continue
        if manager_id and emp_manager and manager_id != emp_manager:
            continue

        form_status = str(entry.get("formDataStatus", ""))
        status_label = status_labels.get(form_status, form_status)
        status_counts[status_label] = status_counts.get(status_label, 0) + 1

        reviews.append({
            "form_id": entry.get("formDataId"),
            "template_name": entry.get("formTemplateName"),
            "subject_user_id": entry.get("formSubjectId"),
            "subject_name": subject_nav.get("displayName") or f"{subject_nav.get('firstName', '')} {subject_nav.get('lastName', '')}".strip() if subject_nav else entry.get("formSubjectId"),
            "department": emp_department,
            "status": status_label,
            "due_date": entry.get("formDueDate"),
            "last_modified": entry.get("formLastModifiedDate"),
        })

    response_data = {
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

    _audit_log(
        event_type="tool_invocation", tool_name="get_performance_review_status",
        instance=instance, status="success",
        details={"reviews_returned": len(reviews), "by_status": status_counts},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


@mcp.tool()
def get_compensation_details(
    instance: str,
    user_ids: str,
    data_center: str,
    environment: str,
    auth_user_id: str,
    auth_password: str,
    effective_date: str = ""
) -> dict[str, Any]:
    """
    Get compensation breakdown for employees including base pay and pay components.

    Shows current compensation details with recurring and non-recurring pay
    components. Useful for compensation reviews, equity analysis, and HR inquiries.

    Args:
        instance: The SuccessFactors instance/company ID
        user_ids: Employee user ID(s) - single ID or comma-separated (max 20)
        data_center: SAP data center code (e.g., 'DC55', 'DC10', 'DC4')
        environment: Environment type ('preview', 'production', 'sales_demo')
        auth_user_id: SuccessFactors user ID for authentication (required)
        auth_password: SuccessFactors password for authentication (required)
        effective_date: Show compensation as of this date (YYYY-MM-DD). Defaults to latest.
    """
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()

    _audit_log(
        event_type="tool_invocation", tool_name="get_compensation_details",
        instance=instance, status="started",
        details={"user_ids_count": len(user_ids.split(","))},
        request_id=request_id
    )

    try:
        _validate_identifier(instance, "instance")
        _validate_ids(user_ids, "user_ids")
        if effective_date:
            _validate_date(effective_date, "effective_date")
    except ValueError as e:
        _audit_log(event_type="validation_error", tool_name="get_compensation_details",
                   instance=instance, status="failure", details={"error": str(e)},
                   request_id=request_id, duration_ms=(time.time() - start_time) * 1000)
        return {"error": str(e)}

    id_list = [uid.strip() for uid in user_ids.split(",")][:20]

    all_compensation = []
    for uid in id_list:
        safe_uid = _sanitize_odata_string(uid)
        filter_expr = f"userId eq '{safe_uid}'"

        if effective_date:
            filter_expr += f" and startDate le datetime'{effective_date}T23:59:59'"

        params = {
            "$filter": filter_expr,
            "$select": "userId,startDate,payGroup,payGrade,compensatedHours",
            "$expand": "empPayCompRecurringNav,empPayCompNonRecurringNav",
            "$format": "json",
            "$top": "5",
            "$orderby": "startDate desc"
        }

        result = _make_sf_odata_request(
            instance, "/odata/v2/EmpCompensation", data_center, environment,
            auth_user_id, auth_password, params, request_id
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

        # Extract recurring pay components
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

        # Extract non-recurring pay components
        non_recurring_nav = latest.get("empPayCompNonRecurringNav", {})
        if isinstance(non_recurring_nav, dict) and "results" in non_recurring_nav:
            comp_data["non_recurring_components"] = [
                {
                    "pay_component": r.get("payComponent"),
                    "amount": r.get("value"),
                    "currency": r.get("currencyCode"),
                }
                for r in non_recurring_nav["results"]
            ]

        all_compensation.append(comp_data)

    response_data = {
        "employees": all_compensation,
        "count": len(all_compensation),
    }

    _audit_log(
        event_type="tool_invocation", tool_name="get_compensation_details",
        instance=instance, status="success",
        details={"employees_queried": len(all_compensation)},
        request_id=request_id, duration_ms=(time.time() - start_time) * 1000
    )

    return response_data


# =============================================================================
# SECURITY: API Key Middleware
# =============================================================================

class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate API key for MCP endpoint protection.

    Accepts API key via:
    - X-API-Key header
    - Authorization: Bearer <key> header
    """

    async def dispatch(self, request, call_next):
        # Skip auth for health check endpoints
        if request.url.path in ["/health", "/healthz", "/"]:
            return await call_next(request)

        # Check API key if configured
        if MCP_API_KEY:
            client_key = request.headers.get("X-API-Key")
            if not client_key:
                # Try Authorization header
                auth_header = request.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    client_key = auth_header[7:]

            if client_key != MCP_API_KEY:
                _audit_log(
                    event_type="authentication",
                    status="failure",
                    details={
                        "reason": "invalid_api_key",
                        "path": str(request.url.path),
                        "has_key": bool(client_key)
                    }
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"}
                )

        return await call_next(request)


if __name__ == "__main__":
    import sys
    import asyncio
    
    # Check if PORT env var is set (Cloud Run deployment)
    # If not, assume we're running in stdio mode for Claude Desktop
    if os.environ.get("PORT"):
        # HTTP mode for Cloud Run
        import uvicorn
        port = int(os.environ.get("PORT", 8080))
        
        # Build middleware list for HTTP app
        middleware_list = []
        if MCP_API_KEY:
            from starlette.middleware import Middleware as StarletteMiddleware
            middleware_list.append(StarletteMiddleware(APIKeyMiddleware))
        
        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        # Stdio mode for Claude Desktop
        asyncio.run(mcp.run())

    # Create HTTP app with middleware
    app = mcp.http_app(
        transport="streamable-http",
        middleware=middleware_list if middleware_list else None
    )

    # Run with uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)
