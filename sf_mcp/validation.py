"""Input validation functions and patterns for OData parameters."""

import re
import urllib.parse
from datetime import datetime

from sf_mcp.config import MAX_FILTER_LENGTH

# Patterns for validating OData input parameters
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")
SAFE_IDS_PATTERN = re.compile(r"^[a-zA-Z0-9_\-,]+$")
SAFE_LOCALE_PATTERN = re.compile(r"^[a-zA-Z]{2}(-[a-zA-Z]{2})?$")
SAFE_ENTITY_PATH_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\('[a-zA-Z0-9_\-]+'\))?$")
SAFE_SELECT_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_,/]*$")
SAFE_ORDERBY_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_,/ ]*(asc|desc)?$", re.IGNORECASE)
SAFE_EXPAND_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_,/]*$")

ODATA_FILTER_BLOCKLIST = {
    "$batch",
    "$metadata",
    "$value",
    "$count",
    "$ref",
    "$links",
    "javascript:",
    "script>",
    "<script",
    "onerror",
    "onload",
    "onclick",
    "onmouseover",
    "onfocus",
    "eval(",
    "expression(",
}

# Map of validator names to functions (used by the sf_tool decorator)
VALIDATORS = {}


def _register(name):
    """Decorator to register a validator by name."""

    def decorator(fn):
        VALIDATORS[name] = fn
        return fn

    return decorator


@_register("identifier")
def validate_identifier(value: str, field_name: str) -> str:
    """Validate that a value contains only safe identifier characters."""
    if not value or not SAFE_IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"Invalid {field_name}: must contain only alphanumeric characters, underscores, and hyphens")
    return value


@_register("ids")
def validate_ids(value: str, field_name: str) -> str:
    """Validate comma-separated IDs contain only safe characters."""
    if not value or not SAFE_IDS_PATTERN.match(value):
        raise ValueError(
            f"Invalid {field_name}: must contain only alphanumeric characters, underscores, hyphens, and commas"
        )
    return value


@_register("locale")
def validate_locale(value: str, field_name: str = "locale") -> str:
    """Validate locale format (e.g., 'en-US', 'de')."""
    if not SAFE_LOCALE_PATTERN.match(value):
        raise ValueError(f"Invalid locale format: {value}. Expected format like 'en-US' or 'en'")
    return value


def sanitize_odata_string(value: str) -> str:
    """Sanitize a string value for use in OData queries by escaping single quotes."""
    return value.replace("'", "''")


@_register("entity_path")
def validate_entity_path(value: str, field_name: str = "entity") -> str:
    """Validate OData entity path (e.g., 'User', 'User('admin')')."""
    if not value or not SAFE_ENTITY_PATH_PATTERN.match(value):
        raise ValueError("Invalid entity: must be a valid OData entity name (e.g., 'User', 'Position')")
    return value


@_register("select")
def validate_select(value: str, field_name: str = "select") -> str:
    """Validate OData $select parameter."""
    if not SAFE_SELECT_PATTERN.match(value):
        raise ValueError("Invalid select: must contain only valid field names separated by commas")
    return value


@_register("orderby")
def validate_orderby(value: str, field_name: str = "orderby") -> str:
    """Validate OData $orderby parameter."""
    if not SAFE_ORDERBY_PATTERN.match(value):
        raise ValueError("Invalid orderby: must contain valid field names with optional 'asc' or 'desc'")
    return value


@_register("expand")
def validate_expand(value: str, field_name: str = "expand") -> str:
    """Validate OData $expand parameter."""
    if not SAFE_EXPAND_PATTERN.match(value):
        raise ValueError("Invalid expand: must contain valid navigation property names")
    return value


@_register("odata_filter")
def validate_odata_filter(value: str, field_name: str = "filter") -> str:
    """Validate and sanitize OData $filter parameter.

    Checks both the raw value and its URL-decoded form to prevent
    encoded bypass attempts (e.g., %24batch for $batch).
    Also rejects null bytes and other control characters.
    """
    if len(value) > MAX_FILTER_LENGTH:
        raise ValueError(f"Invalid filter: expression too long (max {MAX_FILTER_LENGTH} characters)")

    # Reject null bytes and control characters (except space, tab)
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
        raise ValueError("Invalid filter: contains control characters")

    # Check both raw and URL-decoded forms to prevent encoded bypasses
    candidates = {value.lower()}
    try:
        decoded = urllib.parse.unquote(value)
        candidates.add(decoded.lower())
        # Double-decode to catch double-encoding attacks
        double_decoded = urllib.parse.unquote(decoded)
        candidates.add(double_decoded.lower())
    except (ValueError, UnicodeDecodeError):
        pass

    for candidate in candidates:
        for blocked in ODATA_FILTER_BLOCKLIST:
            if blocked in candidate:
                raise ValueError(f"Invalid filter: contains blocked keyword '{blocked}'")

    return value


@_register("date")
def validate_date(value: str, field_name: str) -> str:
    """Validate that a value is a valid YYYY-MM-DD date string."""
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Invalid {field_name}: must be in YYYY-MM-DD format (e.g., '2026-01-15')") from None
    return value
