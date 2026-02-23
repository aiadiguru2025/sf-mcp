"""Administrative tools: quota status, cache management."""

from typing import Any

from sf_mcp.cache import get_cache
from sf_mcp.rate_limiter import get_rate_limiter
from sf_mcp.server import mcp


@mcp.tool()
def get_api_quota_status(instance: str) -> dict[str, Any]:
    """
    Check current API usage against rate limits for a SuccessFactors instance.

    Shows how many requests have been made in the current window, how many
    remain before the limit is hit, and the percentage of quota used.

    Args:
        instance: The SuccessFactors instance/company ID to check
    """
    status = get_rate_limiter().get_status(instance)
    return {
        "instance": status.instance,
        "requests_in_window": status.requests_in_window,
        "limit": status.limit,
        "window_seconds": status.window_seconds,
        "remaining": status.remaining,
        "percent_used": status.percent_used,
        "oldest_request_age_seconds": status.oldest_request_age_seconds,
    }


@mcp.tool()
def get_cache_status() -> dict[str, Any]:
    """
    View cache statistics including hit rate, entry counts, and per-category breakdown.

    Shows how effectively the cache is reducing API calls.
    """
    return get_cache().get_status()


@mcp.tool()
def clear_cache(instance: str = "") -> dict[str, Any]:
    """
    Clear cached API responses.

    Specify an instance to clear only that instance's cache,
    or leave blank to clear the entire cache.

    Args:
        instance: Optional instance ID to clear cache for. If empty, clears all.
    """
    cleared = get_cache().invalidate(instance if instance else None)
    return {
        "cleared_entries": cleared,
        "instance": instance or "all",
    }
