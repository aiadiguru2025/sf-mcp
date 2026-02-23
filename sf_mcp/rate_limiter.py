"""Per-instance sliding window rate limiter for SuccessFactors API calls."""

import threading
import time
from collections import deque
from typing import NamedTuple

from sf_mcp.config import (
    DEFAULT_RATE_LIMIT,
    RATE_LIMIT_WARN_THRESHOLD,
    RATE_LIMIT_WINDOW_SECONDS,
)
from sf_mcp.logging_config import audit_log


class QuotaStatus(NamedTuple):
    """Snapshot of rate limit status for an instance."""

    instance: str
    requests_in_window: int
    limit: int
    window_seconds: int
    remaining: int
    percent_used: float
    oldest_request_age_seconds: float | None


class RateLimitExceeded(Exception):
    """Raised when an instance exceeds its rate limit."""

    def __init__(self, instance: str, current_count: int, limit: int, window_seconds: int):
        self.instance = instance
        self.current_count = current_count
        self.limit = limit
        self.window_seconds = window_seconds
        super().__init__(
            f"Rate limit exceeded for instance '{instance}': "
            f"{current_count}/{limit} requests in {window_seconds}s window. "
            f"Please wait before retrying."
        )


class RateLimiter:
    """Thread-safe sliding window rate limiter, keyed per SF instance."""

    def __init__(
        self,
        limit: int = DEFAULT_RATE_LIMIT,
        window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
    ):
        self._limit = limit
        self._window = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = {}

    def check_and_record(self, instance: str, request_id: str | None = None) -> None:
        """Check rate limit and record a new request.

        Raises RateLimitExceeded if over limit.
        """
        now = time.monotonic()
        key = instance.lower()

        with self._lock:
            if key not in self._requests:
                self._requests[key] = deque()
            q = self._requests[key]

            # Prune expired entries
            cutoff = now - self._window
            while q and q[0] < cutoff:
                q.popleft()

            count = len(q)

            if count >= self._limit:
                audit_log(
                    event_type="rate_limit",
                    instance=instance,
                    status="exceeded",
                    details={
                        "requests_in_window": count,
                        "limit": self._limit,
                        "window_seconds": self._window,
                    },
                    request_id=request_id,
                )
                raise RateLimitExceeded(
                    instance=instance,
                    current_count=count,
                    limit=self._limit,
                    window_seconds=self._window,
                )

            # Warn at threshold
            if count >= int(self._limit * RATE_LIMIT_WARN_THRESHOLD):
                audit_log(
                    event_type="rate_limit",
                    instance=instance,
                    status="warning",
                    details={
                        "requests_in_window": count,
                        "limit": self._limit,
                        "percent_used": round(count / self._limit * 100, 1),
                    },
                    request_id=request_id,
                )

            q.append(now)

    def get_status(self, instance: str) -> QuotaStatus:
        """Return current quota status for an instance."""
        now = time.monotonic()
        key = instance.lower()

        with self._lock:
            q = self._requests.get(key, deque())
            cutoff = now - self._window
            while q and q[0] < cutoff:
                q.popleft()
            count = len(q)
            oldest_age = (now - q[0]) if q else None

        return QuotaStatus(
            instance=instance,
            requests_in_window=count,
            limit=self._limit,
            window_seconds=self._window,
            remaining=max(0, self._limit - count),
            percent_used=round(count / self._limit * 100, 1) if self._limit > 0 else 0,
            oldest_request_age_seconds=round(oldest_age, 2) if oldest_age is not None else None,
        )

    def reset(self, instance: str | None = None) -> None:
        """Reset counters for a specific instance, or all instances."""
        with self._lock:
            if instance:
                self._requests.pop(instance.lower(), None)
            else:
                self._requests.clear()


# Module-level singleton
_rate_limiter: RateLimiter | None = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        with _rate_limiter_lock:
            if _rate_limiter is None:
                _rate_limiter = RateLimiter()
    return _rate_limiter
