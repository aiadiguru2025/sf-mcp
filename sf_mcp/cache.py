"""Thread-safe in-memory response cache with per-category TTL."""

import hashlib
import json
import threading
import time
from typing import Any, NamedTuple

from sf_mcp.config import (
    CACHE_MAX_ENTRIES,
    CACHE_TTL_DEFAULT,
    CACHE_TTL_METADATA,
    CACHE_TTL_PERMISSIONS,
    CACHE_TTL_PICKLIST,
    CACHE_TTL_SERVICE_DOC,
)
from sf_mcp.logging_config import audit_log

CACHE_CATEGORY_TTLS: dict[str, int] = {
    "metadata": CACHE_TTL_METADATA,
    "picklist": CACHE_TTL_PICKLIST,
    "permissions": CACHE_TTL_PERMISSIONS,
    "service_doc": CACHE_TTL_SERVICE_DOC,
    "default": CACHE_TTL_DEFAULT,
}


class CacheEntry(NamedTuple):
    """A cached response with expiry information."""

    data: Any
    created_at: float
    expires_at: float
    category: str
    cache_key: str
    instance: str


class ResponseCache:
    """Thread-safe in-memory cache keyed by (instance, endpoint, params).

    Credentials are excluded from cache keys.
    """

    def __init__(self, max_entries: int = CACHE_MAX_ENTRIES):
        self._lock = threading.Lock()
        self._cache: dict[str, CacheEntry] = {}
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0

    @staticmethod
    def make_key(instance: str, endpoint: str, params: dict | None = None) -> str:
        """Build a deterministic cache key excluding credentials."""
        key_parts = {
            "instance": instance.lower(),
            "endpoint": endpoint,
            "params": params or {},
        }
        key_json = json.dumps(key_parts, sort_keys=True)
        return hashlib.sha256(key_json.encode()).hexdigest()[:32]

    def get(
        self,
        instance: str,
        endpoint: str,
        params: dict | None = None,
        request_id: str | None = None,
    ) -> Any | None:
        """Look up a cached response. Returns None on miss or expiry."""
        key = self.make_key(instance, endpoint, params)
        now = time.time()

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                audit_log(
                    event_type="cache",
                    instance=instance,
                    status="miss",
                    details={"endpoint": endpoint, "cache_key": key[:8]},
                    request_id=request_id,
                )
                return None

            if now > entry.expires_at:
                del self._cache[key]
                self._misses += 1
                audit_log(
                    event_type="cache",
                    instance=instance,
                    status="expired",
                    details={"endpoint": endpoint, "category": entry.category, "cache_key": key[:8]},
                    request_id=request_id,
                )
                return None

            self._hits += 1
            audit_log(
                event_type="cache",
                instance=instance,
                status="hit",
                details={
                    "endpoint": endpoint,
                    "category": entry.category,
                    "age_seconds": round(now - entry.created_at, 1),
                    "cache_key": key[:8],
                },
                request_id=request_id,
            )
            return entry.data

    def put(
        self,
        instance: str,
        endpoint: str,
        params: dict | None,
        data: Any,
        category: str = "default",
        ttl: int | None = None,
        request_id: str | None = None,
    ) -> None:
        """Store a response in the cache."""
        if ttl is None:
            ttl = CACHE_CATEGORY_TTLS.get(category, CACHE_TTL_DEFAULT)
        if ttl <= 0:
            return

        key = self.make_key(instance, endpoint, params)
        now = time.time()
        entry = CacheEntry(
            data=data,
            created_at=now,
            expires_at=now + ttl,
            category=category,
            cache_key=key,
            instance=instance.lower(),
        )

        with self._lock:
            if len(self._cache) >= self._max_entries and key not in self._cache:
                self._evict_oldest()
            self._cache[key] = entry

    def _evict_oldest(self) -> None:
        """Remove the oldest 10% of entries. Called with lock held."""
        if not self._cache:
            return
        evict_count = max(1, len(self._cache) // 10)
        sorted_keys = sorted(self._cache.keys(), key=lambda k: self._cache[k].created_at)
        for k in sorted_keys[:evict_count]:
            del self._cache[k]

    def invalidate(self, instance: str | None = None) -> int:
        """Clear cache for an instance or all instances. Returns count removed."""
        with self._lock:
            if instance is None:
                count = len(self._cache)
                self._cache.clear()
                self._hits = 0
                self._misses = 0
                return count
            instance_lower = instance.lower()
            to_remove = [k for k, e in self._cache.items() if e.instance == instance_lower]
            for k in to_remove:
                del self._cache[k]
            return len(to_remove)

    def get_status(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            total = len(self._cache)
            now = time.time()
            expired = sum(1 for e in self._cache.values() if now > e.expires_at)
            by_category: dict[str, int] = {}
            for entry in self._cache.values():
                by_category[entry.category] = by_category.get(entry.category, 0) + 1
            total_requests = self._hits + self._misses
            return {
                "total_entries": total,
                "expired_entries": expired,
                "active_entries": total - expired,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(self._hits / total_requests * 100, 1) if total_requests > 0 else 0,
                "by_category": by_category,
            }


# Module-level singleton
_cache: ResponseCache | None = None
_cache_lock = threading.Lock()


def get_cache() -> ResponseCache:
    """Get or create the global cache singleton."""
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache = ResponseCache()
    return _cache
