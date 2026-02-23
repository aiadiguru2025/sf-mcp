"""Tests for sf_mcp.cache module."""

import threading
import time
from unittest.mock import patch

from sf_mcp.cache import ResponseCache


class TestResponseCache:
    def test_make_key_excludes_credentials(self):
        """Two different credentials produce the same key for the same query."""
        key1 = ResponseCache.make_key("inst", "/odata/v2/User", {"$top": "10"})
        key2 = ResponseCache.make_key("inst", "/odata/v2/User", {"$top": "10"})
        assert key1 == key2

    def test_make_key_differentiates_instances(self):
        key1 = ResponseCache.make_key("inst-a", "/odata/v2/User")
        key2 = ResponseCache.make_key("inst-b", "/odata/v2/User")
        assert key1 != key2

    def test_make_key_differentiates_endpoints(self):
        key1 = ResponseCache.make_key("inst", "/odata/v2/User")
        key2 = ResponseCache.make_key("inst", "/odata/v2/EmpJob")
        assert key1 != key2

    def test_make_key_differentiates_params(self):
        key1 = ResponseCache.make_key("inst", "/ep", {"$top": "10"})
        key2 = ResponseCache.make_key("inst", "/ep", {"$top": "20"})
        assert key1 != key2

    @patch("sf_mcp.cache.audit_log")
    def test_put_and_get(self, mock_log):
        cache = ResponseCache()
        data = {"d": {"results": [{"userId": "jsmith"}]}}
        cache.put("inst", "/odata/v2/User", None, data, category="metadata", ttl=60)

        result = cache.get("inst", "/odata/v2/User")
        assert result == data

    @patch("sf_mcp.cache.audit_log")
    def test_get_returns_none_on_miss(self, mock_log):
        cache = ResponseCache()
        result = cache.get("inst", "/odata/v2/User")
        assert result is None

    @patch("sf_mcp.cache.audit_log")
    def test_ttl_expiry(self, mock_log):
        cache = ResponseCache()
        data = {"d": {"results": []}}
        cache.put("inst", "/ep", None, data, ttl=1)

        # Immediate retrieval should work
        assert cache.get("inst", "/ep") is not None

        # Wait for TTL to expire
        time.sleep(1.1)
        assert cache.get("inst", "/ep") is None

    @patch("sf_mcp.cache.audit_log")
    def test_default_ttl_zero_no_cache(self, mock_log):
        """Category 'default' has TTL=0 and should not store anything."""
        cache = ResponseCache()
        cache.put("inst", "/ep", None, {"data": 1}, category="default")

        result = cache.get("inst", "/ep")
        assert result is None

    @patch("sf_mcp.cache.audit_log")
    def test_invalidate_specific_instance(self, mock_log):
        cache = ResponseCache()
        cache.put("inst-a", "/ep", None, {"a": 1}, ttl=60)
        cache.put("inst-b", "/ep", None, {"b": 2}, ttl=60)

        cleared = cache.invalidate("inst-a")
        assert cleared == 1

        assert cache.get("inst-a", "/ep") is None
        assert cache.get("inst-b", "/ep") == {"b": 2}

    @patch("sf_mcp.cache.audit_log")
    def test_invalidate_all(self, mock_log):
        cache = ResponseCache()
        cache.put("inst-a", "/ep", None, {"a": 1}, ttl=60)
        cache.put("inst-b", "/ep", None, {"b": 2}, ttl=60)

        cleared = cache.invalidate()
        assert cleared == 2

        assert cache.get("inst-a", "/ep") is None
        assert cache.get("inst-b", "/ep") is None

    @patch("sf_mcp.cache.audit_log")
    def test_max_entries_eviction(self, mock_log):
        cache = ResponseCache(max_entries=5)
        for i in range(6):
            cache.put("inst", f"/ep/{i}", None, {"i": i}, ttl=3600)

        status = cache.get_status()
        assert status["total_entries"] <= 5

    @patch("sf_mcp.cache.audit_log")
    def test_get_status_returns_correct_stats(self, mock_log):
        cache = ResponseCache()
        cache.put("inst", "/ep1", None, {"data": 1}, category="metadata", ttl=60)
        cache.put("inst", "/ep2", None, {"data": 2}, category="picklist", ttl=60)

        # Generate a hit and a miss
        cache.get("inst", "/ep1")  # hit
        cache.get("inst", "/ep-missing")  # miss

        status = cache.get_status()
        assert status["total_entries"] == 2
        assert status["hits"] == 1
        assert status["misses"] == 1
        assert status["hit_rate_percent"] == 50.0
        assert status["by_category"]["metadata"] == 1
        assert status["by_category"]["picklist"] == 1

    @patch("sf_mcp.cache.audit_log")
    def test_thread_safety(self, mock_log):
        cache = ResponseCache()
        errors = []

        def writer(thread_id):
            try:
                for i in range(50):
                    cache.put(f"inst-{thread_id}", f"/ep/{i}", None, {"t": thread_id, "i": i}, ttl=60)
            except Exception as e:
                errors.append(e)

        def reader(thread_id):
            try:
                for i in range(50):
                    cache.get(f"inst-{thread_id}", f"/ep/{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for t in range(5):
            threads.append(threading.Thread(target=writer, args=(t,)))
            threads.append(threading.Thread(target=reader, args=(t,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    @patch("sf_mcp.cache.audit_log")
    def test_case_insensitive_instance_invalidation(self, mock_log):
        cache = ResponseCache()
        cache.put("MyInstance", "/ep", None, {"data": 1}, ttl=60)

        cleared = cache.invalidate("myinstance")
        assert cleared == 1
