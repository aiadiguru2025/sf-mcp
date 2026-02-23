"""Tests for sf_mcp.rate_limiter module."""

import threading
import time
from unittest.mock import patch

import pytest

from sf_mcp.rate_limiter import RateLimiter, RateLimitExceeded


class TestRateLimiter:
    def test_allows_requests_under_limit(self):
        rl = RateLimiter(limit=5, window_seconds=60)
        for _ in range(5):
            rl.check_and_record("test-instance")

    def test_raises_when_limit_exceeded(self):
        rl = RateLimiter(limit=3, window_seconds=60)
        for _ in range(3):
            rl.check_and_record("test-instance")

        with pytest.raises(RateLimitExceeded) as exc_info:
            rl.check_and_record("test-instance")

        assert exc_info.value.instance == "test-instance"
        assert exc_info.value.current_count == 3
        assert exc_info.value.limit == 3

    def test_sliding_window_expiry(self):
        rl = RateLimiter(limit=2, window_seconds=1)
        rl.check_and_record("inst")
        rl.check_and_record("inst")

        with pytest.raises(RateLimitExceeded):
            rl.check_and_record("inst")

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        rl.check_and_record("inst")

    def test_per_instance_isolation(self):
        rl = RateLimiter(limit=2, window_seconds=60)
        rl.check_and_record("instance-a")
        rl.check_and_record("instance-a")

        with pytest.raises(RateLimitExceeded):
            rl.check_and_record("instance-a")

        # Instance B should be unaffected
        rl.check_and_record("instance-b")
        rl.check_and_record("instance-b")

    def test_case_insensitive_instance(self):
        rl = RateLimiter(limit=2, window_seconds=60)
        rl.check_and_record("MyInstance")
        rl.check_and_record("myinstance")

        with pytest.raises(RateLimitExceeded):
            rl.check_and_record("MYINSTANCE")

    def test_get_status_returns_correct_data(self):
        rl = RateLimiter(limit=10, window_seconds=60)
        rl.check_and_record("inst")
        rl.check_and_record("inst")
        rl.check_and_record("inst")

        status = rl.get_status("inst")
        assert status.instance == "inst"
        assert status.requests_in_window == 3
        assert status.limit == 10
        assert status.remaining == 7
        assert status.percent_used == 30.0
        assert status.oldest_request_age_seconds is not None

    def test_get_status_empty_instance(self):
        rl = RateLimiter(limit=10, window_seconds=60)
        status = rl.get_status("nonexistent")
        assert status.requests_in_window == 0
        assert status.remaining == 10
        assert status.oldest_request_age_seconds is None

    def test_reset_specific_instance(self):
        rl = RateLimiter(limit=5, window_seconds=60)
        rl.check_and_record("inst-a")
        rl.check_and_record("inst-b")

        rl.reset("inst-a")

        status_a = rl.get_status("inst-a")
        status_b = rl.get_status("inst-b")
        assert status_a.requests_in_window == 0
        assert status_b.requests_in_window == 1

    def test_reset_all(self):
        rl = RateLimiter(limit=5, window_seconds=60)
        rl.check_and_record("inst-a")
        rl.check_and_record("inst-b")

        rl.reset()

        assert rl.get_status("inst-a").requests_in_window == 0
        assert rl.get_status("inst-b").requests_in_window == 0

    def test_thread_safety(self):
        rl = RateLimiter(limit=1000, window_seconds=60)
        errors = []

        def worker():
            try:
                for _ in range(100):
                    rl.check_and_record("shared-inst")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        status = rl.get_status("shared-inst")
        assert status.requests_in_window == 1000

    @patch("sf_mcp.rate_limiter.audit_log")
    def test_warn_threshold_logging(self, mock_audit_log):
        rl = RateLimiter(limit=10, window_seconds=60)
        # Warning fires when count (before append) >= 8 (80% of 10).
        # That means the 9th call sees count=8 in the deque and warns.
        for _ in range(9):
            rl.check_and_record("inst", request_id="test")

        warning_calls = [c for c in mock_audit_log.call_args_list if c.kwargs.get("status") == "warning"]
        assert len(warning_calls) > 0

    def test_rate_limit_exceeded_message(self):
        exc = RateLimitExceeded("myinst", 100, 100, 60)
        assert "myinst" in str(exc)
        assert "100/100" in str(exc)
        assert "60s" in str(exc)
