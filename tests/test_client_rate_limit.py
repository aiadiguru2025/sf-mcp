"""Tests for rate limiting and 429 handling in sf_mcp.client."""

from unittest.mock import MagicMock, patch

from sf_mcp.client import make_odata_request
from sf_mcp.rate_limiter import RateLimiter


class TestClientRateLimiting:
    @patch("sf_mcp.client.get_rate_limiter")
    @patch("sf_mcp.client.get_session")
    def test_rate_limit_exceeded_returns_error(self, mock_get_session, mock_get_rl):
        """When rate limiter says no, HTTP call is never made."""

        rl = RateLimiter(limit=0, window_seconds=60)
        mock_get_rl.return_value = rl

        result = make_odata_request(
            "test-instance",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "password",
            None,
            "test123",
        )

        assert "Rate limit exceeded" in result["error"]
        mock_get_session.return_value.get.assert_not_called()


class TestClient429Handling:
    @patch("sf_mcp.client.get_rate_limiter")
    @patch("sf_mcp.client.time.sleep")
    @patch("sf_mcp.client.get_session")
    def test_429_retry_then_succeed(self, mock_get_session, mock_sleep, mock_get_rl):
        """HTTP 429 is retried and succeeds on second attempt."""
        # Rate limiter allows all requests
        mock_rl = MagicMock()
        mock_get_rl.return_value = mock_rl

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "1"}

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = '{"d": {"results": []}}'
        resp_200.json.return_value = {"d": {"results": []}}

        mock_session = mock_get_session.return_value
        mock_session.get.side_effect = [resp_429, resp_200]

        result = make_odata_request(
            "test-instance",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "password",
            None,
            "test123",
        )

        assert "error" not in result
        assert mock_session.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    @patch("sf_mcp.client.get_rate_limiter")
    @patch("sf_mcp.client.time.sleep")
    @patch("sf_mcp.client.get_session")
    def test_429_retries_exhausted(self, mock_get_session, mock_sleep, mock_get_rl):
        """HTTP 429 with all retries exhausted returns error."""
        mock_rl = MagicMock()
        mock_get_rl.return_value = mock_rl

        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "1"}
        mock_get_session.return_value.get.return_value = resp_429

        result = make_odata_request(
            "test-instance",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "password",
            None,
            "test123",
        )

        assert "429" in result["error"]
        assert "retry_after_seconds" in result
