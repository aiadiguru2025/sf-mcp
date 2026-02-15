"""Tests for sf_mcp.client module."""

import pytest
from unittest.mock import patch, MagicMock

from sf_mcp.client import make_odata_request, make_metadata_request, make_service_doc_request


class TestMakeOdataRequest:
    @patch("sf_mcp.client.requests.get")
    def test_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"d": {"results": []}}'
        mock_resp.json.return_value = {"d": {"results": []}}
        mock_get.return_value = mock_resp

        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "admin", "password123", {"$format": "json"}, "test123",
        )

        assert "error" not in result
        assert result == {"d": {"results": []}}
        mock_get.assert_called_once()

    @patch("sf_mcp.client.requests.get")
    def test_401_returns_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "admin", "wrong", None, "test123",
        )

        assert result["error"] == "HTTP 401"

    @patch("sf_mcp.client.requests.get")
    def test_500_returns_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_get.return_value = mock_resp

        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "admin", "password", None, "test123",
        )

        assert "HTTP 500" in result["error"]

    def test_missing_credentials(self):
        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "", "", None, "test123",
        )

        assert "Missing credentials" in result["error"]

    def test_invalid_dc(self):
        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC99", "production",
            "admin", "password", None, "test123",
        )

        assert "Invalid data_center" in result["error"]

    @patch("sf_mcp.client.requests.get")
    def test_empty_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "   "
        mock_get.return_value = mock_resp

        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "admin", "password", None, "test123",
        )

        assert "Empty response" in result["error"]

    @patch("sf_mcp.client.requests.get")
    def test_request_exception(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = make_odata_request(
            "test-instance", "/odata/v2/User", "DC55", "production",
            "admin", "password", None, "test123",
        )

        assert "Request failed" in result["error"]

    @patch("sf_mcp.client.requests.get")
    def test_builds_correct_url(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"d": {}}'
        mock_resp.json.return_value = {"d": {}}
        mock_get.return_value = mock_resp

        make_odata_request(
            "mycompany", "/odata/v2/User", "DC55", "production",
            "admin", "password123", None, "test123",
        )

        call_args = mock_get.call_args
        assert call_args.kwargs["auth"] == ("admin@mycompany", "password123")
        assert "api55.sapsf.eu" in call_args.args[0]


class TestMakeMetadataRequest:
    @patch("sf_mcp.client.requests.get")
    def test_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<root><child>test</child></root>"
        mock_get.return_value = mock_resp

        result = make_metadata_request(
            "test-instance", "User", "DC55", "production",
            "admin", "password", "test123",
        )

        assert result is not None
        assert "error" not in result

    def test_missing_credentials(self):
        result = make_metadata_request(
            "test-instance", "User", "DC55", "production",
            "", "", "test123",
        )

        assert "Missing credentials" in result["error"]


class TestMakeServiceDocRequest:
    @patch("sf_mcp.client.requests.get")
    def test_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"d": {"EntitySets": ["User", "EmpJob"]}}
        mock_get.return_value = mock_resp

        result = make_service_doc_request(
            "test-instance", "DC55", "production",
            "admin", "password", "test123",
        )

        assert "error" not in result
        assert "d" in result
