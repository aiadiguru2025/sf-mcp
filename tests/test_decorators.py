"""Tests for sf_mcp.decorators module."""

import pytest
from unittest.mock import patch

from sf_mcp.decorators import sf_tool


class TestSfToolDecorator:
    def test_injects_request_id(self):
        @sf_tool("test_tool")
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"got_request_id": bool(request_id)}

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert result["got_request_id"] is True

    def test_injects_api_host(self):
        @sf_tool("test_tool")
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"api_host": api_host}

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert result["api_host"] == "api55.sapsf.eu"

    def test_validation_error_returns_error(self):
        @sf_tool("test_tool")
        def my_tool(instance="", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"should": "not reach here"}

        result = my_tool(
            instance="", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert "error" in result

    def test_invalid_dc_returns_error(self):
        @sf_tool("test_tool")
        def my_tool(instance="test", data_center="DC99", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"should": "not reach here"}

        result = my_tool(
            instance="test", data_center="DC99", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert "error" in result
        assert "Invalid data_center" in result["error"]

    def test_max_top_clamping(self):
        @sf_tool("test_tool", max_top=500)
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b", top=100,
                     *, request_id="", start_time=0.0, api_host=""):
            return {"top": top}

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b", top=9999,
        )
        assert result["top"] == 500

    def test_max_top_min_clamping(self):
        @sf_tool("test_tool", max_top=500)
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b", top=100,
                     *, request_id="", start_time=0.0, api_host=""):
            return {"top": top}

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b", top=-5,
        )
        assert result["top"] == 1

    def test_exception_returns_error(self):
        @sf_tool("test_tool")
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            raise RuntimeError("Something broke")

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert "error" in result
        assert "Internal error" in result["error"]

    def test_error_result_logged_as_error(self):
        @sf_tool("test_tool")
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"error": "Something went wrong"}

        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b",
        )
        assert result["error"] == "Something went wrong"

    def test_additional_validation(self):
        @sf_tool("test_tool", validate={"locale": "locale"})
        def my_tool(instance="test", data_center="DC55", environment="production",
                     auth_user_id="a", auth_password="b", locale="en-US",
                     *, request_id="", start_time=0.0, api_host=""):
            return {"locale": locale}

        # Valid
        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b", locale="en-US",
        )
        assert result["locale"] == "en-US"

        # Invalid
        result = my_tool(
            instance="test", data_center="DC55", environment="production",
            auth_user_id="a", auth_password="b", locale="invalid-locale-format-extra",
        )
        assert "error" in result
