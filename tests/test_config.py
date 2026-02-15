"""Tests for sf_mcp.config module."""

import pytest

from sf_mcp.config import (
    get_api_host,
    VALID_DATA_CENTERS,
    VALID_ENVIRONMENTS,
    DC_API_HOST_MAP,
    DEFAULT_TIMEOUT,
    MAX_TOP_STANDARD,
)


class TestGetApiHost:
    def test_valid_production(self):
        host = get_api_host("DC55", "production")
        assert host == "api55.sapsf.eu"

    def test_valid_preview(self):
        host = get_api_host("DC55", "preview")
        assert host == "api55preview.sapsf.eu"

    def test_case_insensitive_dc(self):
        host = get_api_host("dc55", "production")
        assert host == "api55.sapsf.eu"

    def test_case_insensitive_env(self):
        host = get_api_host("DC55", "Production")
        assert host == "api55.sapsf.eu"

    def test_dc_alias(self):
        """DC57 is an alias for DC2."""
        host1 = get_api_host("DC2", "production")
        host2 = get_api_host("DC57", "production")
        assert host1 == host2

    def test_sales_demo(self):
        host = get_api_host("DC2", "sales_demo")
        assert host == "apisalesdemo2.successfactors.eu"

    def test_invalid_dc_raises(self):
        with pytest.raises(ValueError, match="Invalid data_center"):
            get_api_host("DC99", "production")

    def test_invalid_env_raises(self):
        with pytest.raises(ValueError, match="Invalid environment"):
            get_api_host("DC55", "staging")

    def test_env_not_available_raises(self):
        """DC22 doesn't have sales_demo."""
        with pytest.raises(ValueError, match="not available"):
            get_api_host("DC22", "sales_demo")

    def test_us_dc(self):
        host = get_api_host("DC4", "production")
        assert host == "api4.successfactors.com"

    def test_china_dc(self):
        host = get_api_host("DC15", "production")
        assert host == "api15.sapsf.cn"

    def test_india_dc(self):
        host = get_api_host("DC80", "production")
        assert host == "api-in10.hr.cloud.sap"


class TestConstants:
    def test_valid_data_centers_not_empty(self):
        assert len(VALID_DATA_CENTERS) >= 18

    def test_valid_environments(self):
        assert VALID_ENVIRONMENTS == {"production", "preview", "sales_demo"}

    def test_dc_map_entries(self):
        assert len(DC_API_HOST_MAP) > 50

    def test_defaults(self):
        assert DEFAULT_TIMEOUT == 30
        assert MAX_TOP_STANDARD == 500
