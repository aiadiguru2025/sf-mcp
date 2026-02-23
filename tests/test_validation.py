"""Tests for sf_mcp.validation module."""

import pytest

from sf_mcp.validation import (
    VALIDATORS,
    sanitize_odata_string,
    validate_date,
    validate_entity_path,
    validate_expand,
    validate_identifier,
    validate_ids,
    validate_locale,
    validate_odata_filter,
    validate_orderby,
    validate_select,
)


class TestValidateIdentifier:
    def test_valid_simple(self):
        assert validate_identifier("admin", "test") == "admin"

    def test_valid_with_special(self):
        assert validate_identifier("my-instance_01", "test") == "my-instance_01"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Invalid test"):
            validate_identifier("", "test")

    def test_spaces_raise(self):
        with pytest.raises(ValueError):
            validate_identifier("bad value", "test")

    def test_injection_raises(self):
        with pytest.raises(ValueError):
            validate_identifier("admin'; DROP TABLE--", "test")


class TestValidateIds:
    def test_single_id(self):
        assert validate_ids("user1", "ids") == "user1"

    def test_comma_separated(self):
        assert validate_ids("user1,user2,user3", "ids") == "user1,user2,user3"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            validate_ids("", "ids")

    def test_spaces_raise(self):
        with pytest.raises(ValueError):
            validate_ids("user1, user2", "ids")


class TestValidateLocale:
    def test_valid_en_us(self):
        assert validate_locale("en-US") == "en-US"

    def test_valid_short(self):
        assert validate_locale("en") == "en"

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid locale"):
            validate_locale("en-US-extra")

    def test_numbers_raise(self):
        with pytest.raises(ValueError):
            validate_locale("12-34")


class TestValidateEntityPath:
    def test_simple_entity(self):
        assert validate_entity_path("User") == "User"

    def test_with_key(self):
        assert validate_entity_path("User('admin')") == "User('admin')"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            validate_entity_path("")

    def test_injection_raises(self):
        with pytest.raises(ValueError):
            validate_entity_path("User;DROP TABLE")


class TestValidateSelect:
    def test_simple(self):
        assert validate_select("userId,firstName") == "userId,firstName"

    def test_with_slash(self):
        assert validate_select("userId,manager/displayName") == "userId,manager/displayName"

    def test_injection_raises(self):
        with pytest.raises(ValueError):
            validate_select("userId;DROP TABLE")


class TestValidateOrderby:
    def test_simple(self):
        assert validate_orderby("hireDate desc") == "hireDate desc"

    def test_asc(self):
        assert validate_orderby("lastName asc") == "lastName asc"

    def test_injection_raises(self):
        with pytest.raises(ValueError):
            validate_orderby("a;DROP")


class TestValidateExpand:
    def test_simple(self):
        assert validate_expand("manager") == "manager"

    def test_multiple(self):
        assert validate_expand("manager,hr") == "manager,hr"

    def test_injection_raises(self):
        with pytest.raises(ValueError):
            validate_expand("manager;DROP")


class TestValidateOdataFilter:
    def test_simple_filter(self):
        assert validate_odata_filter("userId eq 'admin'") == "userId eq 'admin'"

    def test_blocked_keyword(self):
        with pytest.raises(ValueError, match="blocked keyword"):
            validate_odata_filter("userId eq '$batch'")

    def test_script_injection(self):
        with pytest.raises(ValueError, match="blocked keyword"):
            validate_odata_filter("userId eq '<script>alert(1)</script>'")

    def test_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validate_odata_filter("a" * 2001)


class TestValidateDate:
    def test_valid(self):
        assert validate_date("2024-01-15", "test") == "2024-01-15"

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="YYYY-MM-DD"):
            validate_date("15-01-2024", "test")

    def test_invalid_date(self):
        with pytest.raises(ValueError):
            validate_date("2024-13-01", "test")


class TestSanitizeOdataString:
    def test_no_quotes(self):
        assert sanitize_odata_string("admin") == "admin"

    def test_single_quote(self):
        assert sanitize_odata_string("O'Brien") == "O''Brien"


class TestValidatorsRegistry:
    def test_all_registered(self):
        expected = {"identifier", "ids", "locale", "entity_path", "select", "orderby", "expand", "odata_filter", "date"}
        assert expected == set(VALIDATORS.keys())
