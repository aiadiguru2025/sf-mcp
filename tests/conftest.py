"""Shared test fixtures for sf-mcp tests."""

import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_odata_response():
    """Factory fixture for creating mock OData JSON responses."""
    def _make(results: list | None = None, single: dict | None = None):
        if single is not None:
            return {"d": single}
        return {"d": {"results": results or []}}
    return _make


@pytest.fixture
def sample_user():
    """A sample SuccessFactors User record."""
    return {
        "userId": "jsmith",
        "firstName": "John",
        "lastName": "Smith",
        "displayName": "John Smith",
        "email": "jsmith@example.com",
        "hireDate": "2020-01-15T00:00:00",
        "status": "active",
        "title": "Software Engineer",
        "department": "Engineering",
        "division": "Product",
        "location": "New York",
        "manager": {"results": [{"userId": "mjones", "displayName": "Mary Jones"}]},
        "hr": {"userId": "hrrep", "displayName": "HR Rep"},
    }


@pytest.fixture
def sample_role():
    """A sample RBP role record."""
    return {
        "roleId": "10",
        "roleName": "Admin",
        "roleDesc": "Administrator role",
        "userType": "admin",
        "lastModifiedDate": "/Date(1700000000000)/",
        "lastModifiedBy": "admin",
        "createdBy": "admin",
        "createdDate": "/Date(1600000000000)/",
    }
