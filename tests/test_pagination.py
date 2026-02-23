"""Tests for automatic pagination in sf_mcp.client."""

from unittest.mock import patch

from sf_mcp.client import make_paginated_odata_request


def _mock_odata_response(results):
    """Create a mock OData JSON response."""
    return {"d": {"results": results}}


class TestMakePaginatedOdataRequest:
    @patch("sf_mcp.client.make_odata_request")
    def test_single_page_all_results(self, mock_request):
        """When fewer results than page_size, only one API call is made."""
        mock_request.return_value = _mock_odata_response([{"id": 1}, {"id": 2}])

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            {"$format": "json"},
            "req1",
            page_size=10,
            max_pages=5,
        )

        assert result["count"] == 2
        assert len(result["results"]) == 2
        assert result["pagination"]["pages_fetched"] == 1
        assert result["pagination"]["complete"] is True
        assert result["pagination"]["has_more"] is False
        assert mock_request.call_count == 1

    @patch("sf_mcp.client.make_odata_request")
    def test_multi_page_accumulation(self, mock_request):
        """Results from multiple pages are accumulated."""
        page1 = [{"id": i} for i in range(10)]
        page2 = [{"id": i} for i in range(10, 15)]

        mock_request.side_effect = [
            _mock_odata_response(page1),
            _mock_odata_response(page2),
        ]

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            {"$format": "json"},
            "req1",
            page_size=10,
            max_pages=5,
        )

        assert result["count"] == 15
        assert len(result["results"]) == 15
        assert result["pagination"]["pages_fetched"] == 2
        assert result["pagination"]["complete"] is True
        assert result["pagination"]["has_more"] is False

    @patch("sf_mcp.client.make_odata_request")
    def test_max_pages_limit(self, mock_request):
        """Stops after max_pages even if more results exist."""
        full_page = [{"id": i} for i in range(10)]
        mock_request.return_value = _mock_odata_response(full_page)

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            None,
            "req1",
            page_size=10,
            max_pages=3,
        )

        assert result["count"] == 30
        assert result["pagination"]["pages_fetched"] == 3
        assert result["pagination"]["complete"] is False
        assert result["pagination"]["has_more"] is True
        assert mock_request.call_count == 3

    @patch("sf_mcp.client.make_odata_request")
    def test_error_on_first_page(self, mock_request):
        """Error on first page returns error dict directly."""
        mock_request.return_value = {"error": "HTTP 401", "message": "Auth failed"}

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            None,
            "req1",
        )

        assert "error" in result
        assert result["error"] == "HTTP 401"

    @patch("sf_mcp.client.make_odata_request")
    def test_error_on_subsequent_page(self, mock_request):
        """Error after first page returns partial results with error info."""
        mock_request.side_effect = [
            _mock_odata_response([{"id": 1}, {"id": 2}, {"id": 3}]),
            {"error": "HTTP 500"},
        ]

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            None,
            "req1",
            page_size=3,
            max_pages=5,
        )

        assert result["count"] == 3
        assert result["pagination"]["complete"] is False
        assert result["pagination"]["stopped_reason"] == "error_on_page"
        assert result["pagination"]["error"] == "HTTP 500"

    def test_page_size_clamping(self):
        """Page size is clamped to MAX_TOP_QUERY."""
        with patch("sf_mcp.client.make_odata_request") as mock_request:
            mock_request.return_value = _mock_odata_response([])

            make_paginated_odata_request(
                "inst",
                "/odata/v2/User",
                "DC55",
                "production",
                "admin",
                "pass",
                None,
                "req1",
                page_size=9999,
                max_pages=1,
            )

            # Check that $top was clamped to 1000
            call_params = mock_request.call_args[0][6]  # params arg
            assert call_params["$top"] == "1000"

    @patch("sf_mcp.client.make_odata_request")
    def test_skip_increments_correctly(self, mock_request):
        """$skip should increment by page_size across pages."""
        full_page = [{"id": i} for i in range(5)]
        partial_page = [{"id": 10}]

        mock_request.side_effect = [
            _mock_odata_response(full_page),
            _mock_odata_response(full_page),
            _mock_odata_response(partial_page),
        ]

        make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            {"$format": "json"},
            "req1",
            page_size=5,
            max_pages=10,
        )

        # First call: no $skip
        first_params = mock_request.call_args_list[0][0][6]
        assert "$skip" not in first_params

        # Second call: $skip=5
        second_params = mock_request.call_args_list[1][0][6]
        assert second_params["$skip"] == "5"

        # Third call: $skip=10
        third_params = mock_request.call_args_list[2][0][6]
        assert third_params["$skip"] == "10"

    @patch("sf_mcp.client.make_odata_request")
    def test_empty_result_set(self, mock_request):
        """Empty results on first page should return cleanly."""
        mock_request.return_value = _mock_odata_response([])

        result = make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            None,
            "req1",
        )

        assert result["count"] == 0
        assert result["results"] == []
        assert result["pagination"]["complete"] is True
        assert result["pagination"]["pages_fetched"] == 1

    @patch("sf_mcp.client.make_odata_request")
    def test_removes_existing_top_skip_from_params(self, mock_request):
        """Base params with $top/$skip are stripped since pagination manages them."""
        mock_request.return_value = _mock_odata_response([])

        make_paginated_odata_request(
            "inst",
            "/odata/v2/User",
            "DC55",
            "production",
            "admin",
            "pass",
            {"$format": "json", "$top": "999", "$skip": "50"},
            "req1",
            page_size=100,
            max_pages=1,
        )

        call_params = mock_request.call_args[0][6]
        assert call_params["$top"] == "100"
        assert "$skip" not in call_params
        assert call_params["$format"] == "json"
