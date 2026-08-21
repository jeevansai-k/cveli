"""
Unit Tests for Utility Functions.

Purpose: Verify that utility functions work correctly with various inputs.
Inputs: Sample data, edge cases.
Outputs: Test results (pass/fail).
Responsibilities: Ensure helper functions handle all scenarios properly.
Dependencies: pytest, httpx for mocking.

Example:
    # Basic test structure using pytest fixtures and parametrization
"""


def test_format_json_dict():
    """Test JSON formatting with dictionary."""
    from utils.helpers import format_json

    result = format_json({"key": "value"})

    assert '""key"": ""value""' in result or '"key": "value"' in result.lower()


def test_truncate_text_long():
    """Test text truncation for long strings."""
    from utils.helpers import truncate_text

    original = "This is a very long string that should be truncated"
    truncated = truncate_text(original, max_length=20)

    assert len(truncated) <= 25  # Max length + ellipsis suffix


def test_parse_date_formats():
    """Test parsing various date formats."""
    from utils.helpers import parse_date

    valid_dates = [
        "2024-08-09",  # ISO format (most common)
        "2024/08/09",  # Slash-separated
        "08/09/2024",  # US format (might work depending on implementation)
    ]

    for date_str in valid_dates:
        result = parse_date(date_str)
        assert result is not None, f"Failed to parse {date_str}"
