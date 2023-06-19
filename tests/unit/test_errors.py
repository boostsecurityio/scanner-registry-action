"""Errors unit tests."""

from typing import Any

import pytest

from boostsec.registry_validator.errors import format_validation_error


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            {"loc": ["obj", "field", "sub-field"], "type": "value_error.missing"},
            "obj.field.sub-field is a required property",
        ),
        (
            {"loc": ["field"], "type": "value_error.extra"},
            "Additional properties are not allowed (field was unexpected)",
        ),
        (
            {"loc": ["field"], "type": "not-handled"},
            "field: unknown error",
        ),
    ],
)
def test_format_validation_error(error: dict[str, Any], expected: str) -> None:
    """Should return expected message based on error type."""
    assert format_validation_error(error) == expected
