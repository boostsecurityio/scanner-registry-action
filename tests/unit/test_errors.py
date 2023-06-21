"""Errors unit tests."""

from enum import Enum
from typing import Any

import pytest

from boostsec.registry_validator.errors import format_validation_error


class DummyEnum(str, Enum):
    """Dummy enum for testing."""

    A = "a"
    B = "b"
    C = "c"


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
            {
                "loc": ["field", "0"],
                "type": "type_error.enum",
                "ctx": {"enum_values": list(DummyEnum)},
            },
            "field.0 has an invalid value; permitted values are: a, b, c",
        ),
        (
            {
                "loc": ["field"],
                "type": "value_error.list.min_items",
                "ctx": {"limit_value": 1},
            },
            "field: at least 1 item is required",
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
