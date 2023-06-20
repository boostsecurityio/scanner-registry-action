"""CLI errors."""
from typing import Any


def format_validation_error(e: dict[str, Any]) -> str:
    """Format the error message of a pydantic validation error."""
    error_type = e["type"]
    loc = ".".join(str(loc) for loc in e["loc"])
    if error_type == "value_error.missing":
        return f"{loc} is a required property"
    elif error_type == "value_error.extra":
        return f"Additional properties are not allowed ({loc} was unexpected)"
    elif error_type == "type_error.enum":
        permitted = [str(enum.value) for enum in e["ctx"]["enum_values"]]
        return (
            f"{loc} has an invalid value; permitted values are: {', '.join(permitted)}"
        )
    elif error_type == "value_error.list.min_items":
        min_items = e["ctx"]["limit_value"]
        return f"{loc}: at least {min_items} item is required"
    else:
        msg = e.get("msg", "unknown error")
        return f"{loc}: {msg}"
