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
    else:
        msg = e.get("msg", "unknown error")
        return f"{loc}: {msg}"
