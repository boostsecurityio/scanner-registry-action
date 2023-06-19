"""Scanners & rules config."""
from pathlib import Path

from pydantic import BaseModel


class RegistryConfig(BaseModel):
    """Config class for the registry.

    Holds reference to the scanners and rules realm location.
    """

    scanners_path: Path
    rules_realm_path: Path
    server_side_scanners_path: Path

    @classmethod
    def from_registry(cls, registry_path: Path) -> "RegistryConfig":
        """Initialize a RegistryConfig from the base registry path."""
        return cls(
            scanners_path=registry_path / "scanners",
            rules_realm_path=registry_path / "rules-realm",
            server_side_scanners_path=registry_path / "server-side-scanners",
        )
