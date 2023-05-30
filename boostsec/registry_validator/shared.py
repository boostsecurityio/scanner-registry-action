"""Shared components between validation & uploads."""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RegistryConfig:
    """Config class for the registry.

    Holds reference to the scanners and rules realm location.
    """

    scanners_path: Path
    rules_realm_path: Path
