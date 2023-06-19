"""Scanner unit tests fixtures."""
from pathlib import Path

import pytest

from boostsec.registry_validator.config import RegistryConfig


@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    """Return a temporary registry directory."""
    registry = tmp_path / "registry"
    registry.mkdir(parents=True)

    return registry


@pytest.fixture()
def scanners_path(registry_path: Path) -> Path:
    """Return a temporary scanners directory."""
    registry = registry_path / "scanners"
    registry.mkdir(parents=True)

    return registry


@pytest.fixture()
def rules_realm_path(registry_path: Path) -> Path:
    """Return a temporary rules-realm directory."""
    registry = registry_path / "rules-realm"
    registry.mkdir(parents=True)

    return registry


@pytest.fixture()
def registry_config(registry_path: Path) -> RegistryConfig:
    """Return a RegistryConfig from valid temporary paths."""
    return RegistryConfig.from_registry(registry_path)
