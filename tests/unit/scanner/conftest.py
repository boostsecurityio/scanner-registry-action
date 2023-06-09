"""Scanner unit tests fixtures."""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from boostsec.registry_validator.shared import RegistryConfig


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
def registry_config(scanners_path: Path, rules_realm_path: Path) -> RegistryConfig:
    """Return a RegistryConfig from valid temporary paths."""
    return RegistryConfig(
        scanners_path=scanners_path, rules_realm_path=rules_realm_path
    )


@pytest.fixture()
def cli_runner() -> CliRunner:
    """Return a CliRunner."""
    return CliRunner()
