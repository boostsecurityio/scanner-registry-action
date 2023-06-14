"""Tests for shared module."""
from pathlib import Path

from boostsec.registry_validator.config import RegistryConfig


def test_registry_config_from_path(tmp_path: Path) -> None:
    """Should init config from a registry base path."""
    config = RegistryConfig.from_registry(tmp_path)
    assert config.scanners_path == tmp_path / "scanners"
    assert config.rules_realm_path == tmp_path / "rules-realm"
