"""Scanner unit tests fixtures."""
from pathlib import Path

import pytest


@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    """Return a temporary registry directory."""
    registry = tmp_path / "registry"
    registry.mkdir(parents=True)

    return registry
