"""Conftest."""
import pytest
from typer.testing import CliRunner


@pytest.fixture()
def cli_runner() -> CliRunner:
    """Return a CliRunner."""
    return CliRunner()
