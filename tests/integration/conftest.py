"""Conftest."""
from pathlib import Path
from subprocess import check_call  # noqa: S404
from typing import Callable

import pytest


@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    """Return a temporary registry directory."""
    registry = tmp_path / "registry"
    registry.mkdir(parents=True)

    check_call(["git", "init"], cwd=registry)  # noqa: S603 S607
    check_call(  # noqa: S603 S607
        ["git", "commit", "--allow-empty", "-m", "first commit"], cwd=registry
    )

    return registry


@pytest.fixture()
def commit_changes(registry_path: Path) -> Callable[[], None]:
    """Commit all changes in the git_root repo."""

    def commit() -> None:
        check_call(["git", "add", "-A"], cwd=registry_path)  # noqa: S603 S607
        check_call(  # noqa: S603 S607
            ["git", "commit", "--allow-empty", "-am", "commit"], cwd=registry_path
        )

    return commit
