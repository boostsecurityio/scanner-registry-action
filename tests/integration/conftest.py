"""Conftest."""
import shutil
from pathlib import Path
from subprocess import check_call  # noqa: S404
from typing import Callable

import pytest

DATADIR = Path(__file__).parent / "samples"


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


CommitChanges = Callable[[], None]


@pytest.fixture()
def commit_changes(registry_path: Path) -> CommitChanges:
    """Commit all changes in the git_root repo."""

    def commit() -> None:
        check_call(["git", "add", "-A"], cwd=registry_path)  # noqa: S603 S607
        check_call(  # noqa: S603 S607
            ["git", "commit", "--allow-empty", "-am", "commit"], cwd=registry_path
        )

    return commit


UseSample = Callable[[str], None]


@pytest.fixture()
def use_sample(registry_path: Path) -> UseSample:
    """Copy the sample module to the temp registry."""

    def _use_sample(sample: str) -> None:
        shutil.copytree(
            (DATADIR / sample).absolute(), (registry_path / sample).absolute()
        )

    return _use_sample
