"""Pytest tools."""
from collections.abc import Generator

import pytest
from aioresponses import aioresponses as aioresponses_cls


@pytest.fixture()
def aioresponses() -> Generator[aioresponses_cls, None, None]:
    """Provide aioresponses mocking as a fixture."""
    # Something's wrong with that lib's typing
    with aioresponses_cls() as mocker:  # type: ignore[no-untyped-call]
        yield mocker
