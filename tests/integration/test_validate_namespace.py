"""Validate namespaces integration tests."""
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from boostsec.registry_validator.validate_namespaces import app
from tests.integration.conftest import UseSample


def test_main(
    registry_path: Path, cli_runner: CliRunner, use_sample: UseSample
) -> None:
    """Test main."""
    use_sample("scanners/boostsecurityio/simple-scanner")
    use_sample("rules-realm/boostsecurityio/mitre-cwe")

    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert result.exit_code == 0
    assert result.stdout == "Validating namespaces...\nNamespaces are unique.\n"


@pytest.mark.parametrize(
    "samples",
    [
        pytest.param(
            ("scanners/invalids/duplicate-a", "scanners/invalids/duplicate-b"),
            id="between-scanners",
        ),
        pytest.param(
            ("rules-realm/invalids/duplicate-module", "scanners/invalids/duplicate-a"),
            id="between-scanners-and-realm",
        ),
    ],
)
def test_main_repeated_namespaces(
    registry_path: Path,
    cli_runner: CliRunner,
    use_sample: UseSample,
    samples: list[str],
) -> None:
    """Test main with repeated namespaces.

    Namespaces should be unique across scanners and rules-realm.
    """
    for sample in samples:
        use_sample(sample)

    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == (
        "Validating namespaces...\n"
        "ERROR: namespaces are not unique, duplicate: invalids/duplicate-module\n"
    )


def test_main_invalid_module(
    registry_path: Path, cli_runner: CliRunner, use_sample: UseSample
) -> None:
    """Test main with repeated namespaces."""
    use_sample("scanners/invalids/missing-namespace")
    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert result.exit_code == 1
    assert len(re.findall(r"ERROR: .* is a required property in", result.stdout)) == 1
