"""Validate rules tests."""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from boostsec.registry_validator.validate_rules_db import app
from tests.integration.conftest import UseSample


def test_main_with_valid_rules(
    cli_runner: CliRunner,
    registry_path: Path,
    use_sample: UseSample,
) -> None:
    """Test main with valid rules."""
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
    assert result.stdout == (
        "Validating boostsecurityio/simple-scanner/rules.yaml\n"
        "Validating boostsecurityio/mitre-cwe/rules.yaml\n"
    )


def test_main_with_valid_imports(
    cli_runner: CliRunner,
    registry_path: Path,
    use_sample: UseSample,
) -> None:
    """Test main with valid imported rules."""
    use_sample("scanners/others/only-import")
    use_sample("scanners/boostsecurityio/simple-scanner")
    use_sample("rules-realm/boostsecurityio/mitre-cwe")

    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert "Validating others/only-import/rules.yaml\n" in result.stdout
    assert "Validating boostsecurityio/simple-scanner/rules.yaml\n" in result.stdout
    assert "Validating boostsecurityio/mitre-cwe/rules.yaml\n" in result.stdout


@pytest.mark.parametrize(
    "sample", ["scanners/invalids/empty-rules", "rules-realm/invalids/empty-rules"]
)
def test_main_with_empty_rules_db(
    cli_runner: CliRunner,
    registry_path: Path,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Test main with empty rules db."""
    use_sample(sample)

    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert result.exit_code == 1
    assert (
        result.stdout
        == "Validating invalids/empty-rules/rules.yaml\nERROR: Rules DB is empty\n"
    )


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        (
            "rules-realm/invalids/missing-category",
            "Validating invalids/missing-category/rules.yaml\n"
            "ERROR: Rules db is invalid: "
            "rules.my-rule-1.categories is a required property\n",
        ),
        (
            "rules-realm/invalids/multi-defaults",
            "Validating invalids/multi-defaults/rules.yaml\n"
            "ERROR: Rules db is invalid: default: Only one default rule is allowed\n",
        ),
    ],
)
def test_main_with_error(
    cli_runner: CliRunner,
    registry_path: Path,
    use_sample: UseSample,
    sample: str,
    expected: str,
    # from_realm: bool,
) -> None:
    """Test main with empty rules db."""
    use_sample(sample)

    result = cli_runner.invoke(
        app,
        [
            "--registry-path",
            str(registry_path),
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == expected


def test_main_with_without_rules_db(cli_runner: CliRunner, registry_path: Path) -> None:
    """Test main with empty rules db."""
    result = cli_runner.invoke(app, ["--registry-path", str(registry_path)])
    assert result.stdout == "No Rules DB found\n"
