"""Test."""
import re
from functools import partial
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from boostsec.registry_validator.validate_namespaces import (
    find_module_yaml,
    find_rules_realm_namespace,
    get_module_namespaces,
    main,
    validate_namespaces,
    validate_unique_namepsace,
)


def _create_module_yaml(tmp_path: Path, namespace: str = "") -> None:
    """Create a module.yaml file."""
    modules_path = tmp_path / uuid4().hex
    modules_path.mkdir()
    modules_path = modules_path / "module_name"
    modules_path.mkdir()
    module_yaml = modules_path / "module.yaml"
    module_obj = {
        "api_version": 1,
        "id": "example-diff-sarif",
        "name": "Example Sarif Scanner",
        "config": {"support_diff_scan": True},
        "steps": [],
    }
    if namespace:
        module_obj["namespace"] = namespace
    module_yaml.write_text(yaml.dump(module_obj))


def _create_rules_realm(tmp_path: Path, namespace: str) -> None:
    realm_path = tmp_path / namespace
    realm_path.mkdir(parents=True)
    rule_yaml = realm_path / "rules.yaml"
    rule_yaml.touch()


@pytest.fixture()
def create_unique_modules(tmp_path: Path) -> Path:
    """Create a module.yaml file."""
    _create_module_yaml(tmp_path, "test1")
    _create_module_yaml(tmp_path, "test2")
    _create_module_yaml(tmp_path, "test3")
    return tmp_path


@pytest.fixture()
def create_repeated_modules(tmp_path: Path) -> Path:
    """Create a module.yaml file."""
    _create_module_yaml(tmp_path, "test1")
    _create_module_yaml(tmp_path, "test2")
    _create_module_yaml(tmp_path, "test2")
    return tmp_path


def test_find_module_yaml(create_unique_modules: Path) -> None:
    """Test find_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    assert len(modules) == 3


def test_find_rules_realm_namespace(rules_realm_path: Path) -> None:
    """Should return the namespaces relative to rules realm base."""
    namespaces = ["ns/test1", "ns/deep/test2", "test3"]
    for name in namespaces:
        _create_rules_realm(rules_realm_path, name)

    assert sorted(find_rules_realm_namespace(rules_realm_path)) == sorted(namespaces)


def test_get_module_namespaces(create_unique_modules: Path) -> None:
    """Should return the namespaces from the modules.yaml files."""
    modules = find_module_yaml(str(create_unique_modules))
    assert sorted(get_module_namespaces(modules)) == sorted(["test1", "test2", "test3"])


@pytest.mark.parametrize(
    ("namespaces", "unique", "expected"),
    [
        ([], True, ""),
        (["test1", "test2", "test3"], True, ""),
        (
            ["test1", "test1"],
            False,
            "ERROR: namespaces are not unique, duplicate: test1\n",
        ),
    ],
)
def test_validate_unique_namepsace(
    namespaces: list[str],
    unique: bool,
    expected: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Should error is duplicate values in namespaces."""
    call = partial(validate_unique_namepsace, namespaces)
    if unique:
        call()
    else:
        with pytest.raises(SystemExit):
            call()

    out, _ = capfd.readouterr()
    assert expected == out


def test_validate_namespaces(create_unique_modules: Path) -> None:
    """Test validate_namespaces_from_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    validate_namespaces(modules, [])


def test_validate_namespaces_without_namespace(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_namespaces_from_module_yaml."""
    _create_module_yaml(tmp_path)
    modules = find_module_yaml(str(tmp_path))
    with pytest.raises(SystemExit):
        validate_namespaces(modules, [])
    out, _ = capfd.readouterr()
    assert "ERROR: namespace not found in" in out


@pytest.mark.parametrize(
    ("rules_ns", "unique", "expected"),
    [
        ([], True, ""),
        (["test4", "test5"], True, ""),
        (["test1"], False, "ERROR: namespaces are not unique, duplicate: test1\n"),
    ],
)
def test_validate_namespaces_with_rules_realm(
    create_unique_modules: Path,
    rules_ns: list[str],
    unique: bool,
    expected: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Should identify duplicate between modules & rules realm."""
    modules = find_module_yaml(str(create_unique_modules))

    call = partial(validate_namespaces, modules, rules_ns)
    if unique:
        call()
    else:
        with pytest.raises(SystemExit):
            call()

    out, _ = capfd.readouterr()
    assert expected == out


def test_main(
    create_unique_modules: Path,
    rules_realm_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test main."""
    _create_rules_realm(rules_realm_path, "rules-ns")

    main(str(create_unique_modules), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            "Validating namespaces...",
            "Namespaces are unique.",
            "",
        ]
    )


def test_main_error(
    create_repeated_modules: Path,
    rules_realm_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test main with repeated namespaces."""
    with pytest.raises(SystemExit):
        main(str(create_repeated_modules), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            "Validating namespaces...",
            "ERROR: namespaces are not unique, duplicate: test2",
            "",
        ]
    )


def test_main_invalid_module(
    tmp_path: Path, rules_realm_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test main with repeated namespaces."""
    _create_module_yaml(tmp_path)
    with pytest.raises(SystemExit):
        main(str(tmp_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert len(re.findall(r"ERROR: .* is a required property in", out)) == 1


def test_main_with_module_rules_duplicate(
    create_unique_modules: Path,
    rules_realm_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test main with duplicate namespace in module & rules realm."""
    _create_rules_realm(rules_realm_path, "test1")
    with pytest.raises(SystemExit):
        main(str(create_unique_modules), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            "Validating namespaces...",
            "ERROR: namespaces are not unique, duplicate: test1",
            "",
        ]
    )
