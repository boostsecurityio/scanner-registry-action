"""Test."""
from functools import partial
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from faker import Faker

from boostsec.registry_validator.schema import ModuleSchema
from boostsec.registry_validator.testing.factories import ModuleSchemaFactory
from boostsec.registry_validator.validate_namespaces import (
    find_module_yaml,
    find_rules_realm_namespace,
    get_module_namespaces,
    validate_module_yaml_schema,
    validate_namespaces,
    validate_unique_namespace,
)

faker = Faker()


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
        "steps": ["step"],
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
def create_unique_modules(scanners_path: Path) -> Path:
    """Create a module.yaml file."""
    _create_module_yaml(scanners_path, "test1")
    _create_module_yaml(scanners_path, "test2")
    _create_module_yaml(scanners_path, "test3")
    return scanners_path


def test_find_module_yaml(create_unique_modules: Path) -> None:
    """Test find_module_yaml."""
    modules = find_module_yaml(create_unique_modules)
    assert len(modules) == 3


def test_find_rules_realm_namespace(rules_realm_path: Path) -> None:
    """Should return the namespaces relative to rules realm base."""
    namespaces = ["ns/test1", "ns/deep/test2", "test3"]
    for name in namespaces:
        _create_rules_realm(rules_realm_path, name)

    assert sorted(find_rules_realm_namespace(rules_realm_path)) == sorted(namespaces)


def test_get_module_namespaces() -> None:
    """Should return the namespaces from the modules.yaml files."""
    expected_ns = ["test1", "test2", "test3"]
    modules = [ModuleSchemaFactory.build(namespace=ns) for ns in expected_ns]

    assert sorted(get_module_namespaces(modules)) == sorted(expected_ns)


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
def test_validate_unique_namespace(
    namespaces: list[str],
    unique: bool,
    expected: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Should error is duplicate values in namespaces."""
    call = partial(validate_unique_namespace, namespaces)
    if unique:
        call()
    else:
        with pytest.raises(SystemExit):
            call()

    out, _ = capfd.readouterr()
    assert expected == out


@pytest.mark.parametrize(
    ("modules", "rules_realms", "server_modules", "unique", "expected"),
    [
        ([], [], [], True, ""),
        (
            ModuleSchemaFactory.batch(2),
            [faker.pystr(), faker.pystr()],
            ModuleSchemaFactory.batch(1),
            True,
            "",
        ),
        (
            ModuleSchemaFactory.batch(2, namespace="a"),
            [],
            [],
            False,
            "ERROR: namespaces are not unique, duplicate: a\n",
        ),
        (
            [],
            ["a", "a"],
            [],
            False,
            "ERROR: namespaces are not unique, duplicate: a\n",
        ),
        (
            [],
            [],
            ModuleSchemaFactory.batch(2, namespace="a"),
            False,
            "ERROR: namespaces are not unique, duplicate: a\n",
        ),
        (
            ModuleSchemaFactory.batch(1, namespace="a"),
            ["a"],
            [],
            False,
            "ERROR: namespaces are not unique, duplicate: a\n",
        ),
        (
            ModuleSchemaFactory.batch(1, namespace="a"),
            [],
            ModuleSchemaFactory.batch(1, namespace="a"),
            False,
            "ERROR: namespaces are not unique, duplicate: a\n",
        ),
    ],
)
def test_validate_namespaces(
    capfd: pytest.CaptureFixture[str],
    modules: list[ModuleSchema],
    rules_realms: list[str],
    server_modules: list[ModuleSchema],
    unique: bool,
    expected: str,
) -> None:
    """Should identify duplicate between modules, rules realm and server modules."""
    call = partial(validate_namespaces, modules, rules_realms, server_modules)

    if unique:
        call()
    else:
        with pytest.raises(SystemExit):
            call()

    out, _ = capfd.readouterr()
    assert expected == out


def test_validate_namespaces_without_namespace(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_namespaces_from_module_yaml."""
    _create_module_yaml(tmp_path)
    modules_path = find_module_yaml(tmp_path)
    with pytest.raises(SystemExit):
        [validate_module_yaml_schema(module) for module in modules_path]
    out, _ = capfd.readouterr()
    assert "module.yaml is invalid: namespace is a required property" in out
