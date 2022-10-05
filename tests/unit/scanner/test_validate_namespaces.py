"""Test."""
import re
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from boostsec.registry_validator.common import find_module_yaml
from boostsec.registry_validator.validate_namespaces import (
    main,
    validate_namespaces_from_modules_yaml,
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


def test_validate_namespaces_from_module_yaml(create_unique_modules: Path) -> None:
    """Test validate_namespaces_from_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    validate_namespaces_from_modules_yaml(modules)


def test_validate_namespaces_from_module_yaml_without_namespace(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_namespaces_from_module_yaml."""
    _create_module_yaml(tmp_path)
    modules = find_module_yaml(str(tmp_path))
    with pytest.raises(SystemExit):
        validate_namespaces_from_modules_yaml(modules)
    out, _ = capfd.readouterr()
    assert "ERROR: namespace not found in" in out


def test_main(create_unique_modules: Path, capfd: pytest.CaptureFixture[str]) -> None:
    """Test main."""
    main(str(create_unique_modules))
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            "Validating namespaces...",
            "Namespaces are unique.",
            "",
        ]
    )


def test_main_error(
    create_repeated_modules: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test main with repeated namespaces."""
    with pytest.raises(SystemExit):
        main(str(create_repeated_modules))
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            "Validating namespaces...",
            "ERROR: namespaces are not unique, duplicate: test2",
            "",
        ]
    )


def test_main_invalid_module(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    """Test main with repeated namespaces."""
    _create_module_yaml(tmp_path)
    with pytest.raises(SystemExit):
        main(str(tmp_path))
    out, _ = capfd.readouterr()
    assert len(re.findall(r"ERROR: .* is a required property in", out)) == 1
