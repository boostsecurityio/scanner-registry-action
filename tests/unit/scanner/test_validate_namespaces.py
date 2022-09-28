"""Test."""
from pathlib import PosixPath
from uuid import uuid4

import pytest

from boostsec.registry_validator.validate_namespaces import (
    find_module_yaml,
    main,
    validate_namespaces_from_module_yaml,
)


def _create_module_yaml(tmp_path: PosixPath, namespace: str = "") -> None:
    """Create a module.yaml file."""
    modules_path = tmp_path / uuid4().hex
    modules_path.mkdir()
    modules_path = modules_path / "module_name"
    modules_path.mkdir()
    module_yaml = modules_path / "module.yaml"
    if namespace:
        module_yaml.write_text(f"namespace: {namespace}")
    else:
        module_yaml.write_text("not_namespace: not_a_namespace")


@pytest.fixture()
def create_unique_modules(tmp_path: PosixPath) -> PosixPath:
    """Create a module.yaml file."""
    _create_module_yaml(tmp_path, "test1")
    _create_module_yaml(tmp_path, "test2")
    _create_module_yaml(tmp_path, "test3")
    return tmp_path


@pytest.fixture()
def create_repeated_modules(tmp_path: PosixPath) -> PosixPath:
    """Create a module.yaml file."""
    _create_module_yaml(tmp_path, "test1")
    _create_module_yaml(tmp_path, "test2")
    _create_module_yaml(tmp_path, "test2")
    return tmp_path


def test_find_module_yaml(create_unique_modules: PosixPath) -> None:
    """Test find_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    assert len(modules) == 3


def test_validate_namespaces_from_module_yaml(create_unique_modules: PosixPath) -> None:
    """Test validate_namespaces_from_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    validate_namespaces_from_module_yaml(modules)


def test_validate_namespaces_from_module_yaml_without_namespace(
    tmp_path: PosixPath, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_namespaces_from_module_yaml."""
    _create_module_yaml(tmp_path)
    modules = find_module_yaml(str(tmp_path))
    with pytest.raises(SystemExit):
        validate_namespaces_from_module_yaml(modules)
    out, _ = capfd.readouterr()
    assert "ERROR: namespace not found in" in out


def test_main(
    create_unique_modules: PosixPath, capfd: pytest.CaptureFixture[str]
) -> None:
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
    create_repeated_modules: PosixPath, capfd: pytest.CaptureFixture[str]
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
