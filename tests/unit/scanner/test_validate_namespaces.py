from pathlib import PosixPath
from uuid import uuid4

import pytest
from boostsec.scanner.validate_namespaces import (
    assert_namespaces_are_unique,
    find_module_yaml,
    get_namespaces_from_module_yaml,
    main,
)
from pytest import CaptureFixture


def __create_module_yaml(tmp_path: PosixPath, namespace: str = "") -> None:
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


@pytest.fixture
def create_unique_modules(tmp_path: PosixPath) -> PosixPath:
    """Create a module.yaml file."""
    __create_module_yaml(tmp_path, "test1")
    __create_module_yaml(tmp_path, "test2")
    __create_module_yaml(tmp_path, "test3")
    return tmp_path


@pytest.fixture
def create_repeated_modules(tmp_path: PosixPath) -> PosixPath:
    """Create a module.yaml file."""
    __create_module_yaml(tmp_path, "test1")
    __create_module_yaml(tmp_path, "test2")
    __create_module_yaml(tmp_path, "test2")
    return tmp_path


def test_find_module_yaml(create_unique_modules: PosixPath) -> None:
    """Test find_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    assert len(modules) == 3


def test_get_namespaces_from_module_yaml(create_unique_modules: PosixPath) -> None:
    """Test get_namespaces_from_module_yaml."""
    modules = find_module_yaml(str(create_unique_modules))
    namespaces = get_namespaces_from_module_yaml(modules)
    assert set(namespaces) == {"test1", "test2", "test3"}


def test_get_namespaces_from_module_yaml_without_namespace(
    tmp_path: PosixPath, capfd: CaptureFixture[str]
) -> None:
    """Test get_namespaces_from_module_yaml."""
    __create_module_yaml(tmp_path)
    modules = find_module_yaml(str(tmp_path))
    with pytest.raises(SystemExit):
        get_namespaces_from_module_yaml(modules)
    out, _ = capfd.readouterr()
    assert "ERROR: namespace not found in" in out


def test_assert_namespaces_are_unique(create_repeated_modules: PosixPath) -> None:
    """Test assert_namespaces_are_unique."""
    modules = find_module_yaml(str(create_repeated_modules))
    namespaces = get_namespaces_from_module_yaml(modules)
    with pytest.raises(SystemExit):
        assert_namespaces_are_unique(namespaces)


def test_main(create_unique_modules: PosixPath, capfd: CaptureFixture[str]) -> None:
    """Test main."""
    main(str(create_unique_modules))
    out, _ = capfd.readouterr()
    assert out == "Validating namespaces...\nNamespaces are unique.\n"


def test_main_error(
    create_repeated_modules: PosixPath, capfd: CaptureFixture[str]
) -> None:
    """Test main with repeated namespaces."""
    with pytest.raises(SystemExit):
        main(str(create_repeated_modules))
    out, _ = capfd.readouterr()
    assert out == (
        "Validating namespaces...\n"
        "ERROR: namespaces are not unique, duplicates found: ['test2']\n"
    )
