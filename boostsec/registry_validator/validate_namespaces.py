"""Validates that namespaces are unique."""
import sys
from pathlib import Path
from typing import Any, Union, cast

import typer
import yaml
from pydantic import ValidationError

from boostsec.registry_validator.config import RegistryConfig
from boostsec.registry_validator.errors import format_validation_error
from boostsec.registry_validator.parameters import RegistryPath
from boostsec.registry_validator.schema import ModuleSchema, ServerSideModuleSchema

app = typer.Typer()


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_module_yaml(modules_path: Path) -> list[Path]:
    """Find module.yaml files."""
    modules_list = []
    for path in modules_path.rglob("module.yaml"):
        modules_list.append(path)
    return modules_list


def find_rules_realm_namespace(rules_realm_path: Path) -> list[str]:
    """Find rules realm with rules.yaml file."""
    return [
        str(rule.parent.relative_to(rules_realm_path))
        for rule in rules_realm_path.rglob("rules.yaml")
    ]


def get_module_namespaces(
    modules_list: Union[list[ModuleSchema], list[ServerSideModuleSchema]],
) -> list[str]:
    """Return the namespaces for each modules."""
    return [module.namespace for module in modules_list]


def validate_unique_namespace(namespaces: list[str]) -> None:
    """Validate that each namespaces is unique."""
    unique_namespace = set()
    for namespace in namespaces:
        if namespace in unique_namespace:
            _log_error_and_exit(f"namespaces are not unique, duplicate: {namespace}")
        else:
            unique_namespace.add(namespace)


def validate_module_yaml_schema(module: Path) -> ModuleSchema:
    """Validate and load the module.yaml schema."""
    module_yaml = yaml.safe_load(module.read_text())
    try:
        schema = ModuleSchema.parse_obj(module_yaml)
    except ValidationError as e:
        _log_error_and_exit(
            f"{module} is invalid: "
            + "\t\n".join(
                format_validation_error(cast(dict[str, Any], err)) for err in e.errors()
            )
        )

    return schema


def validate_server_side_module(module: Path) -> ServerSideModuleSchema:
    """Validate and load the module.yaml schema."""
    module_yaml = yaml.safe_load(module.read_text())
    try:
        schema = ServerSideModuleSchema.parse_obj(module_yaml)
    except ValidationError as e:
        _log_error_and_exit(
            f"{module} is invalid: "
            + "\t\n".join(
                format_validation_error(cast(dict[str, Any], err)) for err in e.errors()
            )
        )

    return schema


def validate_namespaces(
    modules_list: list[ModuleSchema],
    rule_namespaces: list[str],
    server_modules: list[ServerSideModuleSchema],
) -> None:
    """Validate the namespaces are unique between modules & rules realm."""
    module_namespaces = get_module_namespaces(modules_list)
    server_namespaces = get_module_namespaces(server_modules)
    validate_unique_namespace(module_namespaces + rule_namespaces + server_namespaces)


@app.command()
def main(
    registry_path: Path = RegistryPath,
) -> None:
    """Validate that namespaces are unique."""
    config = RegistryConfig.from_registry(registry_path)
    print("Validating namespaces...")
    modules_list = find_module_yaml(config.scanners_path)
    rule_namespaces = find_rules_realm_namespace(config.rules_realm_path)
    server_list = find_module_yaml(config.server_side_scanners_path)
    modules = [validate_module_yaml_schema(module) for module in modules_list]
    server_modules = [validate_server_side_module(module) for module in server_list]
    validate_namespaces(modules, rule_namespaces, server_modules)
    print("Namespaces are unique.")


if __name__ == "__main__":  # pragma: no cover
    app()
