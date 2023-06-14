"""Validates that namespaces are unique."""
import sys
from pathlib import Path

import typer
import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from boostsec.registry_validator.parameters import ModulesPath, RulesRealmPath

MODULE_SCHEMA = """
type: object
properties:
  api_version:
    type: integer
  id:
    type: string
  name:
    type: string
  namespace:
    type: string
  config:
    type: object
    properties:
      support_diff_scan:
        type: boolean
    required:
      - support_diff_scan
  steps:
    type: array
required:
  - api_version
  - id
  - name
  - namespace
  - config
  - steps
"""

app = typer.Typer()


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_module_yaml(modules_path: str) -> list[Path]:
    """Find module.yaml files."""
    modules_list = []
    for path in Path(modules_path).rglob("module.yaml"):
        modules_list.append(path)
    return modules_list


def find_rules_realm_namespace(rules_realm_path: Path) -> list[str]:
    """Find rules realm with rules.yaml file."""
    return [
        str(rule.parent.relative_to(rules_realm_path))
        for rule in rules_realm_path.rglob("rules.yaml")
    ]


def get_module_namespaces(modules_list: list[Path]) -> list[str]:
    """Return the namespaces for each modules."""
    namespaces = []
    for module in modules_list:
        if namespace := yaml.safe_load(module.read_text()).get("namespace"):
            namespaces.append(namespace)
        else:
            module_relative_path = "/".join(str(module).split("/")[-4:])
            _log_error_and_exit(f'namespace not found in "{module_relative_path}"')

    return namespaces


def validate_unique_namespace(namespaces: list[str]) -> None:
    """Validate that each namespaces is unique."""
    unique_namespace = set()
    for namespace in namespaces:
        if namespace in unique_namespace:
            _log_error_and_exit(f"namespaces are not unique, duplicate: {namespace}")
        else:
            unique_namespace.add(namespace)


def validate_module_yaml_schema(module: Path) -> None:
    """Validate the module.yaml schema."""
    module_yaml = yaml.safe_load(module.read_text())
    try:
        validate(module_yaml, yaml.safe_load(MODULE_SCHEMA))
    except ValidationError as error:
        _log_error_and_exit(f'{error.message} in "{module}"')


def validate_namespaces(modules_list: list[Path], rule_namespaces: list[str]) -> None:
    """Validate the namespaces are unique between modules & rules realm."""
    module_namespaces = get_module_namespaces(modules_list)
    validate_unique_namespace(module_namespaces + rule_namespaces)


@app.command()
def main(
    modules_path: str = ModulesPath,
    rules_realm_path: str = RulesRealmPath,
) -> None:
    """Validate that namespaces are unique."""
    print("Validating namespaces...")
    modules_list = find_module_yaml(modules_path)
    rule_namespaces = find_rules_realm_namespace(Path(rules_realm_path))
    for module in modules_list:
        validate_module_yaml_schema(module)
    validate_namespaces(modules_list, rule_namespaces)
    print("Namespaces are unique.")


if __name__ == "__main__":  # pragma: no cover
    app()
