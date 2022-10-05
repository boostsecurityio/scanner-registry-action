"""Validates that namespaces are unique."""
import argparse
from pathlib import Path

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from boostsec.registry_validator.common import find_module_yaml, log_error_and_exit

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


def validate_module_yaml_schema(module: Path) -> None:
    """Validate the module.yaml schema."""
    module_yaml = yaml.safe_load(module.read_text())
    try:
        validate(module_yaml, yaml.safe_load(MODULE_SCHEMA))
    except ValidationError as error:
        log_error_and_exit(f'{error.message} in "{module}"')


def validate_namespaces_from_modules_yaml(modules_list: list[Path]) -> None:
    """Get namespaces from module.yaml files."""
    namespaces = {}
    for module in modules_list:
        if namespace := yaml.safe_load(module.read_text()).get("namespace"):
            if namespace in namespaces:
                log_error_and_exit(f"namespaces are not unique, duplicate: {namespace}")
            else:
                namespaces[namespace] = module
        else:
            module_relative_path = "/".join(str(module).split("/")[-4:])
            log_error_and_exit(f'namespace not found in "{module_relative_path}"')


def main(modules_path: str) -> None:
    """Validate that namespaces are unique."""
    print("Validating namespaces...")
    modules_list = find_module_yaml(modules_path)
    for module in modules_list:
        validate_module_yaml_schema(module)
    validate_namespaces_from_modules_yaml(modules_list)
    print("Namespaces are unique.")


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="Process a rule database.")
    parser.add_argument(
        "-m",
        "--modules-path",
        help="The location of the rule database.",
    )
    args = parser.parse_args()
    main(**vars(args))
