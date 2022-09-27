"""Validates that namespaces are unique."""
import argparse
import sys
from pathlib import Path

import yaml


def find_module_yaml(modules_path: str) -> list[str]:
    """Find module.yaml files."""
    modules_list = []
    for path in Path(modules_path).rglob("module.yaml"):
        modules_list.append(str(path))
    return modules_list


def validate_namespaces_from_module_yaml(modules_list: list[str]) -> None:
    """Get namespaces from module.yaml files."""
    namespaces = {}
    for module in modules_list:
        with open(module, "r") as module_file:

            if namespace := yaml.safe_load(module_file).get("namespace"):
                if namespace in namespaces:
                    print(f"ERROR: namespaces are not unique, duplicate: {namespace}")
                    sys.exit(1)
                else:
                    namespaces[namespace] = module
            else:
                module_relative_path = "/".join(module.split("/")[-4:])
                print(f'ERROR: namespace not found in "{module_relative_path}"')
                sys.exit(1)


def main(modules_path: str) -> None:
    """Validate that namespaces are unique."""
    print("Validating namespaces...")
    modules_list = find_module_yaml(modules_path)
    validate_namespaces_from_module_yaml(modules_list)
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
