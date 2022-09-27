"""Validates that namespaces are unique."""
import argparse
import os
import sys

import yaml


def find_module_yaml(modules_path: str) -> list[str]:
    """Find module.yaml files."""
    modules_list = []
    for root, _, files in os.walk(modules_path):
        for file in files:
            if file.endswith("module.yaml"):
                file_path = os.path.join(root, file)
                modules_list.append(file_path)
    return modules_list


def get_namespaces_from_module_yaml(modules_list: list[str]) -> list[str]:
    """Get namespaces from module.yaml files."""
    namespaces_list = []
    for module in modules_list:
        with open(module, "r") as module_file:
            module_yaml = yaml.safe_load(module_file)
            if "namespace" not in module_yaml:
                print(f"ERROR: namespace not found in {module}")
                sys.exit(1)
            namespaces_list.append(module_yaml["namespace"])
    return namespaces_list


def _find_duplicated_namespaces(namespaces_list: list[str]) -> list[str]:
    """Find duplicated namespaces."""
    duplicates = set()
    for namespace in namespaces_list:
        if namespaces_list.count(namespace) > 1:
            duplicates.add(namespace)
    return list(duplicates)


def assert_namespaces_are_unique(namespaces_list: list[str]) -> None:
    """Assert that namespaces are unique."""
    if not len(namespaces_list) == len(set(namespaces_list)):
        duplicates = _find_duplicated_namespaces(namespaces_list)
        print(f"ERROR: namespaces are not unique, duplicates found: {duplicates}")
        sys.exit(1)


def main(modules_path: str) -> None:
    """Validate that namespaces are unique."""
    print("Validating namespaces...")
    modules_list = find_module_yaml(modules_path)
    namespaces_list = get_namespaces_from_module_yaml(modules_list)
    assert_namespaces_are_unique(namespaces_list)
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
