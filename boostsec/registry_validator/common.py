"""Common functions for the registry validator."""
import sys
from pathlib import Path


def log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_module_yaml(modules_path: str) -> list[Path]:
    """Find module.yaml files."""
    modules_list = []
    for path in Path(modules_path).rglob("module.yaml"):
        modules_list.append(path)
    return modules_list
