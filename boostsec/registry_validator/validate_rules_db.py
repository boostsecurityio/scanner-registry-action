"""Validates the Rules DB file."""
import sys
from pathlib import Path
from typing import Any, Dict, Sequence, cast

import typer
import yaml
from pydantic import BaseModel, ValidationError

from boostsec.registry_validator.parameters import RegistryPath
from boostsec.registry_validator.shared import RegistryConfig, RulesDbModel


class RulesDbPath(BaseModel):
    """Path to a RulesDB with the root path."""

    root: Path
    path: Path


app = typer.Typer()


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_rules_db_yaml(config: RegistryConfig) -> list[RulesDbPath]:
    """Find rules.yaml files."""
    return [
        RulesDbPath(root=config.scanners_path, path=path)
        for path in config.scanners_path.rglob("rules.yaml")
    ] + [
        RulesDbPath(root=config.rules_realm_path, path=path)
        for path in config.rules_realm_path.rglob("rules.yaml")
    ]


def _log_info(message: str) -> None:
    """Log an info message."""
    print(message)


def load_yaml_file(file_path: Path) -> Any:
    """Load a YAML file."""
    try:
        if rules_db := yaml.safe_load(file_path.read_text()):
            return rules_db
    except FileNotFoundError:
        _log_error_and_exit(f"Rules DB not found: {file_path}")
    except yaml.YAMLError:
        _log_error_and_exit("Unable to parse Rules DB file")
    return {}


def _format_validation_error(e: dict[str, Any]) -> str:
    error_type = e["type"]
    loc = ".".join(str(loc) for loc in e["loc"])
    if error_type == "value_error.missing":
        return f"{loc} is a required property"
    elif error_type == "value_error.extra":
        return f"Additional properties are not allowed ({loc} was unexpected)"
    else:
        msg = e.get("msg", "unknown error")
        return f"{loc}: {msg}"


def validate_rules_db(rules_db: Dict[str, Any]) -> RulesDbModel:
    """Validate rule is valid."""
    try:
        rule = RulesDbModel.parse_obj(rules_db)
    except ValidationError as e:
        _log_error_and_exit(
            "Rules db is invalid: "
            + "\t\n".join(
                _format_validation_error(cast(dict[str, Any], err))
                for err in e.errors()
            )
        )

    return rule


def validate_imports(imports: Sequence[str], config: RegistryConfig) -> None:
    """Validate the imports exists & not circular."""
    visited: set[str] = set()
    visited_stack: set[str] = set()
    for ns in imports:
        _validate_imports(ns, visited, visited_stack, config)


def _validate_imports(
    namespace: str, visited: set[str], visited_stack: set[str], config: RegistryConfig
) -> None:
    """Recursively validate each namespace imports.

    Validate that:
        1. imports exists
        2. imports are not circular
    """
    if namespace in visited and namespace in visited_stack:
        _log_error_and_exit("Import cycle detected")
    else:
        visited.add(namespace)
        visited_stack.add(namespace)

    scanner_path = config.scanners_path / namespace / "rules.yaml"
    rules_realm_path = config.rules_realm_path / namespace / "rules.yaml"
    data = {}
    if scanner_path.exists():
        data = load_yaml_file(scanner_path)
    elif rules_realm_path.exists():
        data = load_yaml_file(rules_realm_path)
    else:
        _log_error_and_exit(f"Imported namespace {namespace} not found")

    if imports := data.get("import"):
        for ns in imports:
            _validate_imports(ns, visited, visited_stack, config)

    visited_stack.discard(namespace)


def validate_rules(raw_rules_db: Dict[str, Any], config: RegistryConfig) -> None:
    """Validate rules from rules_db."""
    rules_db = validate_rules_db(raw_rules_db)
    if imports := rules_db.imports:
        validate_imports(imports, config)


@app.command()
def main(registry_path: Path = RegistryPath) -> None:
    """Validate the Rules DB file."""
    config = RegistryConfig.from_registry(registry_path)
    if rules_db_list := find_rules_db_yaml(config):
        for rules_db_path in rules_db_list:
            _log_info(
                f"Validating {rules_db_path.path.relative_to(rules_db_path.root)}"
            )
            if rules_db := load_yaml_file(rules_db_path.path):
                validate_rules(rules_db, config)
            else:
                _log_error_and_exit("Rules DB is empty")
    else:
        _log_info("No Rules DB found")


if __name__ == "__main__":  # pragma: no cover
    app()
