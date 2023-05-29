"""Validates the Rules DB file."""
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from boostsec.registry_validator.shared import RegistryConfig
from boostsec.registry_validator.upload_rules_db import render_doc_url

RULES_SCHEMA = """
type: object
additionalProperties: false
properties:
  import:
    type: array
    items:
      - type: string
  rules:
    type: object
    additionalProperties:
      $ref: "#$defs/rule"
  default:
    type: object
    additionalProperties:
      $ref: "#$defs/rule"
$defs:
  rule:
    type: object
    additionalProperties: false
    properties:
      categories:
        type: array
        items:
          - type: string
      description:
        type: string
      group:
        type: string
      name:
        type: string
      pretty_name:
        type: string
      ref:
        type: string
    required:
      - categories
      - description
      - group
      - name
      - pretty_name
      - ref
"""


@dataclass
class RulesDbPath:
    """Path to a RulesDB with the root path."""

    root: Path
    path: Path


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


def validate_ref_url(rule: Any) -> None:
    """Validate ref url is valid."""
    url = render_doc_url(rule["ref"])
    if not url.startswith("http") and not url.startswith("https"):
        _log_error_and_exit(
            f"Url missing protocol: \"{url}\" from rule \"{rule['name']}\""
        )


def validate_rules_db(rules_db: Dict[str, Any]) -> None:
    """Validate rule is valid."""
    try:
        validate(rules_db, yaml.safe_load(RULES_SCHEMA))
    except ValidationError as e:
        _log_error_and_exit(f'Rules db is invalid: "{e.message}"')


def validate_rule_name(name: str, rule: Dict[str, Any]) -> None:
    """Validate rule name is equal to rule id."""
    if name != rule["name"]:
        _log_error_and_exit(f"Rule name \"{name}\" does not match \"{rule['name']}\"")


def validate_all_in_category(rule: Dict[str, Any]) -> None:
    """Validate category ALL is included in the categories."""
    if "ALL" not in rule["categories"]:
        _log_error_and_exit(f"Rule \"{rule['name']}\" is missing category \"ALL\"")


def validate_description_length(rule: Dict[str, Any]) -> None:
    """Validate rule description length is less than 512 characters."""
    if len(rule["description"]) > 512:
        _log_error_and_exit(
            f"Rule \"{rule['name']}\" has a description longer than 512 characters"
        )


def validate_imports(imports: list[str], config: RegistryConfig) -> None:
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


def _validate_rule(rule_name: str, rule: Dict[str, Any]) -> None:
    """Validate a single rule."""
    validate_rule_name(rule_name, rule)
    validate_ref_url(rule)
    validate_all_in_category(rule)
    validate_description_length(rule)


def validate_rules(rules_db: Dict[str, Any], config: RegistryConfig) -> None:
    """Validate rules from rules_db."""
    validate_rules_db(rules_db)
    for rule_name, rule in rules_db.get("rules", {}).items():
        _validate_rule(rule_name, rule)
    if default_rule := rules_db.get("default"):
        default_items = list(default_rule.items())
        if len(default_items) > 1:
            _log_error_and_exit("Only one default rule is allowed")
        default_name, default_rule = default_items[0]
        _validate_rule(default_name, default_rule)
    if imports := rules_db.get("import"):
        validate_imports(imports, config)


def main(scanners_path: Path, rules_realm_path: Path) -> None:
    """Validate the Rules DB file."""
    config = RegistryConfig(
        scanners_path=scanners_path, rules_realm_path=rules_realm_path
    )
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
    parser = argparse.ArgumentParser(description="Process a rule database.")
    parser.add_argument(
        "-s",
        "--scanners-path",
        help="The path of scanners.",
    )
    parser.add_argument(
        "-r",
        "--rules-realm-path",
        help="The path of rules realm.",
    )
    args = parser.parse_args()
    main(**vars(args))
