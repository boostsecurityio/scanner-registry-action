"""Validates the Rules DB file."""
import argparse
import os
import sys
from typing import Any, Dict

import requests
import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

RULES_SCHEMA = """
type: object
additionalProperties: false
properties:
  rules:
    type: object
    additionalProperties:
      type: object
      additionalProperties: false
      properties:
        categories:
          type: array
          items:
          - type: string
        description:
          type: string
        driver:
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
      - driver
      - group
      - name
      - pretty_name
      - ref
"""


def find_rules_db_yaml(rules_db_path: str) -> list[str]:
    """Find module.yaml files."""
    rules_db_list = []
    for root, _, files in os.walk(rules_db_path):
        for file in files:
            if file.endswith("rules_db.yaml"):
                file_path = os.path.join(root, file)
                rules_db_list.append(file_path)
    return rules_db_list


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def _log_info(message: str) -> None:
    """Log an info message."""
    print(message)


def load_yaml_file(file_path: str) -> Any:
    """Load a YAML file."""
    try:
        with open(file_path, "r") as file:
            if rules_db := yaml.safe_load(file):
                return rules_db
    except FileNotFoundError:
        _log_error_and_exit(f"Rules DB not found: {file_path}")
    except yaml.YAMLError:
        _log_error_and_exit("Unable to parse Rules DB file")
    return {}


def validate_ref_url(rule: Any) -> None:
    """Validate ref url is valid."""
    if not rule["ref"].startswith("http") and not rule["ref"].startswith("https"):
        _log_error_and_exit(
            f"Url missing protocol: \"{rule['ref']}\" from rule \"{rule['name']}\""
        )
    try:
        response = requests.get(rule["ref"])
        if not response.status_code == 200:
            _log_error_and_exit(
                f"Invalid url: \"{rule['ref']}\" from rule \"{rule['name']}\""
            )
    except requests.exceptions.ConnectionError:
        _log_error_and_exit(
            f"Invalid url: \"{rule['ref']}\" from rule \"{rule['name']}\""
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
    """Validate rule description length is less than 255 characters."""
    if len(rule["description"]) > 255:
        _log_error_and_exit(
            f"Rule \"{rule['name']}\" has a description longer than 255 characters"
        )


def validate_rules(rules_db: Dict[str, Any]) -> None:
    """Validate rules from rules_db."""
    _log_info("Validating rules...")
    validate_rules_db(rules_db)
    for rule_name, rule in rules_db["rules"].items():
        validate_rule_name(rule_name, rule)
        validate_ref_url(rule)
        validate_all_in_category(rule)
        validate_description_length(rule)
    _log_info("Rules are valid!")


def main(rules_db_path: str) -> None:
    """Validate the Rules DB file."""
    if rules_db_list := find_rules_db_yaml(rules_db_path):
        for rules_db_path in rules_db_list:
            if rules_db := load_yaml_file(rules_db_path):
                validate_rules(rules_db)
            else:
                _log_error_and_exit("Rules DB is empty")
    else:
        _log_info("No Rules DB found")


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="Process a rule database.")
    parser.add_argument(
        "-r",
        "--rules-db-path",
        help="The path of the rule database.",
    )
    args = parser.parse_args()
    main(**vars(args))
