"""Uploads the Rules DB file."""
import argparse
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import yaml
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

MUTATION = gql(
    """
mutation setRules($rules: RuleInputSchemas!) {
    setRules(namespacedRules: $rules){
        __typename
        ... on RuleSuccessSchema {
            successMessage
        }
        ... on RuleErrorSchema {
            errorMessage
        }
    }
}"""
)


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_rules_db_yaml(rules_db_path: str) -> list[str]:
    """Find module.yaml files."""
    rules_db_list = []
    for root, _, files in os.walk(rules_db_path):
        for file in files:
            if file.endswith("rules.yaml"):
                file_path = os.path.join(root, file)
                rules_db_list.append(file_path)
    return rules_db_list


def render_doc_url(unrendered_url: str) -> str:
    """Render doc url."""
    var_name = "BOOSTSEC_DOC_BASE_URL"
    placeholder = f"{{{var_name}}}"
    if placeholder in unrendered_url:
        doc_base_url = os.environ[var_name]
        return unrendered_url.replace(placeholder, doc_base_url)
    else:
        return unrendered_url


def _get_header(api_token: str) -> dict[str, str]:
    """Get the header."""
    return {
        "Authorization": f"ApiKey {api_token}",
        "Content-Type": "application/json",
    }


def _get_variables(namespace: str, driver: str, module: Path) -> dict[str, Any]:
    """Get the variables."""
    rules_db_path = module / "rules.yaml"
    rules_db_yaml = yaml.safe_load(rules_db_path.read_text())
    variables = {
        "rules": {
            "namespace": namespace,
            "ruleInputs": [
                {
                    "categories": rule["categories"],
                    "description": rule["description"],
                    "driver": driver,
                    "group": rule["group"],
                    "name": rule["name"],
                    "prettyName": rule["pretty_name"],
                    "ref": render_doc_url(rule["ref"]),
                }
                for _, rule in rules_db_yaml["rules"].items()
            ],
        },
    }
    return variables


def _get_namespace_and_driver(module: Path) -> tuple[str, str]:
    """Get the namespace and driver."""
    module_path = module / "module.yaml"
    module_yaml = yaml.safe_load(module_path.read_text())
    namespace = module_yaml["namespace"]
    driver = module_yaml["name"]
    return namespace, driver


def has_rules_yaml(module: Path) -> bool:
    """Validate a module."""
    module_items = list(map(str, module.rglob("*.yaml")))
    if not any(i.endswith("rules.yaml") for i in module_items):
        print(f'WARNING: rules.yaml not found in "{module}". Skipping...')
        return False
    return True


def _get_gql_session(api_endpoint: str, header: dict[str, str]) -> Client:
    """Get the gql session."""
    transport = RequestsHTTPTransport(
        url=urljoin(api_endpoint, "/rules-management/graphql"), headers=header
    )
    return Client(transport=transport)


def upload_rules_db(module: Path, api_endpoint: str, api_token: str) -> None:
    """Upload the rules.yaml file."""
    header = _get_header(api_token)
    namespace, driver = _get_namespace_and_driver(module)
    variables = _get_variables(namespace, driver, module)
    gql_session = _get_gql_session(api_endpoint, header)

    print(f'Uploading rules "{namespace}" "{driver}"...')
    try:
        response = gql_session.execute(
            MUTATION,
            variable_values=variables,
        )
    except Exception as e:  # noqa: WPS440
        _log_error_and_exit(f"Failed to upload rules: {e}.")

    if response["setRules"]["__typename"] != "RuleSuccessSchema":
        _log_error_and_exit(
            f"Unable to upload rules-db: {response['setRules']['errorMessage']}"
        )


def main(api_endpoint: str, api_token: str, rules_db_path: str) -> None:
    """Validate the Rules DB file."""
    rules = find_rules_db_yaml(rules_db_path)
    if len(rules) == 0:
        print("No module rules to update.")
    else:
        for rule in rules:
            module_path = Path(rule).parent
            upload_rules_db(module_path, api_endpoint, api_token)


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description="Process a rule database.")
    parser.add_argument(
        "-e",
        "--api-endpoint",
        help="The API endpoint to validate against.",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--api-token",
        help="The GitHub token to use for authentication.",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--rules-db-path",
        help="The path of the rule database.",
    )
    args = parser.parse_args()
    main(**vars(args))
