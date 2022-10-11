"""Uploads the Rules DB file."""
import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml

MUTATION = """
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


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_modules(files_stdin: str) -> list[Path]:
    """Find module.yaml files."""
    modules_dic = {}
    for path in [i for i in files_stdin.splitlines() if i.endswith("yaml")]:
        module_path = Path(path).parent
        modules_dic[str(module_path)] = module_path
    return [i for i in modules_dic.values() if has_rules_yaml(i)]


def _get_header(api_token: str) -> dict[str, Any]:
    """Get the header."""
    return {
        "Authorization": f"ApiKey {api_token}",
        "Content-Type": "application/json",
    }


def _get_payload(namespace: str, driver: str, module: Path) -> dict[str, Any]:
    """Get the payload."""
    rules_db_path = module / "rules.yaml"
    rules_db_yaml = yaml.safe_load(rules_db_path.read_text())
    payload = {
        "query": MUTATION,
        "variables": {
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
                        "ref": rule["ref"],
                    }
                    for _, rule in rules_db_yaml["rules"].items()
                ],
            },
        },
    }
    return payload


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


def upload_rules_db(module: Path, api_endpoint: str, api_token: str) -> None:
    """Upload the rules.yaml file."""
    namespace, driver = _get_namespace_and_driver(module)
    header = _get_header(api_token)
    payload = _get_payload(namespace, driver, module)
    print(f'Uploading rules "{namespace}" "{driver}"...')
    response = requests.post(
        urljoin(api_endpoint, "/rules-management/graphql"),
        headers=header,
        data=json.dumps(payload),
    )
    if response.status_code != 200 or "RuleErrorSchema" == response.text:
        _log_error_and_exit(f"Unable to upload rules-db: {response.text}")


def main(files_stdin: str, api_endpoint: str, api_token: str) -> None:
    """Validate the Rules DB file."""
    modules = find_modules(files_stdin)
    if len(modules) == 0:
        print("No module rules to update.")
    else:
        for module in modules:
            upload_rules_db(module, api_endpoint, api_token)


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
    args = parser.parse_args()
    main(sys.stdin.read(), **vars(args))