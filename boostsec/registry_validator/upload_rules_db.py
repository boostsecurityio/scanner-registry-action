"""Uploads the Rules DB file."""
import argparse
import os
import sys
from pathlib import Path
from subprocess import check_call, check_output  # noqa: S404
from typing import Any, Optional
from urllib.parse import urljoin

import yaml
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

from boostsec.registry_validator.shared import RegistryConfig

RulesDB = dict[str, dict[str, str]]

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


def render_doc_url(unrendered_url: str) -> str:
    """Render doc url."""
    var_name = "BOOSTSEC_DOC_BASE_URL"
    placeholder = f"{{{var_name}}}"
    if placeholder in unrendered_url:
        doc_base_url = os.environ[var_name]
        return unrendered_url.replace(placeholder, doc_base_url)
    else:
        return unrendered_url


def find_updated_scanners(
    scanners_path: Path, git_root: Optional[Path] = None
) -> list[Path]:
    """Find module.yaml files."""
    fetch_command = ["git", "fetch", "--deepen=1", "--quiet"]
    check_call(fetch_command, cwd=git_root)  # noqa: S603 noboost
    diff_command = [
        "git",
        "--no-pager",
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter",
        "AM",
        "HEAD~1",
        "--",
        str(scanners_path),
    ]
    diff_output = check_output(diff_command, cwd=git_root)  # noqa: S603 noboost
    diff_output_list = diff_output.decode("utf-8").splitlines()

    modules_dic = {}
    for path in [i for i in diff_output_list if i.endswith("yaml")]:
        module_path = (git_root or Path(".")) / Path(path).parent
        modules_dic[str(module_path)] = module_path
    return [i for i in modules_dic.values() if has_rules_yaml(i)]


def _get_header(api_token: str) -> dict[str, str]:
    """Get the header."""
    return {
        "Authorization": f"ApiKey {api_token}",
        "Content-Type": "application/json",
    }


def _get_variables(
    namespace: str, driver: str, rules: RulesDB, default_rule: Optional[str] = None
) -> dict[str, Any]:
    """Get the variables."""
    variables = {
        "rules": {
            "namespace": namespace,
            "defaultRule": default_rule,
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
                for _, rule in rules.items()
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


def _get_rules_and_default(
    namespace: str, config: RegistryConfig
) -> tuple[RulesDB, Optional[str]]:
    """Get the rules and default rule if applicable."""
    if namespace == "default":
        namespace = "boostsecurityio/native-scanner"

    scanners_path = config.scanners_path / namespace / "rules.yaml"
    rules_realm_path = config.rules_realm_path / namespace / "rules.yaml"
    if scanners_path.exists():
        rules_db_yaml = yaml.safe_load(scanners_path.read_text())
    else:
        rules_db_yaml = yaml.safe_load(rules_realm_path.read_text())

    rules: RulesDB = {}
    default_rule = None
    if imports := rules_db_yaml.get("import"):
        for ns in imports:
            import_rules, imported_default = _get_rules_and_default(ns, config)
            rules.update(import_rules)
            default_rule = imported_default or default_rule

    if module_rules := rules_db_yaml.get("rules"):
        rules.update(module_rules)

    if default := rules_db_yaml.get("default"):
        rules.update(default)
        default_rule = next(iter(default.keys()))

    return rules, default_rule


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


def upload_rules_db(
    module: Path, api_endpoint: str, api_token: str, config: RegistryConfig
) -> None:
    """Upload the rules.yaml file."""
    header = _get_header(api_token)
    namespace, driver = _get_namespace_and_driver(module)
    rules, default_rule = _get_rules_and_default(namespace, config)
    variables = _get_variables(namespace, driver, rules, default_rule)
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


def main(
    api_endpoint: str, api_token: str, scanners_path: str, rules_realm_path: str
) -> None:
    """Validate the Rules DB file."""
    config = RegistryConfig(
        scanners_path=Path(scanners_path), rules_realm_path=Path(rules_realm_path)
    )
    modules = find_updated_scanners(config.scanners_path)
    if len(modules) == 0:
        print("No module rules to update.")
    else:
        for module in modules:
            upload_rules_db(module, api_endpoint, api_token, config)


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
