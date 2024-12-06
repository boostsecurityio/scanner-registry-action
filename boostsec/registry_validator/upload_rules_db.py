"""Uploads the Rules DB file."""

import sys
from pathlib import Path
from subprocess import check_call, check_output
from typing import cast
from urllib.parse import urljoin

import typer
import yaml
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

from boostsec.registry_validator.config import RegistryConfig
from boostsec.registry_validator.models import (
    NamespaceType,
    NamespaceUnion,
    RuleRealmNamespace,
    ScannerNamespace,
)
from boostsec.registry_validator.parameters import ApiEndpoint, ApiToken, RegistryPath
from boostsec.registry_validator.schema import RulesDbSchema, RulesSchema

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

app = typer.Typer()


def _log_error_and_exit(message: str) -> None:
    """Log an error message and exit."""
    print("ERROR: " + message)
    sys.exit(1)


def find_updated_namespaces(registry_path: Path, folder: Path) -> set[str]:
    """Find updated namespaces in the registry path under provider folder.

    Any namespace without a rules.yaml file is ignored.
    """
    fetch_command = ["git", "fetch", "--deepen=1", "--quiet"]
    check_call(fetch_command, cwd=registry_path)  # noqa: S603 noboost
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
        str(folder),
    ]
    diff_output = check_output(diff_command, cwd=registry_path)  # noqa: S603 noboost
    diff_output_list = diff_output.decode("utf-8").splitlines()
    paths = [
        (registry_path / diff).parent
        for diff in diff_output_list
        if diff.endswith("yaml")
    ]
    return {str(path.relative_to(folder)) for path in paths if has_rules_yaml(path)}


def load_scanners(scanners_path: Path, updated_ns: set[str]) -> list[ScannerNamespace]:
    """Load and parse all scanners under the provided path.

    Any scanner using the `default` namespace will be renamed
    to `boostsecurityio/native-scanner`.
    """
    scanners = []
    for module_path in scanners_path.rglob("module.yaml"):
        scanner_path = module_path.parent

        module_yaml = yaml.safe_load(module_path.read_text())
        namespace = module_yaml["namespace"]
        if namespace == "default":  # Support legacy default scanner name
            namespace = "boostsecurityio/native-scanner"

        if namespace != str(scanner_path.relative_to(scanners_path)):
            print(
                "WARNING: Scanner directory "
                f'"{scanner_path.relative_to(scanners_path)}" doesn\'t match namespace '
                f'"{namespace}". Skipping...'
            )
            continue

        driver = module_yaml["name"]
        rules_path = scanner_path / "rules.yaml"
        if not rules_path.exists():
            print(f'WARNING: rules.yaml not found in "{namespace}". Skipping...')
            continue

        rules_db_yaml = yaml.safe_load(rules_path.read_text())
        rules = RulesDbSchema.parse_obj(rules_db_yaml)

        scanners.append(
            ScannerNamespace(
                namespace=namespace,
                driver=driver,
                imports=rules.imports or [],
                rules=rules.rules or {},
                default=rules.default,
                updated=namespace in updated_ns,
            )
        )

    return scanners


def load_rules_realm(
    rules_realm_path: Path, updated_ns: set[str]
) -> list[RuleRealmNamespace]:
    """Load and parse all rules realm under the provided path."""
    rules_realm = []
    for realm_path in rules_realm_path.rglob("rules.yaml"):
        rules_db_yaml = yaml.safe_load(realm_path.read_text())
        rules = RulesDbSchema.parse_obj(rules_db_yaml)
        namespace = str(realm_path.relative_to(rules_realm_path).parent)
        rules_realm.append(
            RuleRealmNamespace(
                namespace=namespace,
                rules=rules.rules or {},
                imports=rules.imports or [],
                default=rules.default,
                updated=namespace in updated_ns,
            )
        )

    return rules_realm


def make_namespace_cache(
    scanners: list[ScannerNamespace],
    rules_realm: list[RuleRealmNamespace],
    server_side_scanners: list[ScannerNamespace],
) -> dict[str, NamespaceUnion]:
    """Create a map from scanners & rules realm with their namespace as key."""
    return (
        {scanner.namespace: scanner for scanner in server_side_scanners}
        | {scanner.namespace: scanner for scanner in scanners}
        | {realm.namespace: realm for realm in rules_realm}
    )


def rollup(
    node: NamespaceUnion, namespace_cache: dict[str, NamespaceUnion]
) -> NamespaceUnion:
    """Rollup the rules, default & updated from the node imports."""
    rules: RulesSchema = {}
    default = None
    updated = node.updated

    for imported in node.imports:
        imported_ns = namespace_cache[imported]
        imported_ns = rollup(imported_ns, namespace_cache)
        rules.update(imported_ns.rules)
        default = imported_ns.default or default
        updated = imported_ns.updated or updated

    rules.update(node.rules)
    default = node.default or default

    if node.namespace_type == NamespaceType.Scanner:
        return ScannerNamespace(
            **node.dict(exclude={"rules", "default", "updated"}),
            rules=rules,
            default=default,
            updated=updated,
        )
    else:
        return RuleRealmNamespace(
            **node.dict(exclude={"rules", "default", "updated"}),
            rules=rules,
            default=default,
            updated=updated,
        )


def get_updated_scanners(
    scanners: list[ScannerNamespace], namespace_cache: dict[str, NamespaceUnion]
) -> list[ScannerNamespace]:
    """Return the list of updated scanners.

    A scanner is considered updated if either itself was updated or if any
    of its imports was updated.
    """
    rollup_scanners = cast(
        list[ScannerNamespace],
        [rollup(scanner, namespace_cache) for scanner in scanners],
    )

    return [scanner for scanner in rollup_scanners if scanner.updated]


def _get_header(api_token: str) -> dict[str, str]:
    """Get the header."""
    return {
        "Authorization": f"ApiKey {api_token}",
        "Content-Type": "application/json",
    }


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
    scanner: ScannerNamespace, api_endpoint: str, api_token: str
) -> None:
    """Upload the rules.yaml file."""
    header = _get_header(api_token)
    gql_session = _get_gql_session(api_endpoint, header)

    print(f'Uploading rules "{scanner.namespace}" "{scanner.driver}"...')

    rules = scanner.rules
    default = None
    if scanner.default:
        rules.update(scanner.default)
        default = next(iter(scanner.default.keys()))

    try:
        response = gql_session.execute(
            MUTATION,
            variable_values={
                "rules": {
                    "namespace": scanner.namespace,
                    "defaultRule": default,
                    "ruleInputs": [
                        {
                            "categories": rule.categories,
                            "description": rule.description,
                            "driver": scanner.driver,
                            "group": rule.group,
                            "name": rule.name,
                            "prettyName": rule.pretty_name,
                            "ref": rule.ref,
                            "recommended": rule.recommended,
                            "remediation": rule.remediation,
                        }
                        for rule in rules.values()
                    ],
                },
            },
        )
    except Exception as e:  # noqa: BLE001
        _log_error_and_exit(f"Failed to upload rules: {e}.")
    else:
        if response["setRules"]["__typename"] != "RuleSuccessSchema":
            _log_error_and_exit(
                f"Unable to upload rules-db: {response['setRules']['errorMessage']}"
            )


@app.command()
def main(
    api_endpoint: str = ApiEndpoint,
    api_token: str = ApiToken,
    registry_path: Path = RegistryPath,
) -> None:
    """Process a rule database."""
    config = RegistryConfig.from_registry(registry_path)
    updated_scanners = find_updated_namespaces(registry_path, config.scanners_path)
    updated_server_scanners = find_updated_namespaces(
        registry_path, config.server_side_scanners_path
    )
    updated_scanners = updated_scanners | updated_server_scanners
    updated_realms = find_updated_namespaces(registry_path, config.rules_realm_path)
    updated_ns = updated_scanners | updated_realms

    scanners = load_scanners(config.scanners_path, updated_ns)
    server_scanners = load_scanners(config.server_side_scanners_path, updated_ns)
    scanners = scanners + server_scanners

    rules_realm = load_rules_realm(config.rules_realm_path, updated_ns)
    namespace_cache = make_namespace_cache(scanners, rules_realm, server_scanners)
    scanners_to_update = get_updated_scanners(scanners, namespace_cache)

    if len(scanners_to_update) == 0:
        print("No module rules to update.")
        return None

    for scanner in scanners_to_update:
        upload_rules_db(scanner, api_endpoint, api_token)


if __name__ == "__main__":  # pragma: no cover
    app()
