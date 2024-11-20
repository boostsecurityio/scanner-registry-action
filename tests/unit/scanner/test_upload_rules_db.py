"""Test."""

from pathlib import Path
from subprocess import check_call
from typing import Any, Optional
from urllib.parse import urljoin

import pytest
import yaml
from pydantic import AnyHttpUrl
from requests_mock import Mocker

from boostsec.registry_validator.models import RuleRealmNamespace, ScannerNamespace
from boostsec.registry_validator.testing.factories import (
    RuleRealmNamespaceFactory,
    RuleSchemaFactory,
    RulesDbSchemaFactory,
    ScannerNamespaceFactory,
)
from boostsec.registry_validator.upload_rules_db import (
    find_updated_namespaces,
    get_updated_scanners,
    load_rules_realm,
    load_scanners,
    make_namespace_cache,
    rollup,
    upload_rules_db,
)

yaml.SafeDumper.add_representer(  # use to create fake rules.yaml
    AnyHttpUrl, lambda dumper, url: dumper.represent_str(str(url))
)


def _create_module_and_rules(
    registry_path: Path,
    rules_db_string: str,
    namespace: str = "",
    create_rules: bool = True,
    module_path: Optional[Path] = None,
) -> Path:
    """Create a module.yaml file."""
    modules_path = registry_path / (module_path or namespace)
    modules_path.mkdir(parents=True)
    module_yaml = modules_path / "module.yaml"
    module_obj = {
        "api_version": 1,
        "id": "example-diff-sarif",
        "name": "Example Scanner",
        "config": {"support_diff_scan": True},
        "steps": [],
    }
    if namespace:
        module_obj["namespace"] = namespace
    module_yaml.write_text(yaml.dump(module_obj))
    if create_rules:
        rules_yaml = modules_path / "rules.yaml"
        rules_yaml.write_text(rules_db_string)
    return module_yaml


def _create_rules_realm(
    registry_path: Path, rules_db_string: str, namespace: str = ""
) -> Path:
    """Create a rules-realm."""
    realm_path = registry_path / namespace
    realm_path.mkdir(parents=True)
    rules_yaml = realm_path / "rules.yaml"
    rules_yaml.write_text(rules_db_string)

    return rules_yaml


def _init_repo(git_root: Path) -> None:
    """Initialize an empty git repo."""
    check_call(["git", "init"], cwd=git_root)  # noqa: S603 S607 noboost
    check_call(  # noboost
        ["git", "commit", "--allow-empty", "-m", "first commit"],  # noqa: S603 S607
        cwd=git_root,
    )


def _commit_all_changes(git_root: Path, message: str = "commit") -> None:
    """Commit all changes in the git_root repo."""
    check_call(["git", "add", "-A"], cwd=git_root)  # noqa: S603 S607 noboost
    check_call(  # noboost
        ["git", "commit", "-am", message],  # noqa: S603 S607
        cwd=git_root,
    )


def test_load_scanners(scanners_path: Path) -> None:
    """Should load all and convert every scanners.

    For backward compatibility, any namespace named default should be renamed
    to boostsecurityio/native-scanner.
    """
    namespace = "multi/level/path/namespace-example"
    imports = ["imported/ns"]
    rules = {
        "my-rule-1": RuleSchemaFactory.build(name="my-rule-1"),
        "my-rule-2": RuleSchemaFactory.build(name="my-rule-2"),
    }
    rules_db = RulesDbSchemaFactory.build(rules=rules, imports=imports)

    _create_module_and_rules(
        scanners_path,
        yaml.safe_dump(rules_db.dict()),
        namespace,
    )

    result = load_scanners(scanners_path, {namespace})
    assert result == [
        ScannerNamespace(
            namespace=namespace,
            driver="Example Scanner",
            rules=rules,
            imports=imports,
            updated=True,
        ),
    ]


def test_load_scanners_default_values(scanners_path: Path) -> None:
    """Should use default values for rules, imports and updated.

    For backward compatibility, any namespace named default should be renamed
    to boostsecurityio/native-scanner.
    """
    rules_db = RulesDbSchemaFactory.build()

    _create_module_and_rules(
        scanners_path,
        yaml.safe_dump(rules_db.dict()),
        namespace="default",
        module_path=Path("boostsecurityio/native-scanner"),
    )

    result = load_scanners(scanners_path, set())
    assert result == [
        ScannerNamespace(
            namespace="boostsecurityio/native-scanner",
            driver="Example Scanner",
            rules={},
            imports=[],
            updated=False,
        ),
    ]


def test_load_rules_realm(rules_realm_path: Path) -> None:
    """Should load all and convert every rules-realm."""
    ns = "boostsecurityio/mitre-cwe"
    rules = {
        "my-rule-1": RuleSchemaFactory.build(name="my-rule-1"),
        "my-rule-2": RuleSchemaFactory.build(name="my-rule-2"),
    }
    rules_db = RulesDbSchemaFactory.build(rules=rules, imports=["imported/ns"])

    _create_rules_realm(rules_realm_path, yaml.safe_dump(rules_db.dict()), ns)

    result = load_rules_realm(rules_realm_path, {ns})
    assert result == [
        RuleRealmNamespace(
            namespace=ns, rules=rules, imports=["imported/ns"], updated=True
        )
    ]


def test_load_rules_realm_default_values(rules_realm_path: Path) -> None:
    """Should load all and convert every rules-realm."""
    ns = "deep/path/rules"
    rules_db = RulesDbSchemaFactory.build()

    _create_rules_realm(rules_realm_path, yaml.safe_dump(rules_db.dict()), ns)

    result = load_rules_realm(rules_realm_path, set())
    assert result == [
        RuleRealmNamespace(namespace=ns, rules={}, imports=[], updated=False)
    ]


def test_make_namespace_cache() -> None:
    """Test building namespace cache from scanners & realms ns.

    There should be an entry for every scanners & rules with their name as key.
    """
    scanners = ScannerNamespaceFactory.batch(2)
    realms = RuleRealmNamespaceFactory.batch(2)
    server_scanners = ScannerNamespaceFactory.batch(2)
    cache = make_namespace_cache(scanners, realms, server_scanners)

    for scanner in scanners:
        assert cache[scanner.namespace] == scanner

    for realm in realms:
        assert cache[realm.namespace] == realm

    for scanner in server_scanners:
        assert cache[scanner.namespace] == scanner


def test_rollup() -> None:
    """Test that rules & default get loaded correctly from imports."""
    rules_1 = {
        "r1": RuleSchemaFactory.build(name="r1"),
        "r2": RuleSchemaFactory.build(name="r2"),
    }
    rules_2 = {
        "r3": RuleSchemaFactory.build(name="r3"),
        "r4": RuleSchemaFactory.build(name="r4"),
    }

    default = {"default": RuleSchemaFactory.build(name="default")}

    n1 = ScannerNamespaceFactory.build(namespace="r1", rules=rules_1)
    n2 = RuleRealmNamespaceFactory.build(
        namespace="r2", rules=rules_2, default=default, imports=["r1"], updated=True
    )
    n3 = ScannerNamespaceFactory.build(namespace="r3", imports=["r1", "r2"])

    cache = make_namespace_cache([n1, n3], [n2], [])

    n1_res = rollup(n1, cache)
    assert n1_res.rules == rules_1
    assert n1_res.default is None
    assert not n1_res.updated

    n2_res = rollup(n2, cache)
    assert n2_res.rules == rules_2 | rules_1
    assert n2_res.default == default
    assert n2_res.updated

    n3_res = rollup(n3, cache)
    assert n3_res.rules == rules_2 | rules_1
    assert n3_res.default == default
    assert n3_res.updated


def test_get_updated_scanners() -> None:
    """Test that only updated scanners are returned.

    All their rules, default & update status should have been merge with their imports.
    """
    rules_1 = {
        "r1": RuleSchemaFactory.build(name="r1"),
        "r2": RuleSchemaFactory.build(name="r2"),
    }
    rules_2 = {
        "r3": RuleSchemaFactory.build(name="r3"),
        "r4": RuleSchemaFactory.build(name="r4"),
    }

    default = {"default": RuleSchemaFactory.build(name="default")}

    scanner_1 = ScannerNamespaceFactory.build(namespace="r1", rules=rules_1)
    rule_realm = RuleRealmNamespaceFactory.build(
        namespace="r2", rules=rules_2, default=default, imports=["r1"], updated=True
    )
    scanner_2 = ScannerNamespaceFactory.build(namespace="r3", imports=["r1", "r2"])

    cache = make_namespace_cache([scanner_1, scanner_2], [rule_realm], [])
    result = get_updated_scanners([scanner_1, scanner_2], cache)

    assert len(result) == 1
    assert result[0].namespace == scanner_2.namespace
    assert result[0].rules == rules_1 | rules_2
    assert result[0].updated
    assert result[0].default == default


@pytest.mark.parametrize("with_default", [True, False])
def test_upload_rules_db(requests_mock: Mocker, with_default: bool) -> None:
    """Test upload_rules_db."""
    url = "https://my_endpoint/"
    test_token = "my-random-key"
    rules = RuleSchemaFactory.batch(2)
    default = None
    if with_default:
        default = RuleSchemaFactory.build(name="default-rule")

    scanner = ScannerNamespaceFactory.build(
        driver="Example Scanner",
        rules={rule.name: rule for rule in rules},
        default={default.name: default} if default else None,
    )

    def has_auth_token(request: Any) -> bool:
        assert request.headers["Authorization"] == f"ApiKey {test_token}"
        return True

    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        additional_matcher=has_auth_token,
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    upload_rules_db(scanner, url, test_token)

    if with_default:
        assert default
        rules.append(default)

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    assert requests_mock.last_request.json() == {
        "query": "mutation setRules($rules: RuleInputSchemas!) {\n  setRules(namespacedRules: $rules) {\n    __typename\n    ... on RuleSuccessSchema {\n      successMessage\n    }\n    ... on RuleErrorSchema {\n      errorMessage\n    }\n  }\n}",  # noqa: E501
        "variables": {
            "rules": {
                "namespace": scanner.namespace,
                "defaultRule": default.name if default else None,
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
                    }
                    for rule in rules
                ],
            }
        },
    }


def test_upload_rules_db_permission_denied(
    capfd: pytest.CaptureFixture[str], requests_mock: Mocker
) -> None:
    """Test upload_rules_db."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": None,
            "errors": [
                {
                    "message": "Permission denied",
                    "locations": [{"line": 2, "column": 5}],
                    "path": ["setRules"],
                }
            ],
        },
    )
    scanner = ScannerNamespaceFactory.build()
    with pytest.raises(SystemExit):
        upload_rules_db(scanner, "https://my_endpoint/", "my-token")
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            f'Uploading rules "{scanner.namespace}" "{scanner.driver}"...',
            "ERROR: Failed to upload rules: {'message': 'Permission denied', 'locations': [{'line': 2, 'column': 5}], 'path': ['setRules']}.",  # noqa: E501
            "",
        ]
    )


def test_upload_rules_db_error_response(
    capfd: pytest.CaptureFixture[str], requests_mock: Mocker
) -> None:
    """Test upload_rules_db."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {
                "setRules": {
                    "__typename": "RuleErrorSchema",
                    "errorMessage": "Error message",
                }
            },
        },
    )
    scanner = ScannerNamespaceFactory.build()

    with pytest.raises(SystemExit):
        upload_rules_db(scanner, url, "my-token")
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            f'Uploading rules "{scanner.namespace}" "{scanner.driver}"...',
            "ERROR: Unable to upload rules-db: Error message",
            "",
        ]
    )


def test_find_updated_namespaces(registry_path: Path, scanners_path: Path) -> None:
    """Should return the list of updated modules since the last commit.

    Any modules updated prior should not be included.
    """
    _init_repo(registry_path)
    ignored_module = scanners_path / "ignore"
    ignored_module.mkdir(parents=True)
    (ignored_module / "module.yaml").touch()
    (ignored_module / "rules.yaml").touch()
    _commit_all_changes(registry_path)

    modules = [scanners_path / "domain/a", scanners_path / "domain/deep/b"]
    for module in modules:
        module.mkdir(parents=True)
        (module / "module.yaml").touch()
        (module / "rules.yaml").touch()

    _commit_all_changes(registry_path)
    assert find_updated_namespaces(registry_path, scanners_path) == {
        "domain/a",
        "domain/deep/b",
    }


def test_find_updated_namespaces_only_rules(
    registry_path: Path, scanners_path: Path
) -> None:
    """Should return the updated module even if only rules.yaml was updated."""
    _init_repo(registry_path)
    module = scanners_path / "ns/test"
    module.mkdir(parents=True)
    (module / "module.yaml").touch()
    rules = module / "rules.yaml"
    rules.touch()
    _commit_all_changes(registry_path)

    rules.write_text("some changes")
    _commit_all_changes(registry_path)

    assert find_updated_namespaces(registry_path, scanners_path) == {"ns/test"}


def test_find_updated_namespaces_no_rules(
    registry_path: Path, scanners_path: Path
) -> None:
    """Should ignore module without rules db."""
    _init_repo(registry_path)
    module = scanners_path / "ns/test"
    module.mkdir(parents=True)
    (module / "module.yaml").touch()
    _commit_all_changes(registry_path)

    assert find_updated_namespaces(registry_path, scanners_path) == set()
