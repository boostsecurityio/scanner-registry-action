"""Upload rules integrations tests."""

from pathlib import Path
from urllib.parse import urljoin

import pytest
from _pytest.monkeypatch import MonkeyPatch
from requests_mock import Mocker
from typer.testing import CliRunner

from boostsec.registry_validator.upload_rules_db import app
from tests.integration.conftest import CommitChanges, UseSample


def test_main_no_module_to_update(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
) -> None:
    """No rules should get uploaded if nothing changed."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample("scanners/boostsecurityio/simple-scanner/")
    commit_changes()

    # Commit a second time to simulate a past upload
    # Updated rules-realm shouldn't get uploaded
    use_sample("rules-realm/boostsecurityio/mitre-cwe")
    commit_changes()

    result = cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 0
    assert result.exit_code == 0
    assert result.stdout == "No module rules to update.\n"


@pytest.mark.parametrize(
    "sample",
    [
        "scanners/boostsecurityio/simple-scanner",
        "server-side-scanners/boostsecurityio/simple-scanner",
    ],
)
def test_main_simple_scanner(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Should parse and upload boostsecurityio/simple-scanner."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample(sample)
    commit_changes()

    result = cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    request_json = requests_mock.last_request.json()
    assert request_json["variables"] == {
        "rules": {
            "namespace": "boostsecurityio/simple-scanner",
            "defaultRule": None,
            "ruleInputs": [
                {
                    "categories": ["ALL", "category-1"],
                    "description": "Lorem Ipsum",
                    "driver": "Simple Scanner",
                    "group": "Test group 1",
                    "name": "my-rule-1",
                    "prettyName": "My rule 1",
                    "ref": "http://my.link.com",
                    "recommended": True,
                },
                {
                    "categories": ["ALL", "category-2"],
                    "description": "Lorem Ipsum",
                    "driver": "Simple Scanner",
                    "group": "Test group 2",
                    "name": "my-rule-2",
                    "prettyName": "My rule 2",
                    "ref": "http://my.link.com",
                    "recommended": False,
                },

            ],
        }
    }

    assert result.exit_code == 0
    assert (
        result.stdout
        == 'Uploading rules "boostsecurityio/simple-scanner" "Simple Scanner"...\n'
    )


@pytest.mark.parametrize(
    "sample",
    [
        "scanners/boostsecurityio/simple-scanner",
        "server-side-scanners/boostsecurityio/simple-scanner",
    ],
)
def test_main_only_import(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Test importing rules & default."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample(sample)
    use_sample("rules-realm/boostsecurityio/mitre-cwe")
    commit_changes()

    use_sample("scanners/others/only-import")
    commit_changes()

    cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    request_json = requests_mock.last_request.json()
    assert request_json["variables"] == {
        "rules": {
            "namespace": "others/only-import",
            "defaultRule": "CWE-UNKNOWN",
            "ruleInputs": [
                {
                    "categories": ["ALL", "cwe-1004", "owasp-top-10"],
                    "description": "CWE-1004 description",
                    "driver": "Only Import",
                    "group": "top10-security-misconfiguration",
                    "name": "CWE-1004",
                    "prettyName": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
                    "ref": "https://cwe.mitre.org/data/definitions/1004.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "boost-hardened"],
                    "description": "CWE-1007 description",
                    "driver": "Only Import",
                    "group": "top10-insecure-design",
                    "name": "CWE-1007",
                    "prettyName": (
                        "CWE-1007: Insufficient Visual Distinction of "
                        "Homoglyphs Presented to User"
                    ),
                    "ref": "https://cwe.mitre.org/data/definitions/1007.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "category-1"],
                    "description": "Lorem Ipsum",
                    "driver": "Only Import",
                    "group": "Test group 1",
                    "name": "my-rule-1",
                    "prettyName": "My rule 1",
                    "ref": "http://my.link.com",
                    "recommended": True,
                },
                {
                    "categories": ["ALL", "category-2"],
                    "description": "Lorem Ipsum",
                    "driver": "Only Import",
                    "group": "Test group 2",
                    "name": "my-rule-2",
                    "prettyName": "My rule 2",
                    "ref": "http://my.link.com",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "boost-hardened"],
                    "description": "The original rule could not be map to a CWE rule",
                    "driver": "Only Import",
                    "group": "top10-insecure-design",
                    "name": "CWE-UNKNOWN",
                    "prettyName": (
                        "CWE-UNKNOWN - Original rule did not map to a known CWE rule"
                    ),
                    "ref": "https://cwe.mitre.org/",
                    "recommended": False,
                },
            ],
        }
    }


@pytest.mark.parametrize(
    "sample", ["scanners/others/only-import", "server-side-scanners/others/only-import"]
)
def test_main_rule_update_trigger_upload(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Test updating an imported rule-realm should update module using it."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample("scanners/boostsecurityio/simple-scanner/")
    use_sample("server-side-scanners/boostsecurityio/simple-server-scanner/")
    use_sample(sample)
    commit_changes()

    use_sample("rules-realm/boostsecurityio/mitre-cwe")
    commit_changes()

    cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    request_json = requests_mock.last_request.json()
    assert request_json["variables"] == {
        "rules": {
            "namespace": "others/only-import",
            "defaultRule": "CWE-UNKNOWN",
            "ruleInputs": [
                {
                    "categories": ["ALL", "cwe-1004", "owasp-top-10"],
                    "description": "CWE-1004 description",
                    "driver": "Only Import",
                    "group": "top10-security-misconfiguration",
                    "name": "CWE-1004",
                    "prettyName": "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
                    "ref": "https://cwe.mitre.org/data/definitions/1004.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "boost-hardened"],
                    "description": "CWE-1007 description",
                    "driver": "Only Import",
                    "group": "top10-insecure-design",
                    "name": "CWE-1007",
                    "prettyName": (
                        "CWE-1007: Insufficient Visual Distinction of "
                        "Homoglyphs Presented to User"
                    ),
                    "ref": "https://cwe.mitre.org/data/definitions/1007.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "category-1"],
                    "description": "Lorem Ipsum",
                    "driver": "Only Import",
                    "group": "Test group 1",
                    "name": "my-rule-1",
                    "prettyName": "My rule 1",
                    "ref": "http://my.link.com",
                    "recommended": True,
                },
                {
                    "categories": ["ALL", "category-2"],
                    "description": "Lorem Ipsum",
                    "driver": "Only Import",
                    "group": "Test group 2",
                    "name": "my-rule-2",
                    "prettyName": "My rule 2",
                    "ref": "http://my.link.com",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "boost-hardened"],
                    "description": "The original rule could not be map to a CWE rule",
                    "driver": "Only Import",
                    "group": "top10-insecure-design",
                    "name": "CWE-UNKNOWN",
                    "prettyName": (
                        "CWE-UNKNOWN - Original rule did not map to a known CWE rule"
                    ),
                    "ref": "https://cwe.mitre.org/",
                    "recommended": False,
                },
            ],
        }
    }


def test_main_rule_import_overload(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
) -> None:
    """Test rules importing with rules overloading."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample("rules-realm/boostsecurityio/mitre-cwe")
    use_sample("scanners/others/overload")
    commit_changes()

    cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    request_json = requests_mock.last_request.json()
    assert request_json["variables"] == {
        "rules": {
            "namespace": "others/overload",
            "defaultRule": "CWE-OVERLOAD",
            "ruleInputs": [
                {
                    "categories": ["ALL"],
                    "description": "Overload",
                    "driver": "Overload",
                    "group": "top10-security-misconfiguration",
                    "name": "CWE-1004",
                    "prettyName": "CWE-1004: Overload",
                    "ref": "https://cwe.mitre.org/data/definitions/1004.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "boost-hardened"],
                    "description": "CWE-1007 description",
                    "driver": "Overload",
                    "group": "top10-insecure-design",
                    "name": "CWE-1007",
                    "prettyName": (
                        "CWE-1007: Insufficient Visual Distinction "
                        "of Homoglyphs Presented to User"
                    ),
                    "ref": "https://cwe.mitre.org/data/definitions/1007.html",
                    "recommended": False,
                },
                {
                    "categories": ["ALL"],
                    "description": "Overload",
                    "driver": "Overload",
                    "group": "top10-insecure-design",
                    "name": "CWE-OVERLOAD",
                    "prettyName": "CWE-OVERLOAD - Overload",
                    "ref": "https://cwe.mitre.org/",
                    "recommended": False,
                },
            ],
        }
    }


def test_main_with_placeholder(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    monkeypatch: MonkeyPatch,
) -> None:
    """Test rules with env placeholder."""
    doc_url = "https://my_doc_url"
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, doc_url)

    use_sample("scanners/others/with-placeholder")
    commit_changes()

    cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 1
    assert requests_mock.last_request is not None
    request_json = requests_mock.last_request.json()
    assert request_json["variables"] == {
        "rules": {
            "namespace": "others/with-placeholder",
            "defaultRule": None,
            "ruleInputs": [
                {
                    "categories": ["ALL", "category-1"],
                    "description": "Lorem Ipsum",
                    "driver": "With Placeholder",
                    "group": "Test group 1",
                    "name": "my-rule-1",
                    "prettyName": "My rule 1",
                    "ref": f"{doc_url}/a/b/c",
                    "recommended": False,
                },
                {
                    "categories": ["ALL", "category-2"],
                    "description": "Lorem Ipsum",
                    "driver": "With Placeholder",
                    "group": "Test group 2",
                    "name": "my-rule-2",
                    "prettyName": "My rule 2",
                    "ref": f"{doc_url}/d/e/f",
                    "recommended": False,
                },
            ],
        },
    }


@pytest.mark.parametrize(
    "sample",
    ["scanners/others/missing-rules", "server-side-scanners/others/missing-rules"],
)
def test_main_module_missing_rules(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Should warn and exit if a module is missing a rules db."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample(sample)
    commit_changes()

    result = cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 0
    assert result.exit_code == 0
    assert "WARNING: rules.yaml not found in " in result.stdout


@pytest.mark.parametrize(
    "sample",
    [
        "scanners/others/path-and-namespace-mismatch",
        "server-side-scanners/others/path-and-namespace-mismatch",
    ],
)
def test_main_path_and_namespace_mismatch(
    cli_runner: CliRunner,
    registry_path: Path,
    requests_mock: Mocker,
    commit_changes: CommitChanges,
    use_sample: UseSample,
    sample: str,
) -> None:
    """Should warn if a module's path is not the same as its namespace."""
    url = "https://my_endpoint/"
    requests_mock.post(
        urljoin(url, "/rules-management/graphql"),
        json={
            "data": {"setRules": {"__typename": "RuleSuccessSchema"}},
        },
    )

    use_sample(sample)
    commit_changes()

    result = cli_runner.invoke(
        app,
        [
            "--api-endpoint",
            url,
            "--api-token",
            "my-token",
            "--registry-path",
            str(registry_path),
        ],
    )

    assert requests_mock.call_count == 0
    assert result.exit_code == 0
    assert (
        'WARNING: Scanner directory "others/path-and-namespace-mismatch" doesn\'t '
        'match namespace "something-different-than-the-path". Skipping...'
        in result.stdout
    )
