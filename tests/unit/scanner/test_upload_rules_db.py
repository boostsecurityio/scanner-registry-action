"""Test."""
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
import yaml
from _pytest.monkeypatch import MonkeyPatch

from boostsec.registry_validator.upload_rules_db import (
    main,
    render_doc_url,
    upload_rules_db,
)
from tests.unit.scanner.test_validate_rules_db import (
    VALID_RULES_DB_STRING,
    VALID_RULES_DB_STRING_WITH_PLACEHOLDER,
)


def _create_module_and_rules(
    tmp_path: Path, rules_db_string: str, namespace: str = "", create_rules: bool = True
) -> Path:
    """Create a module.yaml file."""
    modules_path = tmp_path / uuid4().hex
    modules_path.mkdir()
    modules_path = modules_path / "module_name"
    modules_path.mkdir()
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


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_upload_rules_db(mock_requests: Any, tmp_path: Path) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example"
    module_path = _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    upload_rules_db(module_path.parent, "https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    assert (
        mock_requests.post.call_args[0][0]
        == "https://my_endpoint/rules-management/graphql"
    )
    assert mock_requests.post.call_args[1]["headers"] == {
        "Authorization": "ApiKey my-token",
        "Content-Type": "application/json",
    }
    assert json.loads(mock_requests.post.call_args[1]["data"]) == {
        "query": "\nmutation setRules($rules: RuleInputSchemas!) {\n    setRules(namespacedRules: $rules){\n        __typename\n        ... on RuleSuccessSchema {\n            successMessage\n        }\n        ... on RuleErrorSchema {\n            errorMessage\n        }\n    }\n}",  # noqa: E501
        "variables": {
            "rules": {
                "namespace": "namespace-example",
                "ruleInputs": [
                    {
                        "categories": ["ALL", "category-1"],
                        "description": "Lorem Ipsum",
                        "driver": "Example Scanner",
                        "group": "Test group 1",
                        "name": "my-rule-1",
                        "prettyName": "My rule 1",
                        "ref": "http://my.link.com",
                    },
                    {
                        "categories": ["ALL", "category-2"],
                        "description": "Lorem Ipsum",
                        "driver": "Example Scanner",
                        "group": "Test group 2",
                        "name": "my-rule-2",
                        "prettyName": "My rule 2",
                        "ref": "http://my.link.com",
                    },
                ],
            }
        },
    }


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_upload_rules_db_with_placeholder(
    mock_requests: Any, tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    """Test upload_rules_db."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example"
    module_path = _create_module_and_rules(
        tmp_path, VALID_RULES_DB_STRING_WITH_PLACEHOLDER, namespace
    )

    upload_rules_db(module_path.parent, "https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    assert (
        mock_requests.post.call_args[0][0]
        == "https://my_endpoint/rules-management/graphql"
    )
    assert mock_requests.post.call_args[1]["headers"] == {
        "Authorization": "ApiKey my-token",
        "Content-Type": "application/json",
    }
    assert json.loads(mock_requests.post.call_args[1]["data"]) == {
        "query": "\nmutation setRules($rules: RuleInputSchemas!) {\n    setRules(namespacedRules: $rules){\n        __typename\n        ... on RuleSuccessSchema {\n            successMessage\n        }\n        ... on RuleErrorSchema {\n            errorMessage\n        }\n    }\n}",  # noqa: E501
        "variables": {
            "rules": {
                "namespace": "namespace-example",
                "ruleInputs": [
                    {
                        "categories": ["ALL", "category-1"],
                        "description": "Lorem Ipsum",
                        "driver": "Example Scanner",
                        "group": "Test group 1",
                        "name": "my-rule-1",
                        "prettyName": "My rule 1",
                        "ref": "http://test.com/a/b/c",
                    },
                    {
                        "categories": ["ALL", "category-2"],
                        "description": "Lorem Ipsum",
                        "driver": "Example Scanner",
                        "group": "Test group 2",
                        "name": "my-rule-2",
                        "prettyName": "My rule 2",
                        "ref": "http://test.com/d/e/f",
                    },
                ],
            }
        },
    }


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_upload_rules_db_error_400(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 400
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example"
    module_path = _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    with pytest.raises(SystemExit):
        upload_rules_db(module_path.parent, "https://my_endpoint/", "my-token")
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            'Uploading rules "namespace-example" "Example Scanner"...',
            "ERROR: Unable to upload rules-db: RuleSuccessSchema",
            "",
        ]
    )

    assert mock_requests.post.call_count == 1


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_upload_rules_db_error_response(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleErrorSchema"
    namespace = "namespace-example"
    module_path = _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    with pytest.raises(SystemExit):
        upload_rules_db(module_path.parent, "https://my_endpoint/", "my-token")
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            'Uploading rules "namespace-example" "Example Scanner"...',
            "ERROR: Unable to upload rules-db: RuleErrorSchema",
            "",
        ]
    )

    assert mock_requests.post.call_count == 1


def test_render_doc_url(monkeypatch: MonkeyPatch) -> None:
    """Test render_doc_url."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    rendered_url = render_doc_url(f"{{{env_var_name}}}/a/path")
    assert rendered_url == "http://test.com/a/path"


def test_render_doc_url_error_empty_env_var() -> None:
    """Test render_doc_url."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    with pytest.raises(KeyError):
        render_doc_url(f"{{{env_var_name}}}/a/path")


def test_render_doc_url_no_placeholder() -> None:
    """Test render_doc_url."""
    test_url = "http://test.com/a/path"
    assert render_doc_url(test_url) == test_url


@patch("boostsec.registry_validator.upload_rules_db.subprocess")
@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_success(
    mock_requests: Any,
    mock_subprocess: Any,
    capfd: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example-main"

    module_path = _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)
    mock_subprocess_decode = mock_subprocess.check_output.return_value.decode
    mock_subprocess_decode.return_value.splitlines.return_value = [str(module_path)]

    main("https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    out, _ = capfd.readouterr()
    assert out == 'Uploading rules "namespace-example-main" "Example Scanner"...\n'


@patch("boostsec.registry_validator.upload_rules_db.subprocess")
@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_success_warning(
    mock_requests: Any,
    mock_subprocess: Any,
    capfd: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    module1 = _create_module_and_rules(
        tmp_path, VALID_RULES_DB_STRING, "namespace-example-main"
    )
    module2 = _create_module_and_rules(
        tmp_path, VALID_RULES_DB_STRING, "namespace-example-main2", create_rules=False
    )
    mock_subprocess_decode = mock_subprocess.check_output.return_value.decode
    mock_subprocess_decode.return_value.splitlines.return_value = [
        str(module1),
        str(module2),
    ]

    main("https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    out, _ = capfd.readouterr()
    assert "WARNING: rules.yaml not found in " in out


@patch("boostsec.registry_validator.upload_rules_db.subprocess")
@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_no_modules_to_update(
    mock_requests: Any,
    mock_subprocess: Any,
    capfd: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Test upload_rules_db."""
    mock_subprocess_decode = mock_subprocess.check_output.return_value.decode
    mock_subprocess_decode.return_value.splitlines.return_value = []
    main("https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 0
    out, _ = capfd.readouterr()
    assert out == "No module rules to update.\n"
