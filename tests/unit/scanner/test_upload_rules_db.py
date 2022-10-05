"""Test."""
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
import yaml

from boostsec.registry_validator.common import find_module_yaml
from boostsec.registry_validator.upload_rules_db import main, upload_rules_db
from tests.unit.scanner.test_validate_rules_db import VALID_RULES_DB_STRING


def _create_module_and_rules(
    tmp_path: Path, rules_db_string: str, namespace: str = "", create_rules: bool = True
) -> None:
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


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_upload_rules_db(mock_requests: Any, tmp_path: Path) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example"
    _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    module_path = find_module_yaml(str(tmp_path))[0].parent
    upload_rules_db(module_path, "https://my_endpoint/", "my-token")

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
def test_upload_rules_db_error_400(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 400
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example"
    _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    module_path = find_module_yaml(str(tmp_path))[0].parent
    with pytest.raises(SystemExit):
        upload_rules_db(module_path, "https://my_endpoint/", "my-token")
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
    _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    module_path = find_module_yaml(str(tmp_path))[0].parent
    with pytest.raises(SystemExit):
        upload_rules_db(module_path, "https://my_endpoint/", "my-token")
    out, _ = capfd.readouterr()
    assert out == "\n".join(
        [
            'Uploading rules "namespace-example" "Example Scanner"...',
            "ERROR: Unable to upload rules-db: RuleErrorSchema",
            "",
        ]
    )

    assert mock_requests.post.call_count == 1


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_success(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    namespace = "namespace-example-main"
    _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, namespace)

    main(str(tmp_path), "https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    out, _ = capfd.readouterr()
    assert out == 'Uploading rules "namespace-example-main" "Example Scanner"...\n'


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_success_warning(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    mock_requests.post.return_value.status_code = 200
    mock_requests.post.return_value.text = "RuleSuccessSchema"
    _create_module_and_rules(tmp_path, VALID_RULES_DB_STRING, "namespace-example-main")
    _create_module_and_rules(
        tmp_path, VALID_RULES_DB_STRING, "namespace-example-main2", create_rules=False
    )

    main(str(tmp_path), "https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 1
    out, _ = capfd.readouterr()
    assert "WARNING: rules.yaml not found in " in out


@patch("boostsec.registry_validator.upload_rules_db.requests")
def test_main_error(
    mock_requests: Any, capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Test upload_rules_db."""
    with pytest.raises(SystemExit):
        main(str(tmp_path), "https://my_endpoint/", "my-token")

    assert mock_requests.post.call_count == 0
    out, _ = capfd.readouterr()
    assert out == "ERROR: No modules found.\n"
