"""Test."""
import re
from pathlib import PosixPath
from uuid import uuid4

import pytest
import yaml
from _pytest.monkeypatch import MonkeyPatch
from requests_mock import Mocker

from boostsec.registry_validator.validate_rules_db import (
    find_rules_db_yaml,
    load_yaml_file,
    main,
    validate_all_in_category,
    validate_description_length,
    validate_ref_url,
    validate_rule_name,
    validate_rules,
    validate_rules_db,
)

_INVALID_YAML_FILE = """
invalid yaml:a{] : -
"""

VALID_RULES_DB_STRING = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
  my-rule-2:
    categories:
      - ALL
      - category-2
    description: Lorem Ipsum
    group: Test group 2
    name: my-rule-2
    pretty_name: My rule 2
    ref: "http://my.link.com"
"""

VALID_RULES_DB_STRING_WITH_PLACEHOLDER = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "{BOOSTSEC_DOC_BASE_URL}/a/b/c"
  my-rule-2:
    categories:
      - ALL
      - category-2
    description: Lorem Ipsum
    group: Test group 2
    name: my-rule-2
    pretty_name: My rule 2
    ref: "{BOOSTSEC_DOC_BASE_URL}/d/e/f"
"""

_INVALID_RULES_DB_STRING_MISSING_CATEGORIES = """
rules:
  my-rule-1:
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_DESCRIPTION = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_DRIVER = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_GROUP = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_NAME = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    pretty_name: My rule 1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_PRETTY_NAME = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_REF = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
"""

_INVALID_RULES_DB_STRING_EXTRA_PROPERTY = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
    extra_property: "extra"

"""


def _create_rules_db_yaml(tmp_path: PosixPath, rules_db_string: str) -> None:
    """Create a module.yaml file."""
    modules_path = tmp_path / uuid4().hex
    modules_path.mkdir()
    module_yaml = modules_path / "rules.yaml"
    module_yaml.write_text(rules_db_string)


def test_find_rules_db_yaml(tmp_path: PosixPath) -> None:
    """Test find_rules_db_yaml."""
    _create_rules_db_yaml(tmp_path, VALID_RULES_DB_STRING)
    assert len(find_rules_db_yaml(str(tmp_path))) == 1


def test_load_yaml_file(tmp_path: PosixPath) -> None:
    """Test load_yaml_file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(VALID_RULES_DB_STRING)
    assert load_yaml_file(str(test_yaml)) == yaml.safe_load(VALID_RULES_DB_STRING)


def test_load_empty_yaml_file(tmp_path: PosixPath) -> None:
    """Test load_yaml_file with empty file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text("")
    assert load_yaml_file(str(test_yaml)) == {}


def test_load_yaml_file_with_invalid_yaml(
    tmp_path: PosixPath, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test load_yaml_file with invalid yaml."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(_INVALID_YAML_FILE)
    with pytest.raises(SystemExit):
        load_yaml_file(str(test_yaml))
    out, _ = capfd.readouterr()
    assert out == "ERROR: Unable to parse Rules DB file\n"


def test_load_yaml_without_file(capfd: pytest.CaptureFixture[str]) -> None:
    """Test load_yaml_file without file."""
    with pytest.raises(SystemExit):
        load_yaml_file("/temp/does_not_exist.yaml")
    out, _ = capfd.readouterr()
    assert out == "ERROR: Rules DB not found: /temp/does_not_exist.yaml\n"


def test_validate_ref_url_with_invalid_url(capfd: pytest.CaptureFixture[str]) -> None:
    """Test validate_ref_url with invalid url."""
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "invalid_url"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Url missing protocol: "invalid_url" from rule "test"\n'


def test_validate_ref_url_with_valid_url_with_https(requests_mock: Mocker) -> None:
    """Test validate_ref_url with valid url."""
    requests_mock.get("https://example.com", status_code=200)
    validate_ref_url({"name": "test", "ref": "https://example.com"})


def test_validate_ref_url_with_valid_url_with_http(requests_mock: Mocker) -> None:
    """Test validate_ref_url with valid url."""
    requests_mock.get("http://example.com", status_code=200)
    validate_ref_url({"name": "test", "ref": "http://example.com"})


def test_validate_ref_url_with_valid_url_with_placeholder(
    requests_mock: Mocker, monkeypatch: MonkeyPatch
) -> None:
    """Test validate_ref_url with valid url."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    requests_mock.get("http://test.com/a/b/c", status_code=200)
    validate_ref_url({"name": "test", "ref": f"{{{env_var_name}}}/a/b/c"})
    assert requests_mock.call_count == 1


def test_validate_ref_url_with_invalid_url_exception(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test validate_ref_url with invalid url."""
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "https://nonexistingwebsite"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Invalid url: "https://nonexistingwebsite" from rule "test"\n'


def test_validate_ref_url_return_404(
    requests_mock: Mocker, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_ref_url with invalid url."""
    requests_mock.get("https://example.com", status_code=404)
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "https://example.com"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Invalid url: "https://example.com" from rule "test"\n'


def test_validate_rules_db_with_valid_rules_db() -> None:
    """Test validate_rules_db with valid rules db."""
    validate_rules_db(yaml.safe_load(VALID_RULES_DB_STRING))


@pytest.mark.parametrize(
    ("rule_str", "expected"),
    [
        (
            _INVALID_RULES_DB_STRING_MISSING_CATEGORIES,
            "ERROR: Rules db is invalid: \"'categories' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_DESCRIPTION,
            "ERROR: Rules db is invalid: \"'description' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_GROUP,
            "ERROR: Rules db is invalid: \"'group' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_NAME,
            "ERROR: Rules db is invalid: \"'name' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_PRETTY_NAME,
            "ERROR: Rules db is invalid: \"'pretty_name' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_REF,
            "ERROR: Rules db is invalid: \"'ref' is a required property\"\n",
        ),
        (
            _INVALID_RULES_DB_STRING_EXTRA_PROPERTY,
            'ERROR: Rules db is invalid: "Additional properties are not allowed '
            "('extra_property' was unexpected)\"\n",
        ),
    ],
)
def test_validate_rules_db_with_invalid_rules_db(
    rule_str: str, expected: str, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test validate_rules_db with invalid rules db."""
    with pytest.raises(SystemExit):
        validate_rules_db(yaml.safe_load(rule_str))
    out, _ = capfd.readouterr()
    assert out == expected


def test_validate_rule_name_with_valid_name() -> None:
    """Test validate_rule_name with valid name."""
    validate_rule_name("test", {"name": "test"})


def test_validate_rule_name_with_invalid_name(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test validate_rule_name with invalid name."""
    with pytest.raises(SystemExit):
        validate_rule_name("test", {"name": "invalid"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule name "test" does not match "invalid"\n'


def test_validate_all_in_category_with_valid_category() -> None:
    """Test validate_all_in_category with valid category."""
    validate_all_in_category({"name": "test", "categories": ["ALL"]})


def test_validate_all_in_category_with_invalid_category(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test validate_all_in_category with invalid category."""
    with pytest.raises(SystemExit):
        validate_all_in_category({"name": "test", "categories": ["invalid"]})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule "test" is missing category "ALL"\n'


def test_validate_description_length_with_valid_description() -> None:
    """Test validate_description_length with valid description."""
    validate_description_length({"name": "test", "description": "Lorem Ipsum " * 42})


def test_validate_description_length_with_invalid_description(
    capfd: pytest.CaptureFixture[str],
) -> None:
    """Test validate_description_length with invalid description."""
    with pytest.raises(SystemExit):
        validate_description_length(
            {"name": "test", "description": "Lorem Ipsum " * 43}
        )
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule "test" has a description longer than 512 characters\n'


def test_validate_rules_with_valid_rules(
    capfd: pytest.CaptureFixture[str], requests_mock: Mocker
) -> None:
    """Test validate_rules with valid rules."""
    requests_mock.get("http://my.link.com", status_code=200)
    validate_rules(yaml.safe_load(VALID_RULES_DB_STRING))
    out, _ = capfd.readouterr()
    assert out == ""


def test_main_with_valid_rules(
    capfd: pytest.CaptureFixture[str], requests_mock: Mocker, tmp_path: PosixPath
) -> None:
    """Test main with valid rules."""
    requests_mock.get("http://my.link.com", status_code=200)
    rules_db_path = tmp_path / "rules.yaml"
    rules_db_path.write_text(VALID_RULES_DB_STRING)
    main(str(tmp_path))
    out, _ = capfd.readouterr()
    assert re.match(
        r"\n".join(
            [
                "^Validating .*/test_main_with_valid_rules0/rules.yaml",
                "$",
            ]
        ),
        out,
    )


def test_main_with_empty_rules_db(
    capfd: pytest.CaptureFixture[str], tmp_path: PosixPath
) -> None:
    """Test main with empty rules db."""
    rules_db_path = tmp_path / "rules.yaml"
    rules_db_path.write_text("")
    with pytest.raises(SystemExit):
        main(str(tmp_path))
    out, _ = capfd.readouterr()
    assert re.match(
        r"\n".join(
            [
                "^Validating .*/test_main_with_empty_rules_db0/rules.yaml",
                "ERROR: Rules DB is empty",
                "$",
            ]
        ),
        out,
    )


def test_main_with_error(
    capfd: pytest.CaptureFixture[str], tmp_path: PosixPath
) -> None:
    """Test main with empty rules db."""
    rules_db_path = tmp_path / "rules.yaml"
    rules_db_path.write_text(_INVALID_RULES_DB_STRING_MISSING_CATEGORIES)
    with pytest.raises(SystemExit):
        main(str(tmp_path))
    out, _ = capfd.readouterr()
    assert re.match(
        r"\n".join(
            [
                "^Validating .*/test_main_with_error0/rules.yaml",
                "ERROR: Rules db is invalid: \"'categories' is a required property\"",
                "$",
            ]
        ),
        out,
    )


def test_main_with_without_rules_db(
    capfd: pytest.CaptureFixture[str], tmp_path: PosixPath
) -> None:
    """Test main with empty rules db."""
    main(str(tmp_path))
    out, _ = capfd.readouterr()
    assert out == "No Rules DB found\n"
