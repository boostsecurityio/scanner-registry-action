from pathlib import PosixPath

import pytest
import yaml
from boostsec.scanner.validate_rules_db import (
    load_yaml_file,
    main,
    validate_all_in_category,
    validate_description_length,
    validate_ref_url,
    validate_rule_name,
    validate_rules,
    validate_rules_db,
)
from pytest import CaptureFixture
from requests_mock import Mocker

_INVALID_YAML_FILE = """
invalid yaml:a{] : -
"""

_VALID_RULES_DB_STRING = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    driver: Test
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
  my-rule-2:
    categories:
      - ALL
      - category-2
    description: Lorem Ipsum
    driver: Test
    group: Test group 2
    name: my-rule-2
    pretty_name: My rule 2
    ref: "http://my.link.com"
"""

_INVALID_RULES_DB_STRING_MISSING_CATEGORIES = """
rules:
  my-rule-1:
    description: Lorem Ipsum
    driver: Test
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
    driver: Test
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
    driver: Test
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
    driver: Test
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
    driver: Test
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
    driver: Test
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
    driver: Test
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
    ref: "http://my.link.com"
    extra_property: "extra"

"""


def test_load_yaml_file(tmp_path: PosixPath) -> None:
    """Test load_yaml_file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(_VALID_RULES_DB_STRING)
    assert load_yaml_file(str(test_yaml)) == yaml.safe_load(_VALID_RULES_DB_STRING)


def test_load_empty_yaml_file(tmp_path: PosixPath) -> None:
    """Test load_yaml_file with empty file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text("")
    assert load_yaml_file(str(test_yaml)) == {}


def test_load_yaml_file_with_invalid_yaml(
    tmp_path: PosixPath, capfd: CaptureFixture[str]
) -> None:
    """Test load_yaml_file with invalid yaml."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(_INVALID_YAML_FILE)
    with pytest.raises(SystemExit):
        load_yaml_file(str(test_yaml))
    out, _ = capfd.readouterr()
    assert out == "ERROR: Unable to parse Rules DB file\n"


def test_load_yaml_without_file(capfd: CaptureFixture[str]) -> None:
    """Test load_yaml_file without file."""
    with pytest.raises(SystemExit):
        load_yaml_file("/tmp/does_not_exist.yaml")
    out, _ = capfd.readouterr()
    assert out == "ERROR: Rules DB not found: /tmp/does_not_exist.yaml\n"


def test_validate_ref_url_with_invalid_url(capfd: CaptureFixture[str]) -> None:
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


def test_validate_ref_url_with_invalid_url_exception(
    capfd: CaptureFixture[str],
) -> None:
    """Test validate_ref_url with invalid url."""
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "https://nonexistingwebsite"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Invalid url: "https://nonexistingwebsite" from rule "test"\n'


def test_validate_ref_url_return_404(
    requests_mock: Mocker, capfd: CaptureFixture[str]
) -> None:
    """Test validate_ref_url with invalid url."""
    requests_mock.get("https://example.com", status_code=404)
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "https://example.com"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Invalid url: "https://example.com" from rule "test"\n'


def test_validate_rules_db_with_valid_rules_db() -> None:
    """Test validate_rules_db with valid rules db."""
    validate_rules_db(yaml.safe_load(_VALID_RULES_DB_STRING))


@pytest.mark.parametrize(
    "rule_str, expected",
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
            _INVALID_RULES_DB_STRING_MISSING_DRIVER,
            "ERROR: Rules db is invalid: \"'driver' is a required property\"\n",
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
    rule_str: str, expected: str, capfd: CaptureFixture[str]
) -> None:
    """Test validate_rules_db with invalid rules db."""
    with pytest.raises(SystemExit):
        validate_rules_db(yaml.safe_load(rule_str))
    out, _ = capfd.readouterr()
    assert out == expected


def test_validate_rule_name_with_valid_name() -> None:
    """Test validate_rule_name with valid name."""
    validate_rule_name("test", {"name": "test"})


def test_validate_rule_name_with_invalid_name(capfd: CaptureFixture[str]) -> None:
    """Test validate_rule_name with invalid name."""
    with pytest.raises(SystemExit):
        validate_rule_name("test", {"name": "invalid"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule name "test" does not match "invalid"\n'


def test_validate_all_in_category_with_valid_category() -> None:
    """Test validate_all_in_category with valid category."""
    validate_all_in_category({"name": "test", "categories": ["ALL"]})


def test_validate_all_in_category_with_invalid_category(
    capfd: CaptureFixture[str],
) -> None:
    """Test validate_all_in_category with invalid category."""
    with pytest.raises(SystemExit):
        validate_all_in_category({"name": "test", "categories": ["invalid"]})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule "test" is missing category "ALL"\n'


def test_validate_description_length_with_valid_description() -> None:
    """Test validate_description_length with valid description."""
    validate_description_length({"name": "test", "description": "Lorem Ipsum " * 21})


def test_validate_description_length_with_invalid_description(
    capfd: CaptureFixture[str],
) -> None:
    """Test validate_description_length with invalid description."""
    with pytest.raises(SystemExit):
        validate_description_length(
            {"name": "test", "description": "Lorem Ipsum " * 22}
        )
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Rule "test" has a description longer than 255 characters\n'


def test_validate_rules_with_valid_rules(
    capfd: CaptureFixture[str], requests_mock: Mocker
) -> None:
    """Test validate_rules with valid rules."""
    requests_mock.get("http://my.link.com", status_code=200)
    validate_rules(yaml.safe_load(_VALID_RULES_DB_STRING))
    out, _ = capfd.readouterr()
    assert out == "Validating rules...\nRules are valid!\n"


def test_main_with_valid_rules(
    capfd: CaptureFixture[str], requests_mock: Mocker, tmp_path: PosixPath
) -> None:
    """Test main with valid rules."""
    requests_mock.get("http://my.link.com", status_code=200)
    rules_db_path = tmp_path / "rules_db.yaml"
    rules_db_path.write_text(_VALID_RULES_DB_STRING)
    main(str(rules_db_path))
    out, _ = capfd.readouterr()
    assert out == "Validating rules...\nRules are valid!\n"


def test_main_with_empty_rules_db(
    capfd: CaptureFixture[str], tmp_path: PosixPath
) -> None:
    """Test main with empty rules db."""
    rules_db_path = tmp_path / "rules_db.yaml"
    rules_db_path.write_text("")
    with pytest.raises(SystemExit):
        main(str(rules_db_path))
    out, _ = capfd.readouterr()
    assert out == "ERROR: Rules DB is empty\n"
