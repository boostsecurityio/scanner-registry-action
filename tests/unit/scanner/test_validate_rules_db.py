from pathlib import PosixPath
from urllib import request

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


def test_validate_ref_url_with_valid_url(requests_mock) -> None:
    """Test validate_ref_url with valid url."""
    requests_mock.get("https://example.com", status_code=200)
    validate_ref_url({"name": "test", "ref": "https://example.com"})


def test_validate_ref_url_with_valid_url_with_trailing_slash(requests_mock) -> None:
    """Test validate_ref_url with valid url with trailing slash."""
    requests_mock.get("https://example.com", status_code=200)
    validate_ref_url({"name": "test", "ref": "https://example.com/"})


def test_validate_ref_url_with_invalid_url(requests_mock) -> None:
    """Test validate_ref_url with invalid url."""
    requests_mock.get("https://example.com", status_code=404)
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "https://example.com"})


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
