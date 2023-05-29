"""Test."""
from pathlib import Path, PosixPath

import pytest
import yaml
from _pytest.monkeypatch import MonkeyPatch

from boostsec.registry_validator.shared import RegistryConfig
from boostsec.registry_validator.validate_rules_db import (
    RulesDbPath,
    find_rules_db_yaml,
    load_yaml_file,
    main,
    validate_all_in_category,
    validate_description_length,
    validate_imports,
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


VALID_RULES_DB_STRING_WITH_IMPORTS = """
import:
  - namespace/module-a

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

VALID_RULES_DB_STRING_WITH_DEFAULT = """
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
default:
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

VALID_RULES_DB_STRING_WITH_ONLY_IMPORT = """
import:
  - namespace/module-a
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

_INVALID_DEFAULT_RULES_DB_STRING = """
rules:
  my-rule-1:
    categories:
      - ALL
      - category-1
    description: Lorem Ipsum
    group: Test group 1
    name: my-rule-1
    pretty_name: My rule 1
default:
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

_INVALID_DEFAULT_MULTIPLE_RULES_DB_STRING = """
default:
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


def _create_module_rules(
    registry_path: Path, namespace: str, rules_db_string: str
) -> Path:
    """Create a module with rules db under provided namespace in registry_path."""
    module = registry_path / namespace
    module.mkdir(parents=True)
    (module / "rules.yaml").write_text(rules_db_string)
    return module


def test_find_rules_db_yaml(registry_config: RegistryConfig) -> None:
    """Test find_rules_db_yaml."""
    module = _create_module_rules(
        registry_config.scanners_path, "namespace1", VALID_RULES_DB_STRING
    )
    realm = _create_module_rules(
        registry_config.rules_realm_path, "namespace2", VALID_RULES_DB_STRING
    )

    result = find_rules_db_yaml(registry_config)
    assert result == [
        RulesDbPath(root=registry_config.scanners_path, path=module / "rules.yaml"),
        RulesDbPath(root=registry_config.rules_realm_path, path=realm / "rules.yaml"),
    ]


def test_load_yaml_file(tmp_path: Path) -> None:
    """Test load_yaml_file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(VALID_RULES_DB_STRING)
    assert load_yaml_file(test_yaml) == yaml.safe_load(VALID_RULES_DB_STRING)


def test_load_empty_yaml_file(tmp_path: PosixPath) -> None:
    """Test load_yaml_file with empty file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text("")
    assert load_yaml_file(test_yaml) == {}


def test_load_yaml_file_with_invalid_yaml(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Test load_yaml_file with invalid yaml."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(_INVALID_YAML_FILE)
    with pytest.raises(SystemExit):
        load_yaml_file(test_yaml)
    out, _ = capfd.readouterr()
    assert out == "ERROR: Unable to parse Rules DB file\n"


def test_load_yaml_without_file(capfd: pytest.CaptureFixture[str]) -> None:
    """Test load_yaml_file without file."""
    with pytest.raises(SystemExit):
        load_yaml_file(Path("/temp/does_not_exist.yaml"))
    out, _ = capfd.readouterr()
    assert out == "ERROR: Rules DB not found: /temp/does_not_exist.yaml\n"


def test_validate_ref_url_with_invalid_url(capfd: pytest.CaptureFixture[str]) -> None:
    """Test validate_ref_url with invalid url."""
    with pytest.raises(SystemExit):
        validate_ref_url({"name": "test", "ref": "invalid_url"})
    out, _ = capfd.readouterr()
    assert out == 'ERROR: Url missing protocol: "invalid_url" from rule "test"\n'


def test_validate_ref_url_with_valid_url_with_https() -> None:
    """Test validate_ref_url with valid url."""
    validate_ref_url({"name": "test", "ref": "https://example.com"})


def test_validate_ref_url_with_valid_url_with_http() -> None:
    """Test validate_ref_url with valid url."""
    validate_ref_url({"name": "test", "ref": "http://example.com"})


def test_validate_ref_url_with_valid_url_with_placeholder(
    monkeypatch: MonkeyPatch,
) -> None:
    """Test validate_ref_url with valid url."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    validate_ref_url({"name": "test", "ref": f"{{{env_var_name}}}/a/b/c"})


@pytest.mark.parametrize(
    "rules_db_yaml",
    [
        VALID_RULES_DB_STRING,
        VALID_RULES_DB_STRING_WITH_IMPORTS,
        VALID_RULES_DB_STRING_WITH_ONLY_IMPORT,
        VALID_RULES_DB_STRING_WITH_DEFAULT,
    ],
)
def test_validate_rules_db_with_valid_rules_db(rules_db_yaml: str) -> None:
    """Test validate_rules_db with valid rules db."""
    validate_rules_db(yaml.safe_load(rules_db_yaml))


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
        (
            _INVALID_DEFAULT_RULES_DB_STRING,
            "ERROR: Rules db is invalid: \"'ref' is a required property\"\n",
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


def test_validate_imports_from_realm() -> None:
    """Should be able to import rules from realm and vise-versa."""


@pytest.mark.parametrize("from_realm", [True, False])
def test_validate_imports_circular_import(
    capfd: pytest.CaptureFixture[str],
    registry_config: RegistryConfig,
    from_realm: bool,
) -> None:
    """Should notify & exit if an import cycle is found."""
    _create_module_rules(
        registry_config.scanners_path,
        "namespace1/module-a",
        """
        import:
          - namespace2/module-b
        """,
    )

    _create_module_rules(
        registry_config.rules_realm_path
        if from_realm
        else registry_config.scanners_path,
        "namespace2/module-b",
        """
        import:
          - namespace1/module-a
        """,
    )

    with pytest.raises(SystemExit):
        validate_imports(["namespace2/module-b"], registry_config)
    out, _ = capfd.readouterr()
    assert out == "ERROR: Import cycle detected\n"


@pytest.mark.parametrize("from_realm", [True, False])
def test_validate_imports_missing_import(
    capfd: pytest.CaptureFixture[str],
    registry_config: RegistryConfig,
    from_realm: bool,
) -> None:
    """Should notify & exit if an import doesn't exists."""
    _create_module_rules(
        registry_config.rules_realm_path
        if from_realm
        else registry_config.scanners_path,
        "namespace/module-a",
        """
        import:
          - namespace/module-b
        """,
    )

    with pytest.raises(SystemExit):
        validate_imports(["namespace/module-a"], registry_config)
    out, _ = capfd.readouterr()
    assert "ERROR: Imported namespace namespace/module-b not found\n" in out


@pytest.mark.parametrize(
    "rules_db_yaml",
    [
        VALID_RULES_DB_STRING,
        VALID_RULES_DB_STRING_WITH_IMPORTS,
        VALID_RULES_DB_STRING_WITH_ONLY_IMPORT,
        VALID_RULES_DB_STRING_WITH_DEFAULT,
    ],
)
def test_validate_rules_with_valid_rules(
    rules_db_yaml: str,
    capfd: pytest.CaptureFixture[str],
    registry_config: RegistryConfig,
) -> None:
    """Test validate_rules with valid rules."""
    _create_module_rules(
        registry_config.scanners_path,
        "namespace/module-a",
        """
        import:
          - namespace/module-b
        """,
    )
    _create_module_rules(
        registry_config.scanners_path,
        "namespace/module-b",
        VALID_RULES_DB_STRING,
    )
    validate_rules(yaml.safe_load(rules_db_yaml), registry_config)
    out, _ = capfd.readouterr()
    assert out == ""


def test_main_with_valid_rules(
    capfd: pytest.CaptureFixture[str],
    scanners_path: Path,
    rules_realm_path: Path,
) -> None:
    """Test main with valid rules."""
    _create_module_rules(scanners_path, "namespace/module-name", VALID_RULES_DB_STRING)
    _create_module_rules(
        rules_realm_path, "namespace/realm-name", VALID_RULES_DB_STRING
    )
    main(str(scanners_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert (
        "Validating namespace/module-name/rules.yaml\n"
        "Validating namespace/realm-name/rules.yaml\n" == out
    )


def test_main_with_valid_imports(
    capfd: pytest.CaptureFixture[str],
    scanners_path: Path,
    rules_realm_path: Path,
) -> None:
    """Test main with valid imported rules."""
    _create_module_rules(
        scanners_path,
        "testing-ns/testing-module",
        VALID_RULES_DB_STRING_WITH_ONLY_IMPORT,
    )
    _create_module_rules(scanners_path, "namespace/module-a", VALID_RULES_DB_STRING)
    main(str(scanners_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert "Validating namespace/module-a/rules.yaml\n" in out
    assert "Validating testing-ns/testing-module/rules.yaml\n" in out


def test_main_with_valid_imports_from_realm(
    capfd: pytest.CaptureFixture[str],
    scanners_path: Path,
    rules_realm_path: Path,
) -> None:
    """Test main with valid imported rules."""
    _create_module_rules(
        scanners_path,
        "testing-ns/testing-module",
        VALID_RULES_DB_STRING_WITH_ONLY_IMPORT,
    )
    _create_module_rules(rules_realm_path, "namespace/module-a", VALID_RULES_DB_STRING)
    main(str(scanners_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert "Validating namespace/module-a/rules.yaml\n" in out
    assert "Validating testing-ns/testing-module/rules.yaml\n" in out


@pytest.mark.parametrize("from_realm", [True, False])
def test_main_with_empty_rules_db(
    capfd: pytest.CaptureFixture[str],
    scanners_path: Path,
    rules_realm_path: Path,
    from_realm: bool,
) -> None:
    """Test main with empty rules db."""
    _create_module_rules(
        rules_realm_path if from_realm else scanners_path, "ns/empty", ""
    )
    with pytest.raises(SystemExit):
        main(str(scanners_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert "Validating ns/empty/rules.yaml\nERROR: Rules DB is empty\n" == out


@pytest.mark.parametrize(
    ("rules_db_yaml", "expected"),
    [
        (
            _INVALID_RULES_DB_STRING_MISSING_CATEGORIES,
            "ERROR: Rules db is invalid: \"'categories' is a required property\"",
        ),
        (
            _INVALID_DEFAULT_MULTIPLE_RULES_DB_STRING,
            "ERROR: Only one default rule is allowed",
        ),
    ],
)
@pytest.mark.parametrize("from_realm", [True, False])
def test_main_with_error(
    capfd: pytest.CaptureFixture[str],
    rules_db_yaml: str,
    scanners_path: Path,
    rules_realm_path: Path,
    expected: str,
    from_realm: bool,
) -> None:
    """Test main with empty rules db."""
    _create_module_rules(
        rules_realm_path if from_realm else scanners_path, "ns/invalid", rules_db_yaml
    )
    with pytest.raises(SystemExit):
        main(str(scanners_path), str(rules_realm_path))
    out, _ = capfd.readouterr()
    assert f"Validating ns/invalid/rules.yaml\n{expected}\n" == out


def test_main_with_without_rules_db(
    capfd: pytest.CaptureFixture[str], tmp_path: PosixPath
) -> None:
    """Test main with empty rules db."""
    main(str(tmp_path), str(tmp_path))
    out, _ = capfd.readouterr()
    assert out == "No Rules DB found\n"
