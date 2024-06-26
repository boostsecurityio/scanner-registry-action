"""Test."""

from pathlib import Path

import pytest
import yaml

from boostsec.registry_validator.config import RegistryConfig
from boostsec.registry_validator.validate_rules_db import (
    find_rules_db_yaml,
    load_yaml_file,
    validate_imports,
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
    server_side = _create_module_rules(
        registry_config.server_side_scanners_path, "namespace3", VALID_RULES_DB_STRING
    )

    result = find_rules_db_yaml(registry_config)
    assert result == [
        module / "rules.yaml",
        realm / "rules.yaml",
        server_side / "rules.yaml",
    ]


def test_load_yaml_file(tmp_path: Path) -> None:
    """Test load_yaml_file."""
    test_yaml = tmp_path / "test.yaml"
    test_yaml.write_text(VALID_RULES_DB_STRING)
    assert load_yaml_file(test_yaml) == yaml.safe_load(VALID_RULES_DB_STRING)


def test_load_empty_yaml_file(tmp_path: Path) -> None:
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
            "rules.my-rule-1.categories is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_DESCRIPTION,
            "rules.my-rule-1.description is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_GROUP,
            "rules.my-rule-1.group is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_NAME,
            "rules.my-rule-1.name is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_PRETTY_NAME,
            "rules.my-rule-1.pretty_name is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_MISSING_REF,
            "rules.my-rule-1.ref is a required property\n",
        ),
        (
            _INVALID_RULES_DB_STRING_EXTRA_PROPERTY,
            "Additional properties are not allowed "
            "(rules.my-rule-1.extra_property was unexpected)\n",
        ),
        (
            _INVALID_DEFAULT_RULES_DB_STRING,
            "default.my-rule-2.ref is a required property\n",
        ),
        (
            _INVALID_DEFAULT_MULTIPLE_RULES_DB_STRING,
            "default: Only one default rule is allowed\n",
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
    assert out == "ERROR: Rules db is invalid: " + expected


@pytest.mark.parametrize("source", ["scanners", "realm", "server-side"])
def test_validate_imports(
    source: str, capfd: pytest.CaptureFixture[str], registry_config: RegistryConfig
) -> None:
    """Should import the namespace from all 3 sources in the config."""
    module = "namespace/module-a"
    if source == "scanners":
        _create_module_rules(
            registry_config.scanners_path, module, VALID_RULES_DB_STRING
        )
    elif source == "realm":
        _create_module_rules(
            registry_config.rules_realm_path, module, VALID_RULES_DB_STRING
        )
    elif source == "server-side":
        _create_module_rules(
            registry_config.server_side_scanners_path, module, VALID_RULES_DB_STRING
        )

    validate_imports([module], registry_config)
    out, _ = capfd.readouterr()
    assert out == ""


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
