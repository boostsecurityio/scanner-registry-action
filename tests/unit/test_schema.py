"""Test for scanners & rules schemas."""

from typing import Optional

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from boostsec.registry_validator.testing.factories import (
    ModuleSchemaFactory,
    RuleSchemaFactory,
    RulesDbSchemaFactory,
)


def test_validate_server_side_module() -> None:
    """Server side scanner have optional steps."""
    ModuleSchemaFactory.build(steps=None, server_side=True)


@pytest.mark.parametrize("server_side", [None, False])
def test_validate_module_missing_step(server_side: Optional[bool]) -> None:
    """Should raises if a non server side scanner is missing steps."""
    with pytest.raises(
        ValidationError, match="Module without steps must be server side."
    ):
        ModuleSchemaFactory.build(steps=None, server_side=server_side)


def test_validate_rule_name_with_valid_name() -> None:
    """Test that each rule name matches its id."""
    RulesDbSchemaFactory.build(
        rules={
            "rule-1": RuleSchemaFactory.build(name="rule-1"),
            "rule-2": RuleSchemaFactory.build(name="rule-2"),
        }
    )


def test_validate_rule_name_with_invalid_name() -> None:
    """Should raise if rule name doesn't match its id."""
    with pytest.raises(ValidationError, match='Rule name .* does not match ".*"'):
        RulesDbSchemaFactory.build(
            rules={"test": RuleSchemaFactory.build(name="invalid")}
        )


def test_validate_rule_name_with_no_rules() -> None:
    """Test rules db with no rules."""
    RulesDbSchemaFactory.build()


def test_validate_multiple_defaults() -> None:
    """Should raises if multiple default rule."""
    with pytest.raises(ValidationError, match="Only one default rule is allowed"):
        RulesDbSchemaFactory.build(
            default={
                "rule-1": RuleSchemaFactory.build(name="rule-1"),
                "rule-2": RuleSchemaFactory.build(name="rule-2"),
            }
        )


def test_validate_default_invalid_name() -> None:
    """Should raises if default rule as an invalid name."""
    with pytest.raises(
        ValidationError, match='Default rule name ".*" does not match ".*"'
    ):
        RulesDbSchemaFactory.build(
            default={
                "rule-1": RuleSchemaFactory.build(),
            }
        )


def test_validate_all_in_category_with_valid_category() -> None:
    """Test rule with valid category."""
    RuleSchemaFactory.build(categories=["ALL"])


def test_validate_all_in_category_with_invalid_category() -> None:
    """Should raises if ALL is missing in categories."""
    with pytest.raises(ValidationError, match='Rule .* is missing category "ALL"'):
        RuleSchemaFactory.build(categories=["invalid"])


def test_validate_description_length_with_valid_description() -> None:
    """Test rule with valid description."""
    RuleSchemaFactory.build(description="Lorem Ipsum " * 42)


def test_validate_description_length_with_invalid_description() -> None:
    """Should raises if rule description is too long."""
    with pytest.raises(
        ValidationError,
        match="Rule .* has a description longer than 512 characters",
    ):
        RuleSchemaFactory.build(description="Lorem Ipsum " * 43)


@pytest.mark.parametrize("url", ["https://example.com", "http://example.com"])
def test_validate_ref_url_with_valid_url(url: str) -> None:
    """Test rule with valid url."""
    rule = RuleSchemaFactory.build(ref=url)
    assert url == rule.ref


def test_validate_ref_url_with_invalid_url() -> None:
    """Should raises if ref is not a valid url."""
    with pytest.raises(ValidationError):
        RuleSchemaFactory.build(ref="invalid_url")


def test_validate_ref_url_with_valid_url_with_placeholder(
    monkeypatch: MonkeyPatch,
) -> None:
    """Test rule ref with env var injection."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    rule = RuleSchemaFactory.build(ref=f"{{{env_var_name}}}/a/b/c")
    assert rule.ref == "http://test.com/a/b/c"


def test_render_doc_url_error_empty_env_var() -> None:
    """Test render_doc_url."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    with pytest.raises(KeyError):
        RuleSchemaFactory.build(ref=f"{{{env_var_name}}}/a/path")
