"""Tests for shared module."""
import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from boostsec.registry_validator.shared import render_doc_url
from boostsec.registry_validator.testing.factories import (
    RuleDbModelFactory,
    RuleModelFactory,
)


def test_validate_rule_name_with_valid_name() -> None:
    """Test that each rule name matches its id."""
    RuleDbModelFactory.build(
        rules={
            "rule-1": RuleModelFactory.build(name="rule-1"),
            "rule-2": RuleModelFactory.build(name="rule-2"),
        }
    )


def test_validate_rule_name_with_invalid_name() -> None:
    """Should raise if rule name doesn't match its id."""
    with pytest.raises(ValidationError, match='Rule name .* does not match ".*"'):
        RuleDbModelFactory.build(rules={"test": RuleModelFactory.build(name="invalid")})


def test_validate_rule_name_with_no_rules() -> None:
    """Test rules db with no rules."""
    RuleDbModelFactory.build()


def test_validate_multiple_defaults() -> None:
    """Should raises if multiple default rule."""
    with pytest.raises(ValidationError, match="Only one default rule is allowed"):
        RuleDbModelFactory.build(
            default={
                "rule-1": RuleModelFactory.build(name="rule-1"),
                "rule-2": RuleModelFactory.build(name="rule-2"),
            }
        )


def test_validate_default_invalid_name() -> None:
    """Should raises if default rule as an invalid name."""
    with pytest.raises(
        ValidationError, match='Default rule name ".*" does not match ".*"'
    ):
        RuleDbModelFactory.build(
            default={
                "rule-1": RuleModelFactory.build(),
            }
        )


def test_validate_all_in_category_with_valid_category() -> None:
    """Test rule with valid category."""
    RuleModelFactory.build(categories=["ALL"])


def test_validate_all_in_category_with_invalid_category() -> None:
    """Should raises if ALL is missing in categories."""
    with pytest.raises(ValidationError, match='Rule .* is missing category "ALL"'):
        RuleModelFactory.build(categories=["invalid"])


def test_validate_description_length_with_valid_description() -> None:
    """Test rule with valid description."""
    RuleModelFactory.build(description="Lorem Ipsum " * 42)


def test_validate_description_length_with_invalid_description() -> None:
    """Should raises if rule description is too long."""
    with pytest.raises(
        ValidationError,
        match="Rule .* has a description longer than 512 characters",
    ):
        RuleModelFactory.build(description="Lorem Ipsum " * 43)


@pytest.mark.parametrize("url", ["https://example.com", "http://example.com"])
def test_validate_ref_url_with_valid_url(url: str) -> None:
    """Test rule with valid url."""
    rule = RuleModelFactory.build(ref=url)
    assert url == rule.ref


def test_validate_ref_url_with_invalid_url() -> None:
    """Should raises if ref is not a valid url."""
    with pytest.raises(
        ValidationError,
        match='Url missing protocol: "invalid_url" from rule ".*"',
    ):
        RuleModelFactory.build(ref="invalid_url")


def test_validate_ref_url_with_valid_url_with_placeholder(
    monkeypatch: MonkeyPatch,
) -> None:
    """Test rule ref with env var injection."""
    env_var_name = "BOOSTSEC_DOC_BASE_URL"
    monkeypatch.setenv(env_var_name, "http://test.com")
    rule = RuleModelFactory.build(ref=f"{{{env_var_name}}}/a/b/c")
    assert rule.ref == "http://test.com/a/b/c"


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
