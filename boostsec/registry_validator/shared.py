"""Shared components between validation & uploads."""
import os
from pathlib import Path
from typing import Any, Optional

from pydantic import AnyHttpUrl, BaseModel, Field, validator


class RuleModel(BaseModel):
    """Representation of a scanner rule."""

    name: str
    pretty_name: str
    description: str
    group: str
    categories: list[str]
    ref: AnyHttpUrl

    class Config:
        """Config."""

        extra = "forbid"

    @validator("categories")
    def validate_all_in_category(cls, categories: list[str], values: Any) -> list[str]:
        """Validate category ALL is included in the categories."""
        if "ALL" not in categories:
            name = values["name"]
            raise ValueError(f'Rule "{name}" is missing category "ALL"')

        return categories

    @validator("description")
    def validate_description_length(cls, description: str, values: Any) -> str:
        """Validate rule description length is less than 512 characters."""
        if len(description) > 512:
            name = values["name"]
            raise ValueError(
                f'Rule "{name}" has a description longer than 512 characters'
            )
        return description

    @validator("ref", pre=True)
    def validate_ref_url(cls, ref: str) -> str:
        """Validate ref url is valid."""
        return _render_doc_url(ref)


Rules = dict[str, RuleModel]


class RulesDbModel(BaseModel):
    """Representation of a rules db file content."""

    imports: Optional[list[str]] = Field(None, alias="import")
    rules: Optional[Rules]
    default: Optional[Rules]

    @validator("rules")
    def validate_rules_names(cls, rules: Optional[Rules]) -> Optional[Rules]:
        """Validate rule name is equal to rule id."""
        if not rules:
            return None

        for name, rule in rules.items():
            if name != rule.name:
                raise ValueError(f'Rule name "{name}" does not match "{rule.name}"')

        return rules

    @validator("default")
    def validation_default(cls, default: Optional[Rules]) -> Optional[Rules]:
        """Validate default rule."""
        if not default:
            return None

        default_rules = list(default.items())
        if len(default_rules) > 1:
            raise ValueError("Only one default rule is allowed")

        name, rule = default_rules[0]
        if name != rule.name:
            raise ValueError(f'Default rule name "{name}" does not match "{rule.name}"')

        return default


class RegistryConfig(BaseModel):
    """Config class for the registry.

    Holds reference to the scanners and rules realm location.
    """

    scanners_path: Path
    rules_realm_path: Path


def _render_doc_url(unrendered_url: str) -> str:
    """Render doc url."""
    var_name = "BOOSTSEC_DOC_BASE_URL"
    placeholder = f"{{{var_name}}}"
    if placeholder in unrendered_url:
        doc_base_url = os.environ[var_name]
        return unrendered_url.replace(placeholder, doc_base_url)
    else:
        return unrendered_url
