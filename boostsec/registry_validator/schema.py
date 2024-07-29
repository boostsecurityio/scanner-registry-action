"""Scanners & rules definition schemas."""
import os
from enum import Enum
from typing import Any, Optional

from pydantic import AnyHttpUrl, BaseModel, Field, validator


class ScanType(str, Enum):
    """Security types that a scanner can claim it produces."""

    CICD = "cicd"
    IAC = "iac"
    LICENSE = "license"
    METADATA = "metadata"
    SAST = "sast"
    SBOM = "sbom"
    SCA = "sca"
    SCA_CONTAINER = "sca_container"
    SCI = "sci"
    SECRETS = "secrets"


class ModuleBaseSchema(BaseModel):
    """Base for scanner modules."""

    name: str
    namespace: str


class ModuleConfigSchema(BaseModel):
    """Representation of a module config."""

    support_diff_scan: bool


class ModuleSchema(ModuleBaseSchema):
    """Representation of a module file content."""

    api_version: int
    id_: str = Field(..., alias="id")
    config: ModuleConfigSchema
    steps: list[Any]  # steps aren't currently validated
    scan_types: list[ScanType] = Field(..., min_items=1)


class ServerSideModuleSchema(ModuleBaseSchema):
    """Representation of a server-side module file content."""


class RuleSchema(BaseModel):
    """Representation of a scanner rule."""

    name: str
    pretty_name: str
    description: str
    group: str
    categories: list[str]
    ref: AnyHttpUrl

    recommended: bool = False

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


RulesSchema = dict[str, RuleSchema]


class RulesDbSchema(BaseModel):
    """Representation of a rules db file content."""

    imports: Optional[list[str]] = Field(None, alias="import")
    rules: Optional[RulesSchema]
    default: Optional[RulesSchema]

    class Config:
        """Config."""

        allow_population_by_field_name = True

    @validator("rules")
    def validate_rules_names(
        cls, rules: Optional[RulesSchema]
    ) -> Optional[RulesSchema]:
        """Validate rule name is equal to rule id."""
        if not rules:
            return None

        for name, rule in rules.items():
            if name != rule.name:
                raise ValueError(f'Rule name "{name}" does not match "{rule.name}"')

        return rules

    @validator("default")
    def validation_default(
        cls, default: Optional[RulesSchema]
    ) -> Optional[RulesSchema]:
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


def _render_doc_url(unrendered_url: str) -> str:
    """Render doc url."""
    var_name = "BOOSTSEC_DOC_BASE_URL"
    placeholder = f"{{{var_name}}}"
    if placeholder in unrendered_url:
        doc_base_url = os.environ[var_name]
        return unrendered_url.replace(placeholder, doc_base_url)
    else:
        return unrendered_url
