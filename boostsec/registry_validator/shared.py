"""Shared components between validation & uploads."""
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class RuleModel(BaseModel):
    """Representation of a scanner rule."""

    categories: list[str]
    description: str
    group: str
    name: str
    pretty_name: str
    ref: str


Rules = dict[str, RuleModel]


class RulesDbModel(BaseModel):
    """Representation of a rules db file content."""

    imports: Optional[list[str]] = Field(None, alias="import")
    rules: Optional[Rules]
    default: Optional[Rules]


class RegistryConfig(BaseModel):
    """Config class for the registry.

    Holds reference to the scanners and rules realm location.
    """

    scanners_path: Path
    rules_realm_path: Path
