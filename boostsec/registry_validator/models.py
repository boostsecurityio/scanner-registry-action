"""Models."""
from enum import Enum
from typing import Literal, Optional, Union

from pydantic import BaseModel

from boostsec.registry_validator.schema import RulesSchema


class NamespaceType(str, Enum):
    """Type of namespace."""

    Scanner = "scanner"
    RuleRealm = "rule-realm"


class _NamespaceBase(BaseModel):
    namespace: str
    updated: bool = False
    rules: RulesSchema = {}
    imports: list[str] = []
    default: Optional[RulesSchema] = None


class ScannerNamespace(_NamespaceBase):
    """Scanner namespace."""

    namespace_type: Literal[NamespaceType.Scanner] = NamespaceType.Scanner

    driver: str


class RuleRealmNamespace(_NamespaceBase):
    """Rule realm namespace."""

    namespace_type: Literal[NamespaceType.RuleRealm] = NamespaceType.RuleRealm


NamespaceUnion = Union[ScannerNamespace, RuleRealmNamespace]
