"""Factories."""
from typing import cast

from pydantic_factories import ModelFactory, Use

from boostsec.registry_validator.models import RuleRealmNamespace, ScannerNamespace
from boostsec.registry_validator.schema import (
    ModuleSchema,
    RuleSchema,
    RulesDbSchema,
    ScanType,
    ServerSideModuleSchema,
)


class ModuleSchemaFactory(ModelFactory[ModuleSchema]):
    """Factory."""

    __model__ = ModuleSchema
    scan_types = Use(lambda: cast(list[ScanType], [ScanType.SAST]))


class ServerSideModuleSchemaFactory(ModelFactory[ServerSideModuleSchema]):
    """Factory."""

    __model__ = ServerSideModuleSchema
    scan_types = Use(lambda: cast(list[ScanType], [ScanType.SAST]))


class RuleSchemaFactory(ModelFactory[RuleSchema]):
    """Factory."""

    __model__ = RuleSchema

    categories = Use(lambda: ["ALL"])
    ref = Use(lambda: "https://example.org")


class RulesDbSchemaFactory(ModelFactory[RulesDbSchema]):
    """Factory."""

    __model__ = RulesDbSchema

    imports = Use(lambda: None)
    rules = Use(lambda: None)
    default = Use(lambda: None)


class ScannerNamespaceFactory(ModelFactory[ScannerNamespace]):
    """Factory."""

    __model__ = ScannerNamespace

    rules = Use(lambda: cast(RuleSchema, {}))
    imports = Use(lambda: cast(list[str], []))
    default = Use(lambda: None)
    updated = Use(lambda: False)


class RuleRealmNamespaceFactory(ModelFactory[RuleRealmNamespace]):
    """Factory."""

    __model__ = RuleRealmNamespace

    rules = Use(lambda: cast(RuleSchema, {}))
    imports = Use(lambda: cast(list[str], []))
    default = Use(lambda: None)
    updated = Use(lambda: False)
