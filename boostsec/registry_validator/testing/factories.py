"""Factories."""
from pydantic_factories import ModelFactory, Use

from boostsec.registry_validator.shared import RuleModel, RulesDbModel


class RuleModelFactory(ModelFactory[RuleModel]):
    """Factory."""

    __model__ = RuleModel

    categories = Use(lambda: ["ALL"])
    ref = Use(lambda: "https://example.org")


class RuleDbModelFactory(ModelFactory[RulesDbModel]):
    """Factory."""

    __model__ = RulesDbModel

    imports = Use(lambda: None)
    rules = Use(lambda: None)
    default = Use(lambda: None)
