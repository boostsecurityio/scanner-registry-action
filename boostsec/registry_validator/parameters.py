"""Cli Parameters."""

import typer

ApiEndpoint = typer.Option(help="The API endpoint to validate against.")
ApiToken = typer.Option(help="The GitHub token to use for authentication.")
ScannersPath = typer.Option(help="The path of scanners.")
RulesRealmPath = typer.Option(help="The path of rules realm.")
ModulesPath = typer.Option(help="The location of the rule database.")
