"""Cli Parameters."""

import typer

ApiEndpoint = typer.Option(help="The API endpoint to validate against.")
ApiToken = typer.Option(help="The GitHub token to use for authentication.")
RegistryPath = typer.Option(help="The path of the registry.")
