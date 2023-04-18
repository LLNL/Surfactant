# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import importlib.metadata
import sys

import click

from surfactant.cmd import generate as gen
from surfactant.plugin.manager import get_plugin_manager


@click.group()
def main():
    pass


@main.command("generate")
@click.argument("config_file", envvar="CONFIG_FILE", type=click.File("r"), required=True)
@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sbom", type=click.File("r"), required=False)
@click.option(
    "--skip_gather",
    is_flag=True,
    default=False,
    required=False,
    help="Skip gathering information on files and adding software entries",
)
@click.option(
    "--skip_relationships",
    is_flag=True,
    default=False,
    required=False,
    help="Skip adding relationships based on Linux/Windows/etc metadata",
)
@click.option(
    "--recorded_institution", is_flag=False, default="LLNL", help="Name of user's institution"
)
def generate(
    config_file, sbom_outfile, input_sbom, skip_gather, skip_relationships, recorded_institution
):
    """Generate a sbom configured in CONFIG_FILE and output to SBOM_OUTPUT.

    An optional INPUT_SBOM can be supplied to use as a base for subsequent operations
    """
    pm = get_plugin_manager()
    gen.sbom(
        config_file,
        sbom_outfile,
        input_sbom,
        skip_gather,
        skip_relationships,
        recorded_institution,
        pm,
    )


@main.command("version")
def version():
    """Print version information."""
    click.echo(importlib.metadata.version("surfactant"))
    sys.exit(0)


if __name__ == "__main__":
    main()
