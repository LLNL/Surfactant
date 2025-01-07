import sys
import os
import platform
from pathlib import Path

import click
from loguru import logger
import json

from surfactant.configmanager import ConfigManager
from surfactant.cmd.cli_commands import *
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._relationship import Relationship
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._software import Software
from surfactant.cmd.cli_commands import *


@click.argument("sbom", type=click.File("r"), required=True)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("load")
def handle_cli_load(sbom, input_format):
    "CLI command to load supplied SBOM into cli"
    Load(input_format=input_format).execute(sbom)

@click.command("unload")
def handle_cli_unload():
    "CLI command to load supplied SBOM into cli"
    Unload().execute()

@click.argument("sbom", type=click.File("r"), required=True)
@click.option(
    "--input_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "input_format", fallback="surfactant.input_readers.cytrics_reader"
    ),
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("load")
def handle_cli_load(sbom, input_format):
    "CLI command to load supplied SBOM into cli"
    Load(input_format=input_format).execute(sbom)


@click.option("--file", is_flag=False, help="File of the entry to find")
@click.option("--sha256", is_flag=False, type=str, help="sha256 hash of the entry to find")
@click.option("--uuid", is_flag=False, type=str, help="uuid of the entry to find")
@click.option(
    "--installPath",
    is_flag=False,
    type=str,
    help="Matches all entries with an install path or partial install path match",
)
@click.option(
    "--containerPath",
    is_flag=False,
    type=str,
    help="Matches all entries with a container path or partial container path match",
)
@click.command("find")
def handle_cli_find(**kwargs):
    "CLI command to find specific entry(s) within a supplied SBOM"
    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    find = Find()
    success = find.execute(**filtered_kwargs)
    # Write result to stdout in the cytrics format
    if success:
        output_writer = find_io_plugin(get_plugin_manager(), "surfactant.output.cytrics_writer", "write_sbom")
        output_writer.write_sbom(find.get_subset(), sys.stdout)

@click.option("--file", is_flag=False, help="Adds entry for file to sbom")
@click.option("--relationship", is_flag=False, type=str, help="Adds relationship to sbom")
@click.option("--entry", is_flag=False, type=str, help="Adds software entry to sbom")
@click.option(
    "--installPath",
    is_flag=False,
    type=str,
    nargs=2,
    help="Adds new installPath by finding and replacing a containerPath prefix (1st arg) with a new prefix (2nd arg)",
)
@click.command("add")
def handle_cli_add(**kwargs):
    "CLI command to add specific entry(s) to a supplied SBOM"
    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    add = Add()
    success = add.execute(**filtered_kwargs)
    # Write result to stdout in the cytrics format
    if success:
        logger.info("Changes successfully added.")


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def handle_cli_edit(sbom, output_format, input_format, **kwargs):
    "CLI command to edit specific entry(s) in a supplied SBOM"
    pass


@click.argument("outfile", type=click.File("w"), required=True)
@click.option(
    "--save_subset",
    is_flag=True,
    default=False,
    help="When True, cli will save subset, otherwise it will save full sbom",
)
@click.option(
    "--output_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "output_format", fallback="surfactant.output.cytrics_writer"
    ),
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.command("save")
def handle_cli_save(outfile, save_subset, output_format):
    "CLI command to save SBOM to a user specified file"
    Save(output_format=output_format).execute(outfile, save_subset)
