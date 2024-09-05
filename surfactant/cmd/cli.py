import hashlib
import sys
import os
import platform
from pathlib import Path

import click
from loguru import logger
import json

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._relationship import Relationship
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._software import Software
# from surfactant.cmd.cli_commands.cli_load import Load
from surfactant.cmd.cli_commands import *


@click.argument("sbom", type=click.File("r"), required=True)
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
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("find")
def handle_cli_find(sbom, output_format, input_format, **kwargs):
    "CLI command to find specific entry(s) within a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    in_sbom = input_reader.read_sbom(sbom)

    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    out_sbom = find().execute(in_sbom, **filtered_kwargs)
    if not out_sbom.software:
        logger.warning("No software matches found with given parameters.")
    output_writer.write_sbom(out_sbom, sys.stdout)


@click.argument("sbom", required=True)
@click.option(
    "--output",
    default=None,
    is_flag=False,
    help="Specifies the file to output new sbom. Default replaces the input file.",
)
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
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("add")
def handle_cli_add(sbom, output, output_format, input_format, **kwargs):
    "CLI command to add specific entry(s) to a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    with open(Path(sbom), "r") as f:
        in_sbom = input_reader.read_sbom(f)
    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    out_sbom = add().execute(in_sbom, **filtered_kwargs)
    # Write to the input file if no output specified
    if output is None:
        with open(Path(sbom), "w") as f:
            output_writer.write_sbom(out_sbom, f)
    else:
        try:
            with open(Path(output), "w") as f:
                output_writer.write_sbom(out_sbom, f)
        except OSError as e:
            logger.error(f"Could not open file {output} in write mode - {e}")


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def handle_cli_edit(sbom, output_format, input_format, **kwargs):
    "CLI command to edit specific entry(s) in a supplied SBOM"

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


@click.argument("outfile", type=click.File("w"), required=True)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.command("save")
def handle_cli_save(outfile, output_format):
    "CLI command to save SBOM to a user specified file"
    Save(output_format=output_format).execute(outfile)


