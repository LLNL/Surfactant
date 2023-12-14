import hashlib
import sys

import click

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager


@click.argument("sbom", type=click.File("r"), required=True)
@click.option("--file", is_flag=False, help="File of the entry to find")
@click.option("--sha256", is_flag=False, help="sha256 hash of the entry to find")
@click.option("--uuid", is_flag=False, help="UUID of the entry to find")
@click.option(
    "--installPath",
    is_flag=False,
    help="Matches all entries with a install path or partial install path match",
)
@click.option(
    "--containerPath",
    is_flag=False,
    help="Matches all entries with a container path or partial container path match",
)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=surfactant.output.[cytrics|csv|spdx]_writer",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=surfactant.input_readers.[cytrics|cyclonedx|spdx]_reader",
)
@click.command("find")
def find(sbom, sha256, file, uuid, installpath, containerpath, output_format, input_format):
    "CLI command to find specific entry(s) within a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    in_sbom = input_reader.read_sbom(sbom)
    if file:
        chunkSize = 65536
        sha256Gen = hashlib.sha256()
        with open(file, "rb") as f:
            while True:
                data = f.read(chunkSize)
                if not data:
                    break
                sha256Gen.update(data)
        sha256 = sha256Gen.hexdigest()
        entry = in_sbom.find_software(sha256)
        output_writer.write_sbom(entry, sys.stdout)


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def edit(sbom):
    "CLI command to edit specific entry(s) in a supplied SBOM"


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("add")
def add(sbom):
    "CLI command to add specific entry(s) to a supplied SBOM"
