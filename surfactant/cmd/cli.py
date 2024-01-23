import hashlib
import sys
from loguru import logger
import click

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._sbom import SBOM


@click.argument("sbom", type=click.File("r"), required=True)
@click.option("--file", is_flag=False, help="File of the entry to find")
@click.option("--sha256", is_flag=False, help="sha256 hash of the entry to find")
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
def find(sbom, sha256, file, installpath, containerpath, output_format, input_format):
    "CLI command to find specific entry(s) within a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    in_sbom = input_reader.read_sbom(sbom)
    out_sbom = SBOM()
    if sha256: # Specific hash, no need to check any other params
        out_sbom.add_software(in_sbom.find_software(sha256))
    elif file: # Specific file referenced, only return that entry, other options not neccessary
        sha256, sha1, md5 = _calculate_hashes(file)
        out_sbom.add_software(in_sbom.find_software(sha256))
    else:
        path_query = {}
        if installpath:
            path_query["installPath"] = str(installpath)
        if containerpath:
            path_query["containerPath"] = str(containerpath)
        for sw in in_sbom.find_software_by_path(path_query):
            out_sbom.add_software(sw)
    output_writer.write_sbom(out_sbom, sys.stdout)


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def edit(sbom):
    "CLI command to edit specific entry(s) in a supplied SBOM"


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("add")
def add(sbom):
    "CLI command to add specific entry(s) to a supplied SBOM"


def _calculate_hashes(file):
    with open(file, "rb") as f:
        sha256 = hashlib.sha256(f.read())
        f.seek(0)
        sha1 = hashlib.sha1(f.read())
        f.seek(0)
        md5 = hashlib.md5(f.read())
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()