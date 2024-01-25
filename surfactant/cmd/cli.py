import hashlib
import sys

import click
from loguru import logger

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._software import Software


@click.argument("sbom", type=click.File("r"), required=True)
@click.option("--file", is_flag=False, help="File of the entry to find")
@click.option("--sha256", is_flag=False, type=str, help="sha256 hash of the entry to find")
@click.option("--uuid", is_flag=False, type=str, help="uuid of the entry to find")
@click.option(
    "--installPath",
    is_flag=False,
    type=str,
    help="Matches all entries with a install path or partial install path match",
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
    help="SBOM output format, options=surfactant.output.[cytrics|csv|spdx]_writer",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=surfactant.input_readers.[cytrics|cyclonedx|spdx]_reader",
)
@click.command("find")
def find(sbom, output_format, input_format, **kwargs):
    "CLI command to find specific entry(s) within a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    in_sbom = input_reader.read_sbom(sbom)

    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    out_sbom = cli_find().execute(in_sbom, **filtered_kwargs)
    if not out_sbom.software:
        logger.warning("No software matches found with given parameters.")
    output_writer.write_sbom(out_sbom, sys.stdout)


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def edit(sbom):
    "CLI command to edit specific entry(s) in a supplied SBOM"


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("add")
def add(sbom):
    "CLI command to add specific entry(s) to a supplied SBOM"


class cli_find:
    """
    A class that implements the surfactant cli find functionality

    Attributes:
    match_functions     A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    sbom                A internal record of sbom entries the class adds to as it finds more matches.
    """

    match_functions: dict
    sbom: SBOM

    def __init__(self):
        """Initializes the cli_find class"""
        self.match_functions = {
            "sha256": self.match_by_sha256,
            "file": self.match_by_file,
            "uuid": self.match_by_uuid,
            "containerpath": self.match_by_containerPath,
            "installpath": self.match_by_installPath,
        }
        self.sbom = SBOM()

    def execute(self, input_sbom: SBOM, **kwargs):
        """Executes the main functionality of the cli_find class
        param: input_sbom   The sbom to find matches within
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        for sw in input_sbom.software:
            match = True
            for k, v in kwargs.items():
                if not self.match_functions[k](sw, v):
                    match = False
                    break
            if match:
                self.sbom.add_software(sw)
        return self.sbom

    def match_by_sha256(self, entry: Software, sha256: str) -> bool:
        """Matches sbom entry on sha256 hash
        param: entry   The software sbom entry to match
        param: sha256: String value of the desired hash to match
        returns:       bool, True if a match, False if not
        """
        if entry.sha256 == sha256:
            return True
        return False

    def match_by_file(self, entry: Software, file) -> bool:
        """Matches sbom entry on a given file
        param: entry   The software sbom entry to match
        param: file:   File to match
        returns:       bool, True if a match, False if not
        """
        sha256, _, _ = self._calculate_hashes(file, sha256=True)
        return self.match_by_sha256(entry, sha256)

    def match_by_uuid(self, entry: Software, uuid: str) -> bool:
        """Matches sbom entry on uuid
        param: entry    The software sbom entry to match
        param: uuid:    String value of the desired uuid to match
        returns:        bool, True if a match, False if not
        """
        if entry.UUID == uuid:
            return True
        return False

    def match_by_containerPath(self, entry: Software, containerPath: str) -> bool:
        """Matches sbom entry on containerpath. Will match if containerPath is contained in any of the containerPath entries.
        param: entry            The software sbom entry to match
        param: containerPath:   String value of the desired containerpath to match
        returns:                bool, True if a match, False if not
        """
        if any(containerPath in p for p in entry.containerPath):
            return True
        return False

    def match_by_installPath(self, entry: Software, installPath: str) -> bool:
        """Matches sbom entry on installpath. Will match if installPath is contained in any of the installPath entries.
        param: entry            The software sbom entry to match
        param: installPath:     String value of the desired installPath to match
        returns:                bool, True if a match, False if not
        """
        if any(installPath in p for p in entry.installPath):
            return True
        return False

    def _calculate_hashes(self, file, sha256=False, sha1=False, md5=False):
        """Helper function to calculate hashes on a given file.
        param: file      The file to calculate hashes on
        param: sha256:   Bool to decide if sha256 hash should be calculated
        param: sha1:     Bool to decide if sha1 hash should be calculated
        param: md5:      Bool to decide if md5 hash should be calculated
        returns:         str, str, str, Hashes calculated, None for those that aren't calculated
        """
        sha256_hash, sha1_hash, md5_hash = None, None, None
        with open(file, "rb") as f:
            if sha256:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
                f.seek(0)
            if sha1:
                sha1_hash = hashlib.sha1(f.read()).hexdigest()
                f.seek(0)
            if md5:
                md5_hash = hashlib.md5(f.read()).hexdigest()
        return sha256_hash, sha1_hash, md5_hash
