# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from queue import Queue
from typing import List, Optional

from pluggy import HookspecMarker

from surfactant import ContextEntry
from surfactant.sbomtypes import SBOM, Relationship, Software

hookspec = HookspecMarker("surfactant")


@hookspec(firstresult=True)
def identify_file_type(filepath: str) -> Optional[str]:
    """Determine the type of file located at filepath, and return a string identifying the type
    that will be passed to file extraction plugins. Return `None` to indicate that the type was
    unable to be determined.

    Args:
        filepath (str): The path to the file to determine the type of.

    Returns:
        Optional[str]: A string identifying the type of file, or None if the file type could not be recognized.
    """


@hookspec
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    context: "Queue[ContextEntry]",
    children: List[Software],
) -> Optional[list]:
    """Extracts information from the given file to add to the given software entry. Return an
    object to be included as part of the metadata field, and potentially used as part of
    selecting default values for other Software entry fields. Returning `None` will not add
    anything to the Software entry metadata.

    Args:
        sbom (SBOM): The SBOM that the software entry is part of. Can be used to add observations or analysis data.
        software (Software): The software entry the gathered information will be added to.
        filename (str): The full path to the file to extract information from.
        filetype (str): File type information based on magic bytes.
        context (Queue[ContextEntry]): Modifiable queue of entries from input config file. Existing plugins should still work without adding this parameter.
        children (List[Software]): List of additional software entries to include in the SBOM. Plugins can add additional entries, though if the plugin extracts files to a temporary directory, the context argument should be used to have Surfactant process the files instead.

    Returns:
        object: An object to be added to the metadata field for the software entry. May be `None` to add no metadata.
    """


@hookspec
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """Called to add relationships to an SBOM after information has been gathered.

    The function will be called once for every metadata object in every software
    entry in the SBOM. Realistically, this means a plugin should not be trying to
    establish relationships for the entire SBOM before returning, just for the
    software/metadata object that has been passed to it.

    Returns a list of relationships to be added to the SBOM.

    Args:
        sbom (SBOM): The SBOM object that the Software is part of.
        software (Software): The Software entry that the metadata object is from.
        metadata: The metadata object to establish relationships based on.

    Returns:
        Optional[List[Relationship]]: A list of relationships to add to the SBOM.
    """


@hookspec
def write_sbom(sbom: SBOM, outfile) -> None:
    """Writes the contents of the SBOM to the given output file.

    Args:
        sbom (SBOM): The SBOM to write to the output file.
        outfile: The output file handle to write the SBOM to.
    """


@hookspec
def read_sbom(infile) -> SBOM:
    """Reads the contents of the input SBOM from the given input SBOM file.

    Returns a SBOM object containing the input SBOM, which can be added to.

    Args:
        infile: The input file handle to read the SBOM from.
    """


@hookspec
def short_name() -> Optional[str]:
    """A short name to register the hook as.

    Returns:
        Optional[str]: The name to register the hook with.
    """
