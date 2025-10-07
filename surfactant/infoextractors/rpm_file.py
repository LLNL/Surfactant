# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# import struct
# from pathlib import Path
# from queue import Queue                       # Present for use in future extraction implementation
from typing import Any, Dict, List, Tuple

import rpmfile

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

# from surfactant.context import ContextEntry   # Present for use in future extraction implementation


def supports_file(filetype) -> bool:
    """Returns if filetype contains "RPM Package" """
    return "RPM Package" in filetype


def get_files(
    directories: List[bytes], files: List[bytes], indicies: List[int], hashes: List[bytes]
) -> Dict[Any, Any]:
    """Extracts files from the given directories and files list.

    Args:
        directories (List[bytes]): List of directory paths in bytes.
        files (List[bytes]): List of file names in bytes.
        indicies (List[bytes]): Directory associated with current file.
    Returns:
        List of extracted file paths.
    """
    extracted_files = {}
    index = 0
    # If there is only one index, return as an integer, not a list of integers
    if isinstance(indicies, int):
        directory = directories[indicies].decode()
        file_name = files[index].decode()
        file_hash = hashes[index].decode()
        extracted_files[f"{directory}{file_name}"] = file_hash
    else:
        while index < len(indicies):
            directory = directories[indicies[index]].decode()
            file_name = files[index].decode()
            file_hash = hashes[index].decode()
            extracted_files[f"{directory}{file_name}"] = file_hash
            index += 1
    return extracted_files


def combine_lists(key_list: List[bytes], value_list: List[bytes]) -> Dict:
    """Combines 2 lists into a single dictionary - matching on index.

    Args:
        key_list (List[bytes]): List to use as key.
        value_list (List[bytes]): List to use as value.
    Returns:
        Combined dictionary.
    """
    result = {}
    if not key_list or not value_list or len(key_list) != len(value_list):
        return result
    index = 0
    while index < len(key_list):
        name = key_list[index].decode()
        version = value_list[index].decode()
        result[name] = version
        index += 1
    return result


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: List[str],
    software_field_hints: List[Tuple[str, object, int]],
    # context_queue: "Queue[ContextEntry]",     # Present for use in future extraction implementation
    # current_context: Optional[ContextEntry],
) -> object:
    if not supports_file(filetype):
        return None
    rpm_info = extract_rpm_info(filename)

    for key in rpm_info["rpm"]:
        software_field_hints.append((key, rpm_info["rpm"][key], 80))
    return rpm_info


def extract_rpm_info(filename: str) -> Dict[str, Any]:
    """Extracts fields from the header of an RPM Package.

    Args:
        filename: Path to file to extract information from.
    Returns:
        A dictionary of all fields found in the RPM header.
    """
    file_details: Dict[str, Any] = {}
    with rpmfile.open(filename) as rpm:
        header = rpm.headers
        file_details["rpm"] = {}
        # If any additional fields are desired that have values of single strings, just add the field to this list
        simple_keys = [
            "name",
            "sourcerpm",
            "version",
            "release",
            "summary",
            "description",
            "rpmversion",
            "copyright",
            "os",
            "arch",
            "target",
            "url",
            "archive_format",
            "archive_compression",
            "optflags",
            "sha256",
            "md5",
        ]
        for key in simple_keys:
            if key in header:
                file_details["rpm"][key] = header[key].decode()
        # Handle sections that aren't simple strings
        complex_keys = {
            "requirename": "requireversion",
            "conflict": "conflictversion",
            "obsoletes": "obsoleteversion",
            "enhancename": "enhanceversion",
            "suggestname": "suggestversion",
            "recommendname": "recommendversion",
            "supplementname": "supplementversion",
            "provides": "provideversion",
        }
        for key, value in complex_keys.items():
            if key in header:
                file_details["rpm"][key] = combine_lists(header[key], header[value])
        if "buildtime" in header:
            file_details["rpm"]["buildtime"] = header["buildtime"]
        if "basenames" in header:
            file_details["rpm"]["associated_files"] = get_files(
                header["dirnames"], header["basenames"], header["dirindexes"], header["filemd5s"]
            )
        return file_details
