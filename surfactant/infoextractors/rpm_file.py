# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# import struct
# from pathlib import Path
# from queue import Queue                       # Present for use in future extraction implementation
from typing import Any, Dict, List, Tuple

import rpmfile
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

# from surfactant.context import ContextEntry   # Present for use in future extraction implementation


def supports_file(filetype) -> bool:
    logger.debug("Checks for RPM Package")
    return filetype == "RPM Package"


def get_files(
    directories: List[bytes], files: List[bytes], indicies: List[int], hashes: List[bytes]
) -> Dict[Any, Any]:
    """
    Extracts files from the given directories and files list

    :param directories: List of directory paths in bytes
    :param files: List of file names in bytes
    :param indicies: Directory associated with current file
    :return: List of extracted file paths
    """
    extracted_files = {}
    for i in range(len(indicies)):
        directory = directories[indicies[i]].decode()
        file_name = files[i].decode()
        file_hash = hashes[i].decode()
        extracted_files[f"{directory}{file_name}"] = file_hash
    return extracted_files


def combine_lists(name_info: List[bytes], version_info: List[bytes]) -> Dict:
    """
    Takes given lists and combines the associated data in each into a dictionary

    :param name_info: List of name bytes
    :param version_info: List of version bytes
    :return: Dictionary with name and version
    """
    result = {}
    if not name_info or not version_info or len(name_info) != len(version_info):
        return result
    for index in range(len(name_info)):
        name = name_info[index].decode()
        version = version_info[index].decode()
        result[name] = version
    return result


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    software_field_hints: List[Tuple[str, object, int]],
    # context_queue: "Queue[ContextEntry]",     # Present for use in future extraction implementation
    # current_context: Optional[ContextEntry],
) -> object:
    if not supports_file(filetype):
        return None
    rpm_info = extract_rpm_info(filename)

    if "name" in rpm_info["rpm"]:
        software_field_hints.append(("name", rpm_info["rpm"]["name"], 80))
    if "version" in rpm_info["rpm"]:
        software_field_hints.append(("version", rpm_info["rpm"]["version"], 80))
    if "summary" in rpm_info["rpm"]:
        software_field_hints.append(("summary", rpm_info["rpm"]["summary"], 80))
    if "description" in rpm_info["rpm"]:
        software_field_hints.append(("description", rpm_info["rpm"]["description"], 80))

    for key in rpm_info["rpm"]:
        software_field_hints.append((key, rpm_info["rpm"][key], 80))
    return rpm_info


def extract_rpm_info(filename: str) -> Dict[str, Any]:
    """
    Extracts fields from the header of an RPM Package

    :param filename: Path to file to extract information from
    """
    file_details: Dict[str, Any] = {}
    with rpmfile.open(filename) as rpm:
        header = rpm.headers
        file_details["rpm"] = {}
        # If any additional fields are desired that have values of single strings, just add the field to this list
        easy_keys = [
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
        for key in easy_keys:
            if key in header:
                file_details["rpm"][key] = header[key].decode()
        # Handle sections that aren't simple strings
        medium_keys = {
            "requirename": "requireversion",
            "conflict": "conflictversion",
            "obsoletes": "obsoleteversion",
            "enhancename": "enhanceversion",
            "suggestname": "suggestversion",
            "recommendname": "recommendversion",
            "supplementname": "supplementversion",
            "provides": "provideversion",
        }
        for key in medium_keys:
            if key in header:
                file_details["rpm"][key] = combine_lists(header[key], header[medium_keys[key]])
        if "buildtime" in header:
            file_details["rpm"]["buildtime"] = header["buildtime"]
        if "basenames" in header:
            file_details["rpm"]["associated_files"] = get_files(
                header["dirnames"], header["basenames"], header["dirindexes"], header["filemd5s"]
            )
        return file_details
