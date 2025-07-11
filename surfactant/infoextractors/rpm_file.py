# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# import struct
# from pathlib import Path
# from queue import Queue                       # Present for use in future extraction implementation
from typing import Any, Dict, List#, Optional, Tuple, Union

import rpmfile
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
# from surfactant.context import ContextEntry   # Present for use in future extraction implementation


def supports_file(filetype) -> bool:
    return filetype == "RPM Package"
                
def get_files(directories: List[bytes], files: List[bytes], indicies: List[int]):
    """
    Extracts files from the given directories and files list
    
    :param directories: List of directory paths in bytes
    :param files: List of file names in bytes
    :param indicies: Directory associated with current file
    :return: List of extracted file paths
    """
    extracted_files = []
    for i in range(len(indicies)):
        directory = directories[indicies[i]].decode()
        file_name = files[i].decode()
        extracted_files.append(f"{directory}{file_name}")
    return extracted_files


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    # context_queue: "Queue[ContextEntry]",     # Present for use in future extraction implementation
    # current_context: Optional[ContextEntry],
) -> object:
    if not supports_file(filetype):
        return None
    return extract_rpm_info(filename)

def extract_rpm_info(filename: str) -> object:
    with rpmfile.open(filename) as rpm:
        header = rpm.headers
        file_details: Dict[str, Any] = {"MD5": header["md5"].decode()}
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
            "archive_format",
            "archive_compression",
            "optflags",
            "sha256"
        ]
        for key in easy_keys:
            if key in header:
                file_details[key] = header[key].decode()
        # Handle sections that aren't simple strings
        if "buildtime" in header:
            file_details["buildtime"] = header["buildtime"]
        if "basenames" in header:
            file_details["associated files"] = get_files(
                header["dirnames"],
                header["basenames"],
                header["dirindexes"]
            )
        if "requirename" in header:
            file_details["requirename"] = []
            for item in header["requirename"]:
                file_details["requirename"].append(item.decode())
        if "provides" in header:
            file_details["provides"] = []
            for item in header["provides"]:
                file_details["provides"].append(item.decode())
        return file_details

