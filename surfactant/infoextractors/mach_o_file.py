# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# https://lief.re/doc/stable/api/python/macho.html

from typing import Any, Dict

import lief

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return "MACHO" in filetype  # Covers MACHOFAT, MACHOFAT64, MACHO32, MACHO64


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str
) -> object:
    if not supports_file(filetype):
        return None
    return extract_mach_o_info(filename)


def extract_mach_o_info(filename):
    try:
        binaries = lief.MachO.parse(filename)
    except OSError:
        return {}

    file_details: Dict[str:Any] = {"OS": "MacOS"}
    file_details["numBinaries"] = binaries.size
    file_details["binaries"] = []

    # Iterate over all binaries in the FAT binary
    for binary in binaries:
        header = binary.header
        binary_details = {}

        binary_details["format"] = binary.format.__name__

        # Extract info from headers
        binary_details["cpuType"] = header.cpu_type.__name__
        binary_details["cpuSubtype"] = header.cpu_subtype
        binary_details["fileType"] = header.file_type.__name__
        binary_details["flags"] = [flag.__name__ for flag in header.flags_list]
        binary_details["numCommands"] = header.nb_cmds

        # Extract info from Build Version
        if binary.has_build_version():
            build = binary.build_version
            binary_details["platform"] = build.platform.__name__
            binary_details["minOSVersion"] = build.minos
            binary_details["sdkVersion"] = build.sdk

            tools = []
            for tool in build.tools:
                tools.append({"tool": tool.tool, "version": tool.version})
            binary_details["tools"]: tools

        file_details["binaries"].append(binary_details)

    return file_details
