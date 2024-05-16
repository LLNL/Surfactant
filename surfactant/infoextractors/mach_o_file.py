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
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_mach_o_info(filename)


def extract_mach_o_info(filename: str) -> object:
    try:
        binaries = lief.MachO.parse(filename)
    except OSError:
        return {}
    file_details: Dict[str:Any] = {"OS": "MacOS"}
    file_details["numBinaries"] = binaries.size
    file_details["binaries"] = []

    # Iterate over all binaries in the FAT binary
    for binary in binaries:
        binary_details = {}
        binary_details["format"] = binary.format.__name__

        # Extract info from the header
        header = binary.header
        header_details = {}
        header_details["cpuType"] = header.cpu_type.value
        header_details["cpuSubtype"] = header.cpu_subtype
        header_details["fileType"] = header.file_type.value
        header_details["flags"] = [flag.__name__ for flag in header.flags_list]
        header_details["numCommands"] = header.nb_cmds
        binary_details["header"] = header_details

        # Extract info from build version
        if binary.has_build_version:
            build = binary.build_version
            build_details = {}
            build_details["platform"] = build.platform.value
            build_details["minOSVersion"] = build.minos
            build_details["sdkVersion"] = build.sdk
            tools = []
            for tool in build.tools:
                tools.append({"tool": tool.tool, "version": tool.version})
            build_details["tools"] = tools
            binary_details["build"] = build_details

        # Extract info from code signature
        signature_details = {}
        if binary.has_code_signature or binary.has_code_signature_dir:
            if binary.has_code_signature:
                signature = binary.code_signature
                signature_details["type"] = "Default"
            else:
                signature = binary.code_signature_dir
                signature_details["type"] = "LC_DYLIB_CODE_SIGN_DRS"
            signature_details["offset"] = signature.data_offset
            signature_details["size"] = signature.data_size
            # If a user configurable setting is enabled to include signature:
            # signature_details["signature"] = signature.content
        else:
            signature_details["type"] = None
        binary_details["codeSignature"] = signature_details

        # Extract library dependencies
        libraries = []
        for library in binary.libraries:
            lib_details = {}
            lib_details["name"] = library.name
            lib_details["currentVersion"] = library.current_version
            lib_details["compatibilityVersion"] = library.compatibility_version
            libraries.append(lib_details)
        binary_details["libraryDependencies"] = libraries

        # rpath info
        if binary.has_rpath:
            binary_details["rpathSelf"] = binary.rpath.path
        rpaths = []
        for rpath in binary.rpaths:
            rpaths.append(rpath.path)
        binary_details["rpaths"] = rpaths

        # dyld info
        dyld = {}
        if binary.has_dylinker:
            dyld["linker"] = binary.dylinker.name
        if binary.has_dyld_exports_trie:
            exports = []
            for export in binary.dyld_exports_trie.exports:
                export_details = {}
                export_details["address"] = export.address
                export_details["kind"] = export.kind.__name__
                exports.append(export)
            dyld["exports"] = exports
        if binary.has_dyld_environment:
            dyld["environment"] = binary.dyld_environment.value
        binary_details["dyld"] = dyld

        # encryption info
        if binary.has_encryption_info:
            encryption = binary.encryption_info
            encryption_details = {}
            encryption_details["system"] = encryption.crypt_id
            encryption_details["offset"] = encryption.crypt_offset
            encryption_details["size"] = encryption.crypt_size
            binary_details["encryption"] = encryption_details

        file_details["binaries"].append(binary_details)
    return file_details
