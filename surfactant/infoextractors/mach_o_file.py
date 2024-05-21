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

    file_details: Dict[str:Any] = {"OS": "MacOS", "numBinaries": binaries.size, "binaries": []}

    # Iterate over all binaries in the FAT binary
    for binary in binaries:
        header = binary.header
        details = {
            "format": binary.format.__name__,
            "header": {
                "cpuType": header.cpu_type.value,
                "cpuSubtype": header.cpu_subtype,
                "fileType": header.file_type.value,
                "flags": [flag.__name__ for flag in header.flags_list],
                "numCommands": header.nb_cmds,
            },
            "build": {},
            "signature": {},
            "dependencies": [],
            "rpaths": [],
            "dyld": {},
            "encryption": {},
        }

        # Extract info from build version
        if binary.has_build_version:
            build = binary.build_version
            details["build"] = {
                "platform": build.platform.value,
                "minOSVersion": build.minos,
                "sdkVersion": build.sdk,
                "tools": [],
            }
            for tool in build.tools:
                details["build"]["tools"].append({"tool": tool.tool, "version": tool.version})

        # Extract info from code signature
        if binary.has_code_signature or binary.has_code_signature_dir:
            if binary.has_code_signature:
                signature = binary.code_signature
                signature_type = "Default"
            else:
                signature = binary.code_signature_dir
                signature_type = "LC_DYLIB_CODE_SIGN_DRS"

            details["signature"] = {
                "offset": signature.data_offset,
                "size": signature.data_size,
                "type": signature_type,
                # If a user configurable setting is enabled to include signature contents:
                # "content": signature.content
            }

        # Extract library dependencies
        for library in binary.libraries:
            details["dependencies"].append(
                {
                    "name": library.name,
                    "currentVersion": library.current_version,
                    "compatibilityVersion": library.compatibility_version,
                }
            )

        # rpath info
        if binary.has_rpath:
            for rpath in binary.rpaths:
                details["rpaths"].append(rpath.path)

        # dyld info
        if binary.has_dylinker:
            details["dyld"]["linker"] = binary.dylinker.name
        if binary.has_dyld_environment:
            details["dyld"]["environment"] = binary.dyld_environment.value
        # https://github.com/qyang-nj/llios/blob/main/dynamic_linking/chained_fixups.md
        if binary.has_dyld_info:
            details["dyld"]["info"] = {
                "bindings": [],
                "exports": [],
            }
            bindings = get_bindings(binary.dyld_info.bindings)
            details["dyld"]["info"]["bindings"].append(bindings)
            for export in binary.dyld_info.exports:
                details["dyld"]["info"]["exports"].append(
                    {"address": export.address, "kind": export.kind.__name__}
                )
        elif binary.has_dyld_exports_trie:
            details["dyld"]["exports"] = []
            for export in binary.dyld_exports_trie.exports:
                details["dyld"]["exports"].append(
                    {"address": export.address, "kind": export.kind.__name__}
                )
            if binary.has_dyld_chained_fixups:
                fixups = binary.dyld_chained_fixups
                details["dyld"]["chainedFixups"] = {"chainedStartsInSegment": [], "bindings": []}
                for chainedStarts in fixups.chained_starts_in_segments:
                    details["dyld"]["chainedFixups"]["chainedStartsInSegment"].append(
                        {
                            "maxValidPointer": chainedStarts.max_valid_pointer,
                            "pageSize": chainedStarts.page_size,
                            "pointerFormat": chainedStarts.pointer_format.__name__,
                            "pointerFormatValue": chainedStarts.pointer_format.value,
                            "segment": chainedStarts.segment.name,
                        }
                    )
                bindings = get_bindings(fixups.bindings)
                details["dyld"]["chainedFixups"]["bindings"].append(bindings)

        # encryption info
        if binary.has_encryption_info:
            encryption = binary.encryption_info
            details["encryption"] = {
                "system": encryption.crypt_id,
                "offset": encryption.crypt_offset,
                "size": encryption.crypt_size,
            }
        file_details["binaries"].append(details)
    return file_details


def get_bindings(bindings):
    bindings_info = []
    for binding in bindings:
        info = {
            "addend": binding.addend,
            "address": binding.address,
            "isWeakImport": binding.weak_import,
        }
        if binding.has_library:
            info["library"] = binding.library.name
        if binding.has_segment:
            info["segment"] = binding.segment.name
        bindings_info.append(info)
    return bindings_info
