# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Any, Dict

import olefile

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return filetype == "OLE"


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_ole_info(filename)


def extract_ole_info(filename):
    file_details: Dict[str, Any] = {}

    ole = olefile.OleFileIO(filename)
    md = ole.get_metadata()
    file_details["ole"] = {}

    # to check if an OLE is an MSI file, check the root storage object CLSID
    # {000c1084-0000-0000-c000-000000000046}	MSI
    # {000c1086-0000-0000-c000-000000000046}    Windows Installer Patch MSP
    # extensions are typically .msi and .msp for files with these two clsid's
    # less common would be a .msm (merge) with the same clsid as MSI
    # as well as .mst (transform) with a clsid of 000c1082
    if ole.root and hasattr(ole.root, "clsid"):
        file_details["ole"]["clsid"] = str(ole.root.clsid).lower()
        if file_details["ole"]["clsid"] == "000c1082-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MST"
        if file_details["ole"]["clsid"] == "000c1084-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MSI"  # or msm, depending on file extension
        if file_details["ole"]["clsid"] == "000c1086-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MSP"

    for prop in md.SUMMARY_ATTRIBS:
        if value := getattr(md, prop, None):
            if isinstance(value, bytes):
                file_details["ole"][prop] = value.decode("unicode_escape")
            else:
                file_details["ole"][prop] = str(value)
    ole.close()
    return file_details
