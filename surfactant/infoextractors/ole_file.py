# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Any, Dict, List, Tuple

import olefile

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return filetype == "OLE"


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    software_field_hints: List[Tuple[str, object, int]],
) -> object:
    if not supports_file(filetype):
        return None
    ole_info = extract_ole_info(filename)
    if ole_info and "ole" in ole_info:
        if "subject" in ole_info["ole"]:
            software_field_hints.append(("name", ole_info["ole"]["subject"], 80))
        if "revision_number" in ole_info["ole"]:
            software_field_hints.append(("version", ole_info["ole"]["revision_number"], 80))
        if "author" in ole_info["ole"]:
            software_field_hints.append(("vendor", ole_info["ole"]["author"], 80))
        if "comments" in ole_info["ole"]:
            software_field_hints.append(("comments", ole_info["ole"]["comments"], 80))
    return ole_info


def extract_ole_info(filename: str) -> object:
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
