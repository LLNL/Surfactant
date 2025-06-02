# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from typing import Any, Dict, List, Optional, Tuple

from surfactant.infoextractors import file_decompression
import olefile
import pymsi
from loguru import logger
from pymsi.msi.directory import Directory
from pymsi.thirdparty.refinery.cab import CabFolder

import surfactant.plugin
from surfactant.context import ContextEntry
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return filetype == "OLE"


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    software_field_hints: List[Tuple[str, object, int]],
    context_queue: "Queue[ContextEntry]",
    current_context: Optional[ContextEntry],
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

        if ole_info["ole"].get("clsid_type") == "MSI":
            file_decompression.create_extraction(
                filename, context_queue, current_context, extract_msi
            )

    return ole_info


def extract_ole_info(filename: str) -> object:
    file_details: Dict[str, Any] = {}

    with olefile.OleFileIO(filename) as ole:
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

    return file_details


def extract_msi(filename: str, output_folder: str):
    output_folder = Path(output_folder)

    with pymsi.Package(Path(filename)) as package:
        msi = pymsi.Msi(package, True)

        preprocess_msi_decompression(msi)

        extract_msi_directory(msi.root, output_folder)

    logger.info(f"Extracted MSI contents to {output_folder}")


def preprocess_msi_decompression(msi: pymsi.Msi):
    folders: List[CabFolder] = []
    for media in msi.medias.values():
        if media.cabinet and media.cabinet.disks:
            for disk in media.cabinet.disks.values():
                for directory in disk:
                    for folder in directory.folders:
                        if folder not in folders:
                            folders.append(folder)
    logger.debug(f"Found {len(folders)} folders in .cab files")

    def decompress_folder(folder):
        folder.decompress()
        logger.trace(f"Decompressed .cab folder: {folder}")

    # Use ThreadPoolExecutor to speed up decompression.
    # This is especially useful for LZX, which is implemented in pure Python.
    with ThreadPoolExecutor() as executor:
        executor.map(decompress_folder, folders)

    logger.debug("Decompression of .cab folders completed")


def extract_msi_directory(root: Directory, output: Path, is_root: bool = True):
    if not output.exists():
        output.mkdir(parents=True, exist_ok=True)

    for component in root.components.values():
        for file in component.files.values():
            if file.media is None:
                continue
            cab_file = file.resolve()
            (output / file.name).write_bytes(cab_file.decompress())

    for child in root.children.values():
        folder_name = child.name
        if is_root:
            # Currently, folder_names are kept as Directory IDs.
            # These should be later resolved to better paths, however the user sees fit.
            # However, we're currently extracting to a temporary directory, so I don't
            # know how necessary that is right now.
            # https://learn.microsoft.com/en-us/windows/win32/msi/property-reference#system-folder-properties
            if "." in child.id:
                folder_name, guid = child.id.split(".", 1)
                if child.id != folder_name:
                    logger.warning(f"MSI Directory ID '{child.id}' has a GUID suffix ({guid}).")
            else:
                folder_name = child.id
        extract_msi_directory(child, output / folder_name, False)
