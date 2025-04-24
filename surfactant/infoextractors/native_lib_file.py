# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import re
from typing import Any, Dict, List, Optional, Union

from loguru import logger

import surfactant.plugin
from surfactant.database_manager.database_utils import BaseDatabaseManager, DatabaseConfig
from surfactant.sbomtypes import SBOM, Software

# Global configuration
DATABASE_URL_EMBA = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"
NATIVE_DB_DIR = "native_library_patterns"  # The directory name to store the database toml file and database json files for this module


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "native_lib_file"


class EmbaNativeLibDatabaseManager(BaseDatabaseManager):
    """Manages the EMBA Native Library database."""

    def __init__(self):
        name = (
            short_name()
        )  # Set to '__name__' (without quotation marks), if short_name is not implemented

        config = DatabaseConfig(
            database_dir=NATIVE_DB_DIR,  # The directory name to store the database toml file and database json files for this module.
            database_key="emba",  # The key for this classes database in the version_info toml file.
            database_file="emba_db.json",  # The json file name for the database.
            source=DATABASE_URL_EMBA,  # The source of the database (put "file" or the source url)
            plugin_name=name,
        )

        super().__init__(config)

    def parse_raw_data(self, raw_data: str) -> Dict[str, Any]:
        """Parses raw EMBA configuration file into a structured database."""
        database = {}
        lines = [
            line.strip()
            for line in raw_data.splitlines()
            if line.strip() and not line.startswith("#")
        ]

        for line in lines:
            fields = line.split(";")
            if len(fields) < 4:
                logger.warning("Skipping malformed line: %s", line)
                continue

            lib_name = fields[0]
            filecontent = fields[3].strip('"')

            try:
                re.compile(filecontent.encode("utf-8"))  # Validate regex
                database.setdefault(lib_name, {"filename": [], "filecontent": []})
                database[lib_name]["filecontent"].append(filecontent)
            except re.error as e:
                logger.error("Invalid regex in file content: %s. Error: %s", filecontent, e)

        return database


native_lib_manager = EmbaNativeLibDatabaseManager()


def supports_file(filetype: str) -> bool:
    return filetype in ("PE", "ELF", "MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64", "UIMAGE")


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str
) -> Optional[Dict[str, Any]]:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)


def extract_native_lib_info(filename: str) -> Optional[Dict[str, Any]]:
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    native_lib_database = native_lib_manager.get_database()

    if native_lib_database is None:
        return None

    found_libraries: set = set()
    library_names: List[str] = []
    contains_library_names: List[str] = []

    base_filename = os.path.basename(filename)
    filenames_list = match_by_attribute("filename", base_filename, native_lib_database)
    if len(filenames_list) > 0:
        for match in filenames_list:
            library_name = match["isLibrary"]
            if library_name not in found_libraries:
                library_names.append(library_name)
                found_libraries.add(library_name)

    try:
        with open(filename, "rb") as native_file:
            filecontent = native_file.read()
        filecontent_list = match_by_attribute("filecontent", filecontent, native_lib_database)

        for match in filecontent_list:
            library_name = match["containsLibrary"]
            if library_name not in found_libraries:
                contains_library_names.append(library_name)
                found_libraries.add(library_name)

    except FileNotFoundError:
        logger.warning("File not found: %s", filename)

    if library_names:
        native_lib_info["nativeLibraries"].append({"isLibrary": library_names})

    if contains_library_names:
        native_lib_info["nativeLibraries"].append({"containsLibrary": contains_library_names})

    return native_lib_info


def match_by_attribute(
    attribute: str, content: Union[str, bytes], patterns_database: Dict[str, Any]
) -> List[Dict[str, Any]]:
    libs: List[Dict[str, str]] = []
    for lib_name, lib_info in patterns_database.items():
        if attribute in lib_info:
            for pattern in lib_info[attribute]:
                if attribute == "filename":
                    if pattern.lower() == content.lower():
                        libs.append({"isLibrary": lib_name})

                elif attribute == "filecontent":
                    matches = re.search(pattern.encode("utf-8"), content)
                    if matches:
                        libs.append({"containsLibrary": lib_name})
    return libs


def parse_emba_cfg_file(content: str) -> Dict[str, Dict[str, List[str]]]:
    database: Dict[str, Dict[str, List[str]]] = {}
    lines = content.splitlines()
    filtered_lines: List[str] = []

    for line in lines:
        if not (line.startswith("#") or line.startswith("identifier")):
            filtered_lines.append(line)

    for line in filtered_lines:
        line = line.strip()

        fields = line.split(";")

        lib_name = fields[0]

        name_patterns: List[str] = []

        if fields[3].startswith('"') and fields[3].endswith('""'):
            filecontent = fields[3][1:-1]
        elif fields[3].endswith('""'):
            filecontent = fields[3][:-1]
        else:
            filecontent = fields[3].strip('"')

        if fields[1] == "" or fields[1] == "strict":
            if fields[1] == "strict":
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": [lib_name],
                        "filecontent": [],
                    }
                else:
                    if lib_name not in database[lib_name]["filename"]:
                        database[lib_name]["filename"].append(lib_name)
            else:
                try:
                    re.search(filecontent.encode("utf-8"), b"")
                    if lib_name not in database:
                        database[lib_name] = {
                            "filename": name_patterns,
                            "filecontent": [filecontent],
                        }
                    else:
                        database[lib_name]["filecontent"].append(filecontent)
                except re.error as e:
                    logger.error("Error parsing file content regexp %s: %s", filecontent, e)

    return database


@surfactant.plugin.hookimpl
def update_db() -> str:
    return native_lib_manager.download_and_update_database()


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    """
    Initialization hook to load the native library database.

    Args:
        command_name (Optional[str], optional): The name of the command invoking the initialization.
            If set to "update-db", the database will not be loaded.

    Returns:
        None
    """
    if command_name != "update-db":
        logger.info("Initializing native_lib_file...")
        native_lib_manager.load_db()
        logger.info("Initializing native_lib_file complete.")
