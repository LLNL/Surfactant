# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from loguru import logger

import surfactant.plugin
from surfactant.database_manager.database_utils import (
    BaseDatabaseManager,
    DatabaseConfig,
    calculate_hash,
    download_database,
    load_db_version_metadata,
    save_db_version_metadata,
)
from surfactant.sbomtypes import SBOM, Software

# Global configuration
DATABASE_URL = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "native_lib_file"


class EmbaNativeLibDatabaseManager(BaseDatabaseManager):
    """Manages the EMBA Native Library database."""

    def __init__(self):
        name = short_name()  # use 'name = __name__', if short_name is not implemented

        config = DatabaseConfig(
            version_file_name="native_lib_patterns",
            database_key="emba",
            database_file="native_lib_patterns_emba.json",
            source=DATABASE_URL,
            plugin_name=name,
        )

        super().__init__(config)

    @property
    def data_dir(self) -> Path:
        """Returns the base directory for storing Native Library database files."""
        return super().data_dir / "native_lib_patterns"

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
                logger.warning(f"Skipping malformed line: {line}")
                continue

            lib_name = fields[0]
            filecontent = fields[3].strip('"')

            try:
                re.compile(filecontent.encode("utf-8"))  # Validate regex
                database.setdefault(lib_name, {"filename": [], "filecontent": []})
                database[lib_name]["filecontent"].append(filecontent)
            except re.error as e:
                logger.error(f"Invalid regex in file content: {filecontent}. Error: {e}")

        return database


native_lib_manager = EmbaNativeLibDatabaseManager()


def supports_file(filetype: str) -> bool:
    return filetype in ("PE", "ELF", "MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64")


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
        logger.warning(f"File not found: {filename}")

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
                    logger.error(f"Error parsing file content regexp {filecontent}: {e}")

    return database


@surfactant.plugin.hookimpl
def update_db() -> str:
    # Step 1: Download the raw database content
    file_content = download_database(DATABASE_URL)
    if not file_content:
        return "No update occurred. Failed to download database."

    # Step 2: Calculate the hash of the downloaded content
    new_hash = calculate_hash(file_content)

    # Step 3: Load the current database metadata (source, hash and timestamp)
    current_data = load_db_version_metadata(
        native_lib_manager.database_version_file_path,
        native_lib_manager.config.database_key,
        native_lib_manager.config.database_file,
    )

    # Step 4: Check if the database is already up-to-date
    if current_data and new_hash == current_data.get("hash"):
        return "No update occurred. Database is up-to-date."

    # Step 5: Parse the raw database content
    parsed_data = parse_emba_cfg_file(file_content)

    # Step 6: Clean the parsed data
    for _, value in parsed_data.items():
        filecontent_list = value["filecontent"]

        for i, pattern in enumerate(filecontent_list):
            if pattern.startswith("^"):
                filecontent_list[i] = pattern[1:]

            if not pattern.endswith("\\$"):
                if pattern.endswith("$"):
                    filecontent_list[i] = pattern[:-1]

    # Step 7: Save the cleaned database to disk
    path = native_lib_manager.data_dir
    path.mkdir(parents=True, exist_ok=True)
    native_lib_file = path / native_lib_manager.config.database_file
    with open(native_lib_file, "w") as json_file:
        json.dump(parsed_data, json_file, indent=4)

    # Step 8: Update the hash and timestamp metadata
    native_lib_manager.new_hash = new_hash
    native_lib_manager.download_timestamp = datetime.now(timezone.utc).isoformat()
    save_db_version_metadata(
        native_lib_manager.database_version_file_path, native_lib_manager.database_info
    )

    return "Update complete."


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
