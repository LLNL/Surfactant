# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union

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
from surfactant.utils.ahocorasick import build_regex_literal_matcher

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
        self.ac_filename = None
        self.ac_filecontent = None

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

    def load_db(self) -> Optional[Dict[str, Any]]:
        """Load the database and build the Aho-Corasick automaton for pattern matching."""
        super().load_db()
        if self._database:
            # Build the Aho-Corasick automaton for filename patterns
            filename_patterns = {}
            filecontent_patterns = {}

            for lib_name, lib_data in self._database.items():
                if "filename" in lib_data:
                    for pattern in lib_data["filename"]:
                        pattern_id = (lib_name, "filename", pattern)
                        filename_patterns[pattern_id] = pattern

                if "filecontent" in lib_data:
                    for pattern in lib_data["filecontent"]:
                        pattern_id = (lib_name, "filecontent", pattern)
                        filecontent_patterns[pattern_id] = pattern.encode("utf-8").decode(
                            "unicode_escape"
                        )

            if filename_patterns:
                self.ac_filename = build_regex_literal_matcher(filename_patterns, is_literal=True)

            if filecontent_patterns:
                self.ac_filecontent = build_regex_literal_matcher(
                    filecontent_patterns, is_bytes=True
                )
        return self._database


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

    # Get the appropriate automaton
    if attribute == "filename":
        ac = native_lib_manager.ac_filename
    elif attribute == "filecontent":
        ac = native_lib_manager.ac_filecontent
    else:
        return libs

    # If no automaton available, fall back to old method
    if not ac:
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

    # Use Aho-Corasick for prefix matching
    matched_libraries: Set[str] = set()

    # For filename we can just do direct string matching
    if attribute == "filename":
        if isinstance(content, str):
            potential_matches = ac.search(content)
            for pattern_id, _positions in potential_matches.items():
                lib_name, attr, pattern = pattern_id
                if (
                    attr == attribute
                    and pattern.lower() == content.lower()
                    and lib_name not in matched_libraries
                ):
                    libs.append({"isLibrary": lib_name})
                    matched_libraries.add(lib_name)

    # For file content, we need to search in binary data
    elif attribute == "filecontent":
        if isinstance(content, bytes):
            # Window size for context around matches
            window_size = 4096  # Adjustable based on expected pattern size
            content_length = len(content)
            potential_matches = ac.search(content)
            for pattern_id, positions in potential_matches.items():
                lib_name, attr, pattern = pattern_id
                if attr == attribute and lib_name not in matched_libraries:
                    try:
                        encoded_pattern = pattern.encode("utf-8")

                        # Check each position where the prefix was found
                        for pos in positions:
                            # Calculate start and end for a slice of content around the match position
                            slice_start = max(0, pos - 50)  # Allow some context before match
                            slice_end = min(content_length, pos + window_size)
                            content_slice = content[slice_start:slice_end]

                            # Search only in the slice
                            matches = re.search(encoded_pattern, content_slice)
                            if matches:
                                libs.append({"containsLibrary": lib_name})
                                matched_libraries.add(lib_name)
                                break  # Found one match for this library, no need to check more positions
                    except re.error as e:
                        logger.error(f"Error with regex pattern {pattern}: {e}")

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
    file_content = download_database(DATABASE_URL_EMBA)
    if not file_content:
        return "No update occurred. Failed to download database."

    # Step 2: Calculate the hash of the downloaded content
    new_hash = calculate_hash(file_content)

    # Step 3: Load the current database metadata (source, hash and timestamp)
    current_data = load_db_version_metadata(
        native_lib_manager.database_version_file_path,
        native_lib_manager.config.database_key,
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
    native_lib_file = native_lib_manager.database_file_path
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
