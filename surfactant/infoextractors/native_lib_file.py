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
from typing import Any, Dict, List, Optional, Union

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.database_manager.database_utils import (
    calculate_hash,
    download_database,
    load_hash_and_timestamp,
    save_hash_and_timestamp,
)
from surfactant.sbomtypes import SBOM, Software

# Global configuration
DATABASE_URL = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"


class NativeLibDatabaseManager:
    def __init__(self) -> None:
        self._native_lib_database: Optional[Dict[str, Any]] = None
        self.database_version_file_path = (
            ConfigManager().get_data_dir_path()
            / "infoextractors"
            / "native_lib_patterns"
            / "native_lib_patterns.toml"
        )
        self.pattern_key = "native_lib_patterns"
        self.pattern_file = "native_lib_patterns.json"
        self.source = "nativefile.emba"
        self.new_hash: Optional[str] = None
        self.download_timestamp: Optional[datetime] = None

    @property
    def native_lib_database(self) -> Optional[Dict[str, Any]]:
        if self._native_lib_database is None:
            self.load_db()
        return self._native_lib_database

    @property
    def pattern_info(self) -> Dict[str, Any]:
        return {
            "pattern_key": self.pattern_key,
            "pattern_file": self.pattern_file,
            "source": self.source,
            "hash_value": self.new_hash,
            "timestamp": self.download_timestamp,
        }

    def load_db(self) -> None:
        native_lib_file = (
            ConfigManager().get_data_dir_path()
            / "infoextractors"
            / "native_lib_patterns"
            / self.pattern_file
        )

        try:
            with open(native_lib_file, "r") as regex:
                self._native_lib_database = json.load(regex)
        except FileNotFoundError:
            logger.warning(
                "Native library pattern could not be loaded. Run `surfactant plugin update-db native_lib_patterns` to fetch the pattern database."
            )
            self._native_lib_database = None

    def get_database(self) -> Optional[Dict[str, Any]]:
        return self.nati_native_lib_databaseve_lib_database


native_lib_manager = NativeLibDatabaseManager()


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
    file_content = download_database(DATABASE_URL)
    if file_content is not None:
        native_lib_manager.new_hash = calculate_hash(file_content)
        current_data = load_hash_and_timestamp(
            native_lib_manager.database_version_file_path,
            native_lib_manager.pattern_key,
            native_lib_manager.pattern_file,
        )
        if current_data and native_lib_manager.new_hash == current_data.get("hash"):
            return "No update occurred. Database is up-to-date."

        parsed_data = parse_emba_cfg_file(file_content)
        for _, value in parsed_data.items():
            filecontent_list = value["filecontent"]

            for i, pattern in enumerate(filecontent_list):
                if pattern.startswith("^"):
                    filecontent_list[i] = pattern[1:]

                if not pattern.endswith("\\$"):
                    if pattern.endswith("$"):
                        filecontent_list[i] = pattern[:-1]

        path = ConfigManager().get_data_dir_path() / "infoextractors" / "native_lib_patterns"
        path.mkdir(parents=True, exist_ok=True)
        native_lib_file = path / native_lib_manager.pattern_file
        with open(native_lib_file, "w") as json_file:
            json.dump(parsed_data, json_file, indent=4)

        native_lib_manager.download_timestamp = datetime.now(timezone.utc)
        save_hash_and_timestamp(
            native_lib_manager.database_version_file_path, native_lib_manager.pattern_info
        )
        return "Update complete."
    return "No update occurred."


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "native_lib_patterns"


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    """
    Initialization hook to load the Nativel library database.

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
