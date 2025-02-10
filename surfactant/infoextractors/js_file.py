# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# from pluggy import get_plugin_manager, get_plugin
from loguru import logger

import surfactant.plugin
from surfactant.database_manager.database_utils import (
    BaseDatabaseManager,
    calculate_hash,
    download_database,
    load_hash_and_timestamp,
    save_hash_and_timestamp,
)
from surfactant.sbomtypes import SBOM, Software

# Global configuration
DATABASE_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "js_file"


class RetireJSDatabaseManager(BaseDatabaseManager):
    """Manages the retirejs library database."""

    def __init__(self):
        name = short_name()  # use 'name = __name__', if short_name is not implemented

        super().__init__(
            pattern_key="js_library_patterns",
            pattern_file="js_library_patterns.json",
            source="jsfile.retirejs",
            plugin_name=name,
        )

    @property
    def data_dir(self) -> Path:
        """Returns the base directory for storing JavaScript library database files."""
        return super().data_dir / "js_library_patterns"

    def parse_raw_data(self, raw_data: str) -> Dict[str, Any]:
        """Parses raw RetireJS database data into a structured format."""
        retirejs_db = json.loads(raw_data)
        clean_db = {}
        reg_temp = "\u00a7\u00a7version\u00a7\u00a7"
        version_regex = r"\d+(?:\.\d+)*"

        for library, lib_entry in retirejs_db.items():
            if "extractors" in lib_entry:
                clean_db[library] = {}
                for entry in ["filename", "filecontent", "hashes"]:
                    if entry in lib_entry["extractors"]:
                        clean_db[library][entry] = [
                            reg.replace(reg_temp, version_regex)
                            for reg in lib_entry["extractors"][entry]
                        ]
        return clean_db


js_db_manager = RetireJSDatabaseManager()


def supports_file(filetype) -> bool:
    return filetype == "JAVASCRIPT"


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_js_info(filename)


def extract_js_info(filename: str) -> object:
    js_info: Dict[str, Any] = {"jsLibraries": []}
    js_lib_database = js_db_manager.get_database()

    if js_lib_database is None:
        return None

    # Try to match file name
    libs = match_by_attribute("filename", filename, js_lib_database)
    if len(libs) > 0:
        js_info["jsLibraries"] = libs
        return js_info

    # Try to match file contents
    try:
        with open(filename, "r") as js_file:
            filecontent = js_file.read()
        libs = match_by_attribute("filecontent", filecontent, js_lib_database)
        js_info["jsLibraries"] = libs
    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")
    except UnicodeDecodeError:
        logger.warning(f"File does not appear to be UTF-8: {filename}")
    return js_info


def match_by_attribute(attribute: str, content: str, database: Dict) -> List[Dict]:
    libs = []
    for name, library in database.items():
        if attribute in library:
            for pattern in library[attribute]:
                matches = re.search(pattern, content)
                if matches:
                    if len(matches.groups()) > 0:
                        libs.append({"library": name, "version": matches.group(1)})
                        # skip remaining patterns, move on to the next library
                        break
    return libs


def strip_irrelevant_data(retirejs_db: dict) -> dict:
    clean_db = {}
    reg_temp = "\u00a7\u00a7version\u00a7\u00a7"
    version_regex = r"\d+(?:\.\d+)*"
    for library, lib_entry in retirejs_db.items():
        if "extractors" in lib_entry:
            clean_db[library] = {}
            patterns = lib_entry["extractors"]
            possible_entries = [
                "filename",
                "filecontent",
                "hashes",
            ]
            for entry in possible_entries:
                if entry in patterns:
                    entry_list = []
                    for reg in patterns[entry]:
                        entry_list.append(reg.replace(reg_temp, version_regex))
                    clean_db[library][entry] = entry_list
    return clean_db


@surfactant.plugin.hookimpl
def update_db() -> str:
    raw_data = download_database(DATABASE_URL)
    if raw_data is not None:
        js_db_manager.new_hash = calculate_hash(raw_data)
        current_data = load_hash_and_timestamp(
            js_db_manager.database_version_file_path,
            js_db_manager.pattern_key,
            js_db_manager.pattern_file,
        )
        if current_data and js_db_manager.new_hash == current_data.get("hash"):
            return "No update occurred. Database is up-to-date."

        retirejs = json.loads(raw_data)
        cleaned = strip_irrelevant_data(retirejs)
        js_db_manager.download_timestamp = datetime.now(timezone.utc)

        path = js_db_manager.data_dir
        path.mkdir(parents=True, exist_ok=True)
        json_file_path = path / js_db_manager.pattern_file
        with open(json_file_path, "w") as f:
            json.dump(cleaned, f, indent=4)

        save_hash_and_timestamp(
            js_db_manager.database_version_file_path, js_db_manager.pattern_info
        )
        return "Update complete."
    return "No update occurred."


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None):
    """
    Initialization hook to load the JavaScript library database.

    Args:
        command_name (Optional[str], optional): The name of the command invoking the initialization.
            If set to "update-db", the database will not be loaded.

    Returns:
        None
    """
    if command_name != "update-db":  # Do not load the database if only updating the database.
        logger.info("Initializing js_file...")
        js_db_manager.load_db()
        logger.info("Initializing js_file complete.")
