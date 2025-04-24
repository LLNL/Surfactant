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
from typing import Any, Dict, List, Optional

# from pluggy import get_plugin_manager, get_plugin
from loguru import logger

import surfactant.plugin
from surfactant.database_manager.database_utils import BaseDatabaseManager, DatabaseConfig
from surfactant.sbomtypes import SBOM, Software

# Global configuration
DATABASE_URL_RETIRE_JS = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"
JS_DB_DIR = "js_library_patterns"  # The directory name to store the database toml file and database json files for this module


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "js_file"


class RetireJSDatabaseManager(BaseDatabaseManager):
    """Manages the retirejs library database."""

    def __init__(self):
        name = (
            short_name()
        )  # Set to '__name__' (without quotation marks), if short_name is not implemented

        config = DatabaseConfig(
            database_dir=JS_DB_DIR,  # The directory name to store the database toml file and database json files for this module.
            database_key="retirejs",  # The key for this classes database in the version_info toml file.
            database_file="retirejs_db.json",  # The json file name for the database.
            source=DATABASE_URL_RETIRE_JS,  # The source of the database (put "file" or the source url)
            plugin_name=name,
        )

        super().__init__(config)

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
        logger.warning("File not found: %s", filename)
    except UnicodeDecodeError:
        logger.warning("File does not appear to be UTF-8: %s", filename)
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
    return js_db_manager.download_and_update_database()


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    js_db_manager.initialize_database(command_name)
