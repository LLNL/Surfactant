# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import toml
from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


class JSDatabaseManager:
    def __init__(self):
        self.js_lib_database = None
        self.hash_file_path = (
            ConfigManager().get_data_dir_path() / "infoextractors" / "js_library_patterns.toml"
        )

    def load_db(self) -> None:
        js_lib_file = (
            ConfigManager().get_data_dir_path() / "infoextractors" / "js_library_patterns.json"
        )

        try:
            with open(js_lib_file, "r") as regex:
                self.js_lib_database = json.load(regex)
        except FileNotFoundError:
            logger.warning(
                "Javascript library pattern database could not be loaded. Run `surfactant plugin update-db js_file` to fetch the pattern database."
            )
            self.js_lib_database = None

    def get_database(self) -> Optional[Dict[str, Any]]:
        return self.js_lib_database

    def calculate_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def load_hash_and_timestamp(self) -> Optional[Dict[str, str]]:
        try:
            with open(self.hash_file_path, "r") as f:
                hash_data = toml.load(f)
                return hash_data.get("js_library_patterns", {}).get("js_library_patterns.json")
        except FileNotFoundError:
            return None

    def save_hash_and_timestamp(self, hash_value: str, timestamp: str) -> None:
        # Try to load existing data
        try:
            with open(self.hash_file_path, "r") as f:
                hash_data = toml.load(f)
        except FileNotFoundError:
            # If the file does not exist, start with an empty dictionary
            hash_data = {}

        # Prepare the new data to be added/updated
        new_data = {
            "js_library_patterns": {
                "js_library_patterns.json": {
                    "source": "jsfile.retirejs",
                    "hash": hash_value,
                    "timestamp": timestamp,
                }
            }
        }

        # Update the existing data with the new data
        if "js_library_patterns" in hash_data:
            hash_data["js_library_patterns"].update(new_data["js_library_patterns"])
        else:
            hash_data.update(new_data)

        # Save the updated data back to the file
        with open(self.hash_file_path, "w") as f:
            toml.dump(hash_data, f)


js_db_manager = JSDatabaseManager()


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


def download_database() -> Optional[str]:
    url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"
    response = requests.get(url)
    if response.status_code == 200:
        logger.info("Request successful!")
        return response.text

    if response.status_code == 404:
        logger.error("Resource not found.")
    else:
        logger.error("An error occurred.")

    return None


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
    raw_data = download_database()
    if raw_data is not None:
        new_hash = js_db_manager.calculate_hash(raw_data)
        current_data = js_db_manager.load_hash_and_timestamp()
        if current_data and new_hash == current_data.get("hash"):
            return "No update occurred. Database is up-to-date."

        retirejs = json.loads(raw_data)
        cleaned = strip_irrelevant_data(retirejs)
        download_timestamp = datetime.now().isoformat()

        path = ConfigManager().get_data_dir_path() / "infoextractors"
        path.mkdir(parents=True, exist_ok=True)
        json_file_path = path / "js_library_patterns.json"
        with open(json_file_path, "w") as f:
            json.dump(cleaned, f, indent=4)

        js_db_manager.save_hash_and_timestamp(new_hash, download_timestamp)
        return "Update complete."
    return "No update occurred."


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "js_file"


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
