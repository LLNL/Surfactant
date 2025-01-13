import json
import os
import re
from typing import Any, Dict, List, Optional

import requests
from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


class NativeLibDatabaseManager:
    def __init__(self):
        self.native_lib_database = None

    def load_db(self) -> None:
        # Load the pattern database once at module import
        native_lib_file = ConfigManager().get_data_dir_path() / "native_lib_patterns" / "emba.json"

        # Load regex patterns into database var
        try:
            with open(native_lib_file, "r") as regex:
                self.native_lib_database = json.load(regex)
        except FileNotFoundError:
            logger.warning(
                "Native library pattern could not be loaded. Run `surfactant plugin update-db native_lib_patterns` to fetch the pattern database."
            )
            self.native_lib_database = None

    def get_database(self) -> Optional[Dict[str, Any]]:
        return self.native_lib_database


native_lib_manager = NativeLibDatabaseManager()


def supports_file(filetype) -> bool:
    return filetype in ("PE", "ELF", "MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)


def extract_native_lib_info(filename):
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    native_lib_database = native_lib_manager.get_database()

    if native_lib_database is None:
        return None

    found_libraries = set()
    library_names = []
    contains_library_names = []

    # Match based on filename
    base_filename = os.path.basename(filename)
    filenames_list = match_by_attribute("filename", base_filename, native_lib_database)
    if len(filenames_list) > 0:
        for match in filenames_list:
            library_name = match["isLibrary"]
            if library_name not in found_libraries:
                library_names.append(library_name)
                found_libraries.add(library_name)

    # Match based on filecontent
    try:
        with open(filename, "rb") as native_file:
            filecontent = native_file.read()
        filecontent_list = match_by_attribute("filecontent", filecontent, native_lib_database)

        # Extend the list and add the new libraries found
        for match in filecontent_list:
            library_name = match["containsLibrary"]
            if library_name not in found_libraries:
                contains_library_names.append(library_name)
                found_libraries.add(library_name)

    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")

    # Create the single entry for isLibrary
    if library_names:
        native_lib_info["nativeLibraries"].append({"isLibrary": library_names})

    # Create the single entry for containsLibrary
    if contains_library_names:
        native_lib_info["nativeLibraries"].append({"containsLibrary": contains_library_names})

    return native_lib_info


def match_by_attribute(attribute: str, content: str, patterns_database: Dict) -> List[Dict]:
    libs = []
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


def download_database() -> Optional[Dict[str, Any]]:
    emba_database_url = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"
    response = requests.get(emba_database_url)
    if response.status_code == 200:
        logger.info("Request successful!")
        return response.text

    if response.status_code == 404:
        logger.error("Resource not found.")
    else:
        logger.error("An error occurred.")

    return None


def parse_cfg_file(content):
    database = {}
    lines = content.splitlines()
    filtered_lines = []

    for line in lines:
        if not (line.startswith("#") or line.startswith("identifier")):
            filtered_lines.append(line)

    for line in filtered_lines:
        line = line.strip()

        # Split by semicolons
        fields = line.split(";")

        # Name of library
        lib_name = fields[0]

        # Empty filename because EMBA doesn't need filename patterns
        name_patterns = []

        # Check if it starts with one double quote and ends with two double quotes
        if fields[3].startswith('"') and fields[3].endswith('""'):
            filecontent = fields[3][1:-1]
        elif fields[3].endswith('""'):
            filecontent = fields[3][:-1]
        else:
            filecontent = fields[3].strip('"')

        # Create a dictionary for this entry and add it to the database
        # Strict mode is deprecated so those entries will be matched just by filename
        if fields[1] == "" or fields[1] == "strict":
            if fields[1] == "strict":
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": [lib_name],
                        "filecontent": [],
                    }
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
    file_content = download_database()
    if file_content is not None:
        parsed_data = parse_cfg_file(file_content)
        for _, value in parsed_data.items():
            filecontent_list = value["filecontent"]

            # Remove leading ^ from each string in the filecontent list
            for i, pattern in enumerate(filecontent_list):  # Use enumerate to get index and value
                if pattern.startswith("^"):
                    filecontent_list[i] = pattern[1:]

                if not pattern.endswith("\\$"):
                    if pattern.endswith("$"):
                        filecontent_list[i] = pattern[:-1]

        path = ConfigManager().get_data_dir_path() / "native_lib_patterns"
        path.mkdir(parents=True, exist_ok=True)
        native_lib_file = ConfigManager().get_data_dir_path() / "native_lib_patterns" / "emba.json"
        with open(native_lib_file, "w") as json_file:
            json.dump(parsed_data, json_file, indent=4)
        return "Update complete."
    return "No update occurred."


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "native_lib_patterns"


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None):
    """
    Initialization hook to load the native lib file.

    Args:
        command_name (Optional[str], optional): The name of the command invoking the initialization.
            If set to "update-db", the database will not be loaded.

    Returns:
        None
    """
    if command_name != "update-db":  # Do not load the database if only updating the database.
        logger.info("Initializing native_lib_file...")
        native_lib_manager.load_db()
        logger.info("Initializing native_lib_file complete.")
