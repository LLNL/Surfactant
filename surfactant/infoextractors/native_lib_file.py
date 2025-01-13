import json
import os
import re
from typing import Any, Dict, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


class NativeLibDatabaseManager():
    def __init__(self):
        self.native_lib_database = None

    def load_db(self) -> None:
        # Load the pattern database once at module import
        native_lib_file = (
            ConfigManager().get_data_dir_path() / "native_lib_patterns" / "emba.json"
        )

        # Load regex patterns into database var
        try:
            with open(native_lib_file, "r") as regex:
                self.native_lib_database = json.load(regex)
        except FileNotFoundError:
            logger.warning(f"File not found for native library detection: {native_lib_patterns}")
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
    if not database:
        return None

    found_libraries = set()
    library_names = []
    contains_library_names = []

    # Match based on filename
    base_filename = os.path.basename(filename)
    filenames_list = match_by_attribute("filename", base_filename, database)
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
        filecontent_list = match_by_attribute("filecontent", filecontent, database)

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
