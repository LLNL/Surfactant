import json
import os
import re
from typing import Any, Dict, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "native_lib_patterns"


def load_pattern_db():
    # Load regex patterns into database var
    try:
        with open(native_lib_patterns, "r") as regex:
            emba_patterns = json.load(regex)
            return emba_patterns
    except FileNotFoundError:
        logger.warning(f"File not found for native library detection: {native_lib_patterns}")
        return None


# Load the pattern database once at module import
native_lib_patterns = ConfigManager().get_data_dir_path() / "native_lib_patterns" / "emba.json"
database = load_pattern_db()


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
    for name, library in patterns_database.items():
        if attribute in library:
            for pattern in library[attribute]:
                if attribute == "filename":
                    if name == content:
                        libs.append({"isLibrary": name})

                elif attribute == "filecontent":
                    matches = re.search(pattern.encode("utf-8"), content)
                    if matches:
                        libs.append({"containsLibrary": name})
    return libs
