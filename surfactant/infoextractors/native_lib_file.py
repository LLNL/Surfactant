import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant.configmanager import ConfigManager
from surfactant.filetypeid import id_magic


def supports_file(filetype) -> bool:
    return filetype in ("PE", "ELF", "MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)


def extract_native_lib_info(filename):
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    #native_lib_patterns = pathlib.Path(__file__).parent / "native_lib_patterns.json"
    native_lib_patterns = ConfigManager().get_data_dir_path() / "native_lib_patterns" / "emba.json"

    # Load regex patterns into database var
    try:
        with open(native_lib_patterns, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {native_lib_patterns}")
        return None

    found_libraries = set()

    # Match based on filename
    filenames_list = match_by_attribute("filename", filename, database)
    if len(filenames_list) > 0:
        for match in filenames_list:
            library_name = match["library"]
            if library_name not in found_libraries:
                native_lib_info["nativeLibraries"].append(match)
                found_libraries.add(library_name)

    # Match based on filecontent
    try:
        with open(filename, "rb") as native_file:
            filecontent = native_file.read()
        filecontent_list = match_by_attribute("filecontent", filecontent, database)

        # Extend the list and add the new libraries found
        for match in filecontent_list:
            library_name = match["library"]
            if library_name not in found_libraries:
                native_lib_info["nativeLibraries"].append(match)
                found_libraries.add(library_name)

    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")

    return native_lib_info


def match_by_attribute(attribute: str, content: str, database: Dict) -> List[Dict]:
    libs = []
    for name, library in database.items():
        if attribute in library:
            for pattern in library[attribute]:
                if attribute == "filename":
                    matches = re.search(pattern, content)
                else:
                    print(f"problem pattern: {pattern}")
                    matches = re.search(pattern.encode('utf-8'), content)
                try:
                    if matches:
                        libs.append({"library": name})
                except re.error as e:
                    print(f"Invalid regex filename pattern '{pattern}': {e}")
    return libs
