import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
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
    native_lib_patterns = pathlib.Path(__file__).parent / "native_lib_patterns.json"

    # Load regex patterns into database var
    try:
        with open(native_lib_patterns, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {native_lib_patterns}")
        return None

    # Match based on filename
    filenames_list = match_by_attribute("filename", filename, database)
    if len(filenames_list) > 0:
        #native_lib_info["nativeLibraries"] = filenames_list
        native_lib_info["nativeLibraries"].extend(filenames_list)

    #Match based on filecontent
    try:
        with open(filename, "rb") as native_file:
            filecontent = native_file.read()
        filecontent_list = match_by_attribute("filecontent", filecontent, database)

        #this overwrites the list, need to extend the list
        #native_lib_info["nativeLibraries"] = filecontent_list
        native_lib_info["nativeLibraries"].extend(filecontent_list)

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
                    matches = re.search(pattern.encode('utf-8'), content)
                try:
                    if matches:
                        #libs.append({"library": name, "version": matches.group(1)})
                        libs.append({"library": name})
                except re.error as e:
                    print(f"Invalid regex filename pattern '{pattern}': {e}")
    return libs
