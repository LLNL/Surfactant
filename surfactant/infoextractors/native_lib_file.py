import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant.filetypeid import id_magic

def supports_file(filetype) -> bool:
    # if filetype == "PE":
    #     return filetype == "PE"
    
    # if filetype == "ELF":
    #     return filetype == "ELF"
    
    # if filetype == "MACH-O":
    #     return filetype == "MACH-O"

    return identify_file_type(filetype)

@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)

def extract_native_lib_info(filename):
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    native_lib_file = pathlib.Path(__file__).parent / "native_lib_patterns.cfg"

    try:
        with open(native_lib_file, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {native_lib_file}")
        return None