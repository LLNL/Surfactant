import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant.filetypeid import id_magic
#from enum import Enum, auto

def supports_file(filetype) -> bool:
    return filetype in ("PE", "ELF", "MACHO32", "MACHO64")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)

def extract_native_lib_info(filename):
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    native_lib_file = pathlib.Path(__file__).parent / "native_lib_patterns.json"

    try:
        with open(native_lib_file, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {native_lib_file}")
        return None