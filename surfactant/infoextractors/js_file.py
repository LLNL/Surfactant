# Copyright 2023 Lawrence Livermore National Security, LLC
# SEe the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import pathlib
import re
from typing import Any, Dict, Tuple

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return filetype == "JAVASCRIPT"


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str
) -> object:
    if not supports_file(filetype):
        return None
    return extract_js_info(filename)


def extract_js_info(filename):
    js_info: Dict[str, Any] = {"Library": {}}
    js_lib_file = pathlib.Path(__file__).parent / "js_libraries.regex"

    # Load expressions from retire.js, should move this file elsewhere
    try:
        with open(js_lib_file, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {js_lib_file}")
        return None

    # Try to match file name
    ver, lib = match_by_attribute("filename", filename, database)
    if lib is not None:
        js_info["Library"] = lib
        js_info["Version"] = ver
        return js_info

    # Try to match file contents
    try:
        with open(filename, "r") as js_file:
            filecontent = js_file.read()
        ver, lib = match_by_attribute("filecontent", filecontent, database)
        if lib is not None:
            js_info["Library"] = lib
            js_info["Version"] = ver
    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")
    return js_info


def match_by_attribute(
    attribute: str, content: str, database: Dict
) -> Tuple[str, str]:
    for name, library in database.items():
        if attribute in library:
            for pattern in library[attribute]:
                matches = re.search(pattern, content)
                if matches:
                    if len(matches.groups()) > 0:
                        return (matches.group(1), name)
                    return ("None Found", name)
    return (None, None)
