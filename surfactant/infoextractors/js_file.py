# Copyright 2023 Lawrence Livermore National Security, LLC
# SEe the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import re
from typing import Any, Dict, List

import click
import requests
from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype) -> bool:
    return filetype == "JAVASCRIPT"


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_js_info(filename)


def extract_js_info(filename: str) -> object:
    js_info: Dict[str, Any] = {"jsLibraries": []}
    js_lib_file = (
        ConfigManager().get_data_dir_path() / "infoextractors" / "js_library_patterns.json"
    )

    # Load expressions from retire.js, should move this file elsewhere
    try:
        path = ConfigManager().get_data_dir_path() / "infoextractors"
        path.mkdir(parents=True, exist_ok=True)
        with open(js_lib_file, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(f"File not found: {js_lib_file}")
        return None

    # Try to match file name
    libs = match_by_attribute("filename", filename, database)
    if len(libs) > 0:
        js_info["jsLibraries"] = libs
        return js_info

    # Try to match file contents
    try:
        with open(filename, "r") as js_file:
            filecontent = js_file.read()
        libs = match_by_attribute("filecontent", filecontent, database)
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


def download_database() -> dict:
    url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"
    response = requests.get(url)
    if response.status_code == 200:
        click.echo("Request successful!")
        return json.loads(response.text)

    if response.status_code == 404:
        click.echo("Resource not found.")
    else:
        click.echo("An error occurred.")

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
def update_db():
    """Retrieves the javascript library CVE database used by retire.js (https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository-master.json) and only keeps the contents under each library's "extractors" section, which contains file hashes and regexes relevant for detecting a specific javascript library by its file name or contents.

    The resulting smaller json is written to js_library_patterns.json in the same directory. This smaller file will be read from to make the checks later on."""
    retirejs = download_database()
    if retirejs is not None:
        cleaned = strip_irrelevant_data(retirejs)
        path = ConfigManager().get_data_dir_path() / "infoextractors"
        path.mkdir(parents=True, exist_ok=True)
        json_file_path = (
            ConfigManager().get_data_dir_path() / "infoextractors" / "js_library_patterns.json"
        )
        with open(json_file_path, "w") as f:
            json.dump(cleaned, f, indent=4)
        return "Update complete."
    return "No update occurred."


@surfactant.plugin.hookimpl
def short_name():
    return "js_file"


def load_db():
    js_lib_file = (
        ConfigManager().get_data_dir_path() / "infoextractors" / "js_library_patterns.json"
    )

    # Load expressions from retire.js, should move this file elsewhere
    try:
        path = ConfigManager().get_data_dir_path() / "infoextractors"
        path.mkdir(parents=True, exist_ok=True)
        with open(js_lib_file, "r") as regex:
            database = json.load(regex)
    except FileNotFoundError:
        logger.warning(
            "Javascript library pattern database database could not be loaded. Run `surfactant plugin update js_file` to fetch the pattern database."
        )
        return None
    return database


js_lib_database = load_db()
