# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# surfactant/database_manager/external_db_config.py

import logging
import tomlkit
from surfactant.database_manager.database_utils import download_content, _read_toml_file

# URL for the hosted external TOML file on ReadTheDocs
DEFAULT_EXTERNAL_DB_CONFIG_URL = (
    "https://readthedocs.org/projects/surfacet-docs/downloads/latest/database_sources.toml"
)


def fetch_external_db_config(url: str = DEFAULT_EXTERNAL_DB_CONFIG_URL) -> dict:
    """
    Download and parse the external TOML file containing database source overrides.
    Returns an empty dict on failure.
    """
    content = download_content(url)
    try:
        if content is not None:
            config = tomlkit.parse(content)
            return config
    except tomlkit.exceptions.ParseError as e:
        logging.warning("Error parsing TOML content: %s", e)
    return {}


def get_source_for(database_category: str, key: str) -> str:
    """
    Retrieve the URL for a given database category and key.

    Args:
        database_category (str): The category corresponding to a folder (e.g., 'js_library_patterns').
        key (str): The specific key for the database (e.g., 'retirejs').

    Returns:
        str: The URL from the external configuration if available; otherwise, an empty string.
    """
    config = fetch_external_db_config()
    try:
        return config["sources"][database_category][key]
    except KeyError:
        logging.info("No external override found for [%s].%s", database_category, key)
        return ""
