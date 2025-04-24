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

from surfactant.database_manager.database_utils import download_content

# URL for the hosted external TOML file on ReadTheDocs
DEFAULT_EXTERNAL_DB_CONFIG_URL = (
    "https://readthedocs.org/projects/surfacet-docs/downloads/latest/database_sources.toml"
)


def fetch_external_db_config(url: str = DEFAULT_EXTERNAL_DB_CONFIG_URL) -> dict:
    content = download_content(url)
    if content is None:
        logging.warning("Failed to download the external database configuration.")
        return {}
    try:
        config = tomlkit.parse(content)
        return config
    except Exception as e:
        logging.warning(f"Error parsing TOML content: {e}")
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
        logging.info(f"No external override found for [{database_category}].{key}")
        return ""
