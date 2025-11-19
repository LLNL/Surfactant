# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import requests
import tomlkit
from loguru import logger
from requests.exceptions import RequestException

from surfactant.configmanager import ConfigManager


def download_content(url: str, timeout: int = 10, retries: int = 3) -> Optional[str]:
    """
    Downloads content from a given URL with retry logic and timeout.

    Args:
        url (str): The URL of the content to download.
        timeout (int): The timeout in seconds for each request attempt.
        retries (int): Number of retry attempts for the download.

    Returns:
        Optional[str]: The content as a string if the request is successful,
                       or None if an error occurs.
    """
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                logger.debug("Request successful! URL:{}", url)
                return response.text
            if response.status_code == 404:
                logger.debug("Resource not found. URL: {}", url)
                return None
            logger.debug("Unexpected status code {} for URL: {}", response.status_code, url)
        except RequestException as e:
            logger.debug("Attempt {} - Error fetching URL {}: {}", str(attempt + 1), url, e)

        attempt += 1
        sleep_time = 2**attempt  # exponential backoff
        logger.debug("Retrying in {} seconds...", sleep_time)
        time.sleep(sleep_time)

    return None


def calculate_hash(data: str) -> str:
    """
    Calculate the SHA-256 hash of the given data.

    Args:
        data (str): The input string to hash.

    Returns:
        str: The SHA-256 hash of the input string.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _read_toml_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """
    Read and parse a TOML file.

    Args:
        file_path (Union[str, Path]): The path to the TOML file.

    Returns:
        Optional[Dict[str, Any]]: The parsed TOML data, or None if the file does not exist.
    """
    path = Path(file_path) if not isinstance(file_path, Path) else file_path
    try:
        with path.open("r") as f:
            return tomlkit.load(f)
    except FileNotFoundError:
        return None
    except tomlkit.exceptions.TOMLKitError as e:
        raise ValueError(f"Error parsing TOML file at {file_path}: {e}") from e


def _write_toml_file(file_path: Union[str, Path], data: Dict[str, Any]) -> None:
    """
    Write data to a TOML file.

    Args:
        file_path (Union[str, Path]): The path to the TOML file.
        data (Dict[str, Any]): The data to write to the file.
    """
    path = Path(file_path) if not isinstance(file_path, Path) else file_path
    with path.open("w") as f:
        tomlkit.dump(data, f)


def load_db_version_metadata(
    version_file_path: Union[str, Path], database_key: str
) -> Optional[Dict[str, str]]:
    """
    Load the database version metadata for a specific database from the specified TOML file.

    Args:
        version_file_path (Union[str, Path]): The path to the TOML file that tracks database versions.
        database_key (str): The key identifying the database.

    Returns:
        Optional[Dict[str, str]]: A dictionary with metadata for the database, or None if not found.

        Example structure:
        {
            "retirejs": {
                "file": "js_library_patterns_retirejs.json",
                "source": "https://example.com/source.json",
                "hash": "abc123...",
                "timestamp": "2025-02-10T19:18:34.784116Z"
            },
            "abc": {
                "file": "some_other_library_patterns_abc.json",
                "source": "https://example.com/other_source.json",
                "hash": "def456...",
                "timestamp": "2025-02-10T20:00:00.000000Z"
            }
        }
    """
    db_metadata = _read_toml_file(version_file_path)
    if db_metadata is None:
        return None

    return db_metadata.get(database_key, {})


def save_db_version_metadata(version_info: Union[str, Path], database_info: Dict[str, str]) -> None:
    """
    Save the metadata for a specific database to the specified TOML file.

    Args:
        version_info (Union[str, Path]): The path to the TOML file.
        database_info (Dict[str, str]): A dictionary containing keys:
            - "database_key": The key identifying the database  (e.g., "retirejs")..
            - "database_file": The file name of the database (e.g., "js_library_patterns_retirejs.json").
            - "source": The source URL of the database.
            - "hash_value": The hash value of the database file.
            - "timestamp": The timestamp when the database was downloaded.

    Raises:
        ValueError: If required keys are missing from database_info.
    """
    required_keys = {"database_key", "database_file", "source", "hash_value", "timestamp"}
    if not required_keys.issubset(database_info):
        raise ValueError(f"database_info must contain the keys: {required_keys}")

    db_metadata = _read_toml_file(version_info) or {}
    new_data = {
        database_info["database_key"]: {
            "file": database_info["database_file"],
            "source": database_info["source"],
            "hash": database_info["hash_value"],
            "timestamp": database_info["timestamp"],
        }
    }
    db_metadata.update(new_data)
    _write_toml_file(version_info, db_metadata)


def fetch_db_config() -> dict:
    """
    Load the database_sources.toml from local docs/
    """
    # Get local docs copy in the source tree:
    local = Path(__file__).parents[2] / "docs" / "database_sources.toml"
    return _read_toml_file(local)


def get_source_for(database_category: str, key: str) -> Tuple[Optional[str], Optional[bool], bool]:
    """
    Retrieve the URL and GPL status for a given database category and key.

    Resolution order:
      1. Runtime override in user config.
      2. Local docs/database_sources.toml when running Surfactant from an editable install from a git clone of the Surfactant repo.
      3. ReadTheDocs hosted database_sources.toml file.
      4. Fallback to hard-coded URL in code.

    Returns:
        (url, gpl, overridden):
            url (str or None): The resolved URL.
            gpl (bool or None): True if GPL, False if not, None if unknown.
            overridden (bool): True if user override, False otherwise.
    """
    # 1. Handle user overrides for source URLs
    config_manager = ConfigManager()
    runtime_url = config_manager.get("sources", f"{database_category}.{key}")
    if runtime_url not in ("", [], {}, "[]", "{}", None, "None"):
        # Return the command line override URL if present, with the override flag set to skip GPL check
        return runtime_url, None, True

    # 2. Check local database_sources.toml file for editable/developer installs
    config = fetch_db_config()
    try:
        if config:
            url = config["sources"][database_category][key]
            gpl = config["sources"][database_category].get(key + "_gpl", False)
            return url, gpl, False
        logger.debug("Failed to get local database_sources.toml")
    except KeyError:
        logger.debug("No external override found for [{}].{}", database_category, key)

    # Fallback: hardcoded URL, must prompt if GPL
    return None, None, False


def check_gpl_acceptance(database_category: str, key: str, gpl: bool, overridden: bool) -> bool:
    """
    Check config for GPL acceptance, prompt user if needed. Returns True if download is allowed.
    """
    if not gpl or overridden:
        return True

    config_manager = ConfigManager()

    # Check GPL setting (includes runtime overrides which take precedence)
    gpl_setting = config_manager.get("sources", "gpl_license_ok")
    if gpl_setting in ("always", "a", True):
        return True
    if gpl_setting in ("never", "n", False):
        return False

    # Prompt user if no setting is configured
    return _prompt_user_for_gpl_acceptance(config_manager, database_category, key)


def _prompt_user_for_gpl_acceptance(
    config_manager: ConfigManager, database_category: str, key: str
) -> bool:
    """
    Prompt the user for GPL acceptance and optionally save their preference.

    Returns:
        bool: True if user accepts, False otherwise.
    """
    prompt = (
        f"The pattern database '{key}' in category '{database_category}' is GPL-licensed. "
        "Do you want to download it? [y]es/[n]o/[a]lways/[N]ever: "
    )
    try:
        user_input = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return False

    user_input_lower = user_input.lower()

    # Handle always/never options that update config
    if user_input_lower in ("a", "always"):
        config_manager.set("Settings", "gpl_license_ok", "always")
        return True
    if user_input_lower in ("never") or user_input == "N":
        config_manager.set("Settings", "gpl_license_ok", "never")
        return False

    # Handle yes/no for this time only
    return user_input_lower in ("y", "yes")
