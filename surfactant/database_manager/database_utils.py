# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests
import tomlkit
from loguru import logger
from requests.exceptions import RequestException

from surfactant.configmanager import ConfigManager


@dataclass
class DatabaseConfig:
    version_file_name: str
    database_key: str
    database_file: str
    source: str
    plugin_name: Optional[str]


class BaseDatabaseManager(ABC):
    """Abstract base class for managing pattern databases."""

    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.new_hash: Optional[str] = None
        self.download_timestamp: Optional[str] = None
        self._database: Optional[Dict[str, Any]] = None

    @property
    @abstractmethod
    def data_dir(self) -> Path:
        """Returns the base directory for storing database (.json) and version tracking (TOML) files."""
        return ConfigManager().get_data_dir_path()

    @property
    def database_version_file_path(self) -> Path:
        """Path to the database version file (e.g., TOML file)."""
        return self.data_dir / f"{self.config.version_file_name}.toml"

    @property
    def database_file_path(self) -> Path:
        """Path to the JSON database file."""
        return self.data_dir / self.config.database_file

    @property
    def pattern_info(self) -> Dict[str, Any]:
        """Returns metadata about the database patterns."""
        return {
            "database_key": self.config.database_key,
            "database_file": self.config.database_file,
            "source": self.config.source,
            "hash_value": self.new_hash,
            "timestamp": self.download_timestamp,
        }

    def load_db(self) -> None:
        """Loads the database from a JSON file."""
        try:
            with open(self.database_file_path, "r") as db_file:
                self._database = json.load(db_file)
        except FileNotFoundError:
            logger.warning(
                f"{self.config.database_key} database could not be loaded. Run `surfactant plugin update-db {self.plugin_name}` to fetch the database."
            )
            self._database = None

    def get_database(self) -> Optional[Dict[str, Any]]:
        """Returns the loaded database."""
        if self._database is None:
            self.load_db()
        return self._database

    def save_database(self, data: Dict[str, Any]) -> None:
        """Saves the database to a JSON file."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with open(self.database_file_path, "w") as db_file:
            json.dump(data, db_file, indent=4)
        logger.info(f"{self.config.database_key} database saved successfully.")

    @abstractmethod
    def parse_raw_data(self, raw_data: str) -> Dict[str, Any]:
        """Parses raw database data into a structured format."""
        # No implementation needed for abstract methods.


def download_database(url: str) -> Optional[str]:
    """
    Downloads the content of a database from the given URL.

    Args:
        url (str): The URL of the database to download.
    Returns:
        Optional[str]: The content of the database as a string if the request is successful,
                       or None if an error occurs.
    """
    try:
        # Perform the HTTP GET request with a timeout
        response = requests.get(url, timeout=10)

        # Handle HTTP status codes
        if response.status_code == 200:
            logger.info(f"Request successful! URL: {url}")
            return response.text

        if response.status_code == 404:
            logger.error(f"Resource not found. URL: {url}")
        else:
            logger.warning(f"Unexpected status code {response.status_code} for URL: {url}")
    except RequestException as e:
        # Handle network-related errors
        logger.error(f"An error occurred while trying to fetch the URL: {url}. Error: {e}")

    # Return None in case of any failure
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


def _read_toml_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Read and parse a TOML file.

    Args:
        file_path (str): The path to the TOML file.

    Returns:
        Optional[Dict[str, Any]]: The parsed TOML data, or None if the file does not exist.
    """
    try:
        with open(file_path, "r") as f:
            return tomlkit.load(f)
    except FileNotFoundError:
        return None
    except tomlkit.exceptions.TOMLKitError as e:
        raise ValueError(f"Error parsing TOML file at {file_path}: {e}") from e


def _write_toml_file(file_path: str, data: Dict[str, Any]) -> None:
    """
    Write data to a TOML file.

    Args:
        file_path (str): The path to the TOML file.
        data (Dict[str, Any]): The data to write to the file.
    """
    with open(file_path, "w") as f:
        tomlkit.dump(data, f)


def load_hash_and_timestamp(
    version_file_path: str, database_key: str, database_file: str
) -> Optional[Dict[str, str]]:
    """
    Load the hash and timestamp for a specific database from the specified TOML file.

    Args:
        version_file_path (str): The path to the TOML file that tracks database versions.
        database_key (str): The key identifying the database.
        database_file (str): The key identifying the specific database.

    Returns:
        Optional[Dict[str, str]]: The hash and timestamp data, or None if not found.
    """
    hash_data = _read_toml_file(version_file_path)
    if hash_data is None:
        return None

    # Access the specific structure using the provided keys
    return hash_data.get(database_key, {}).get(database_file)


def save_hash_and_timestamp(version_file_path: str, pattern_info: Dict[str, str]) -> None:
    """
    Save the hash and timestamp for a specific pattern to the specified TOML file.

    Args:
        hash_file_path (str): The path to the TOML file.
        pattern_info (Dict[str, str]): A dictionary containing the following keys:
            - "database_key": The key identifying the database.
            - "database_file": The key identifying the file path of specific database.
            - "source": The source of the pattern.
            - "hash_value": The hash value of the pattern.
            - "timestamp": The timestamp of when the database was downloaded.

    Raises:
        ValueError: If required keys are missing from `pattern_info`.
    """
    required_keys = {"database_key", "database_file", "source", "hash_value", "timestamp"}
    if not required_keys.issubset(pattern_info):
        raise ValueError(f"pattern_info must contain the keys: {required_keys}")

    hash_data = _read_toml_file(version_file_path) or {}

    # Define the new data structure
    new_data = {
        pattern_info["database_key"]: {
            pattern_info["database_file"]: {
                "source": pattern_info["source"],
                "hash": pattern_info["hash_value"],
                "timestamp": pattern_info["timestamp"],
            }
        }
    }

    # Update the existing data with the new data
    if pattern_info["database_key"] in hash_data:
        hash_data[pattern_info["database_key"]].update(new_data[pattern_info["database_key"]])
    else:
        hash_data.update(new_data)

    # Write the updated data back to the TOML file
    _write_toml_file(version_file_path, hash_data)
