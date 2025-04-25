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
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import requests
import tomlkit
from loguru import logger
from requests.exceptions import RequestException

from surfactant.configmanager import ConfigManager


@dataclass
class DatabaseConfig:
    """
    Represents the configuration for a database used by a plugin.

    Attributes:
        database_dir (str): The database directory name for the class of databases (e.g., "js_library", "native_library").
        database_key (str): The key identifying the database (e.g., "retirejs").
        database_file (str): The file name of the database (e.g., "js_library_patterns_retirejs.json").
        source (str): The source URL of the database, or "file" if it's a local file.
        plugin_name (Optional[str]): The canonical name or short name of the plugin handling the database.
    """

    database_dir: str
    database_key: str
    database_file: str
    source: str
    plugin_name: Optional[str] = None

    def __post_init__(self) -> None:
        # Validate that source is either a URL or "file"
        if self.source != "file":
            parsed_url = urlparse(self.source)
            # Check that the scheme is valid (http or https)
            if parsed_url.scheme not in {"http", "https"}:
                raise ValueError(
                    f"Invalid URL scheme: {parsed_url.scheme}. Expected 'http' or 'https'."
                )
            # Check that netloc is present
            if not parsed_url.netloc:
                raise ValueError(
                    f"Invalid URL for source: {self.source}",
                )

        # Ensure database_file ends with .json
        if not self.database_file.endswith(".json"):
            raise ValueError(
                f"database_file '{self.database_file}' must end with '.json'.",
            )


class BaseDatabaseManager(ABC):
    """Abstract base class for managing databases."""

    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config
        # Attempt to retrieve an override URL using the database_dir (e.g., "js_library_patterns")
        # and the database_key (e.g., "retirejs").
        from .external_db_config import get_source_for
        override_url = get_source_for(self.config.database_dir, self.config.database_key)
        if override_url:
            self.config.source = override_url
            logger.info(
                "Using external URL override for %s: %s", self.config.database_key, override_url
            )
        else:
            logger.info("Using built-in URL for %s", self.config.database_key)

        self.new_hash: Optional[str] = None
        self.download_timestamp: Optional[str] = None
        self._database: Optional[Dict[str, Any]] = None

        # Ensure the parent directory exists
        path = self.database_version_file_path
        path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def data_dir(self) -> Path:
        """Returns the base directory for storing database (.json) and version tracking (TOML) files."""
        return ConfigManager().get_data_dir_path() / "databases"

    @property
    def database_version_file_path(self) -> Path:
        """Path to the database version file (e.g., TOML file)."""
        return self.data_dir / f"{self.config.database_dir}" / "version_info.toml"

    @property
    def database_file_path(self) -> Path:
        """Path to the JSON database file."""
        return self.data_dir / f"{self.config.database_dir}" / f"{self.config.database_file}"

    @property
    def database_info(self) -> Dict[str, Any]:
        """Returns metadata about the database patterns."""
        return {
            "database_key": self.config.database_key,
            "database_file": self.config.database_file,
            "source": self.config.source,
            "hash_value": self.new_hash,
            "timestamp": self.download_timestamp,
        }

    def initialize_database(self, command_name: Optional[str] = None) -> None:
        """
        Initialization hook to load the JavaScript library database.

        Args:
            command_name (Optional[str], optional): The name of the command invoking the initialization.
                If set to "update-db", the database will not be loaded.

        Returns:
            None
        """
        if command_name != "update-db":
            logger.info("Initializing %s...", self.config.plugin_name)
            self.load_db()
            logger.info("Initializing %s complete.", self.config.plugin_name)

    def load_db(self) -> None:
        """Loads the database from a JSON file."""
        try:
            with self.database_file_path.open("r") as db_file:
                self._database = json.load(db_file)
        except FileNotFoundError:
            logger.warning(
                "%s database could not be loaded. Run `surfactant plugin update-db %s` to fetch the database.",
                self.config.database_key,
                self.config.plugin_name,
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
        with self.database_file_path.open("w") as db_file:
            json.dump(data, db_file, indent=4)
        logger.info("%s database saved successfully.", self.config.database_key)

    @abstractmethod
    def parse_raw_data(self, raw_data: str) -> Dict[str, Any]:
        """Parses raw database data into a structured format."""
        # No implementation needed for abstract methods.

    def download_and_update_database(self) -> str:
        raw_data = download_content(self.config.source)
        if not raw_data:
            return "No update occurred. Failed to download database."

        new_hash = calculate_hash(raw_data)
        current_data = load_db_version_metadata(
            self.database_version_file_path, self.config.database_key
        )

        if current_data and new_hash == current_data.get("hash"):
            return "No update occurred. Database is up-to-date."

        parsed_data = self.parse_raw_data(raw_data)
        if parsed_data is None:
            return "No update occurred. Failed to parse raw data."

        self.save_database(parsed_data)
        self.new_hash = new_hash
        self.download_timestamp = datetime.now(timezone.utc).isoformat()
        save_db_version_metadata(self.database_version_file_path, self.database_info)
        return "Update complete."


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
                logger.info("Request successful! URL: %s", url)
                return response.text
            if response.status_code == 404:
                logger.error("Resource not found. URL: %s", url)
                return None
            logger.warning("Unexpected status code %s for URL: %s", response.status_code, url)
        except RequestException as e:
            logger.error("Attempt %s - Error fetching URL %s: %s", str(attempt + 1), url, e)

        attempt += 1
        sleep_time = 2**attempt  # exponential backoff
        logger.info("Retrying in %s seconds...", sleep_time)
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
