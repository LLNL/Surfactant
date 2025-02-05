# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
from typing import Dict, Optional

import requests
import tomlkit
from loguru import logger
from requests.exceptions import RequestException


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
        elif response.status_code == 404:
            logger.error(f"Resource not found. URL: {url}")
        else:
            logger.warning(f"Unexpected status code {response.status_code} for URL: {url}")
    except RequestException as e:
        # Handle network-related errors
        logger.error(f"An error occurred while trying to fetch the URL: {url}. Error: {e}")

    # Return None in case of any failure
    return None


def calculate_hash(data: str) -> str:
    """Calculate the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_hash_and_timestamp(
    hash_file_path, pattern_key: str, pattern_file: str
) -> Optional[Dict[str, str]]:
    """Load the hash and timestamp for a specific pattern from the specified TOML file."""
    try:
        with open(hash_file_path, "r") as f:
            hash_data = tomlkit.load(f)
            # Access the specific structure using the provided keys
            return hash_data.get(pattern_key, {}).get(pattern_file)
    except FileNotFoundError:
        return None


def save_hash_and_timestamp(hash_file_path, pattern_info: Dict[str, str]) -> None:
    """Save the hash and timestamp for a specific pattern to the specified TOML file."""
    try:
        with open(hash_file_path, "r") as f:
            hash_data = tomlkit.load(f)
    except FileNotFoundError:
        hash_data = {}

    # Define the new data structure
    new_data = {
        pattern_info["pattern_key"]: {
            pattern_info["pattern_file"]: {
                "source": pattern_info["source"],
                "hash": pattern_info["hash_value"],
                "timestamp": pattern_info["timestamp"],
            }
        }
    }

    # Update the existing data with the new data
    if pattern_info["pattern_key"] in hash_data:
        hash_data[pattern_info["pattern_key"]].update(new_data[pattern_info["pattern_key"]])
    else:
        hash_data.update(new_data)

    # Write the updated data back to the TOML file
    with open(hash_file_path, "w") as f:
        tomlkit.dump(hash_data, f)
