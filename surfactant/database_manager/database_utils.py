# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import hashlib
from typing import Any, Dict, Optional

import tomlkit


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
        raise ValueError(f"Error parsing TOML file at {file_path}: {e}")


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
    hash_file_path: str, pattern_key: str, pattern_file: str
) -> Optional[Dict[str, str]]:
    """
    Load the hash and timestamp for a specific pattern from the specified TOML file.

    Args:
        hash_file_path (str): The path to the TOML file.
        pattern_key (str): The key identifying the pattern group.
        pattern_file (str): The key identifying the specific pattern file.

    Returns:
        Optional[Dict[str, str]]: The hash and timestamp data, or None if not found.
    """
    hash_data = _read_toml_file(hash_file_path)
    if hash_data is None:
        return None

    # Access the specific structure using the provided keys
    return hash_data.get(pattern_key, {}).get(pattern_file)


def save_hash_and_timestamp(hash_file_path: str, pattern_info: Dict[str, str]) -> None:
    """
    Save the hash and timestamp for a specific pattern to the specified TOML file.

    Args:
        hash_file_path (str): The path to the TOML file.
        pattern_info (Dict[str, str]): A dictionary containing the following keys:
            - "pattern_key": The key identifying the pattern group.
            - "pattern_file": The key identifying the specific pattern file.
            - "source": The source of the pattern.
            - "hash_value": The hash value of the pattern.
            - "timestamp": The timestamp of the pattern.

    Raises:
        ValueError: If required keys are missing from `pattern_info`.
    """
    required_keys = {"pattern_key", "pattern_file", "source", "hash_value", "timestamp"}
    if not required_keys.issubset(pattern_info):
        raise ValueError(f"pattern_info must contain the keys: {required_keys}")

    hash_data = _read_toml_file(hash_file_path) or {}

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
    _write_toml_file(hash_file_path, hash_data)
