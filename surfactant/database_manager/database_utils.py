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
import tomlkit


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
