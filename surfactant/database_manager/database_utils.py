import toml
from typing import Optional, Dict
import hashlib

def calculate_hash(data: str) -> str:
    """Calculate the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_hash_and_timestamp(hash_file_path, pattern_key: str, pattern_file: str) -> Optional[Dict[str, str]]:
    """Load the hash and timestamp for a specific pattern from the specified TOML file."""
    try:
        with open(hash_file_path, "r") as f:
            hash_data = toml.load(f)
            # Access the specific structure using the provided keys
            return hash_data.get(pattern_key, {}).get(pattern_file)
    except FileNotFoundError:
        return None

def save_hash_and_timestamp(hash_file_path, pattern_key: str, pattern_file: str, source: str, hash_value: str, timestamp: str) -> None:
    """Save the hash and timestamp for a specific pattern to the specified TOML file."""
    try:
        with open(hash_file_path, "r") as f:
            hash_data = toml.load(f)
    except FileNotFoundError:
        hash_data = {}

    # Define the new data structure
    new_data = {
        pattern_key: {
            pattern_file: {
                "source": source,
                "hash": hash_value,
                "timestamp": timestamp,
            }
        }
    }

    # Update the existing data with the new data
    if pattern_key in hash_data:
        hash_data[pattern_key].update(new_data[pattern_key])
    else:
        hash_data.update(new_data)

    # Write the updated data back to the TOML file
    with open(hash_file_path, "w") as f:
        toml.dump(hash_data, f)
