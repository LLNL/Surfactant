from pathlib import Path
from typing import Any, Dict, Optional

import toml
from loguru import logger


class TOMLManager:
    """Utility class for managing TOML files."""

    @staticmethod
    def read_toml(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Reads a TOML file and returns its contents as a dictionary.

        Args:
            file_path (Path): The path to the TOML file.

        Returns:
            Optional[Dict[str, Any]]: The contents of the TOML file, or None if the file doesn't exist or is invalid.
        """
        if not file_path.exists():
            logger.warning(f"TOML file not found: {file_path}")
            return None

        try:
            with open(file_path, "r") as file:
                return toml.load(file)
        except toml.TomlDecodeError as e:
            logger.error(f"Failed to parse TOML file {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while reading TOML file {file_path}: {e}")
            return None

    @staticmethod
    def write_toml(file_path: Path, data: Dict[str, Any]) -> bool:
        """
        Writes a dictionary to a TOML file.

        Args:
            file_path (Path): The path to the TOML file.
            data (Dict[str, Any]): The data to write to the file.

        Returns:
            bool: True if the file was written successfully, False otherwise.
        """
        try:
            with open(file_path, "w") as file:
                toml.dump(data, file)
            return True
        except Exception as e:
            logger.error(f"Failed to write TOML file {file_path}: {e}")
            return False

    @staticmethod
    def update_toml(
        file_path: Path, top_level_key: str, sub_key: str, updates: Dict[str, Any]
    ) -> bool:
        """
        Updates a TOML file with new data, merging it with existing contents.

        Args:
            file_path (Path): The path to the TOML file.
            top_level_key (str): The top-level key in the TOML structure (e.g., "native_lib_patterns").
            sub_key (str): The sub-key under the top-level key (e.g., "emba").
            updates (Dict[str, Any]): The updates to apply to the file.

        Returns:
            bool: True if the file was updated successfully, False otherwise.
        """
        data = TOMLManager.read_toml(file_path) or {}

        # Ensure the top-level key exists
        if top_level_key not in data:
            data[top_level_key] = {}

        # Update the sub-key under the top-level key
        data[top_level_key][sub_key] = updates

        return TOMLManager.write_toml(file_path, data)
