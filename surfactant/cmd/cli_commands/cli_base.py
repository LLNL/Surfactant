import os
import platform
from pathlib import Path

from loguru import logger

from surfactant.sbomtypes._sbom import SBOM


class Cli:
    """
    A base class that implements the surfactant cli basic functionality

    Attributes:
    match_functions         A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    camel_case_conversions  A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case
    sbom                    An internal record of sbom entries the class adds to as it finds more matches.
    subset                  An internal record of the subset of sbom entries from the last cli find call.
    """

    sbom: SBOM = None
    subset: SBOM = None
    sbom_filename: str
    subset_filename: str
    match_functions: dict
    camel_case_conversions: dict

    def __init__(self):
        self.sbom_filename = "sbom_cli"
        self.subset_filename = "subset_cli"
        # Create data directory
        self.data_dir = self._get_cli_sbom_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _get_cli_sbom_dir(self) -> Path:
        """Determines the path to the loaded serialized sbom file.

        Returns:
            Path: The directory path to where the serialized sboms are stored.
        """
        if platform.system() == "Windows":
            data_dir = Path(os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming")))
        else:
            data_dir = Path(os.getenv("XDG_DATA_HOME", os.path.expanduser("~/.local/share")))
        data_dir = data_dir / "surfactant"
        return data_dir

    def serialize(self, sbom: SBOM) -> bool:
        """Serializes the internal sbom and subset sbom (if it exists) and saves them to the filesystem"""
        try:
            return sbom.to_json(indent=2).encode("utf-8")
        except Exception as e:
            logger.error(f"Could not serialize sbom - {e}")

    def deserialize(self, data) -> SBOM:
        """Deserializes the sbom and subset sbom (if it exists) and saves them in the class instance"""
        try:
            return SBOM.from_json(data.decode("utf-8"))
        except Exception as e:
            logger.error(f"Could not deserialize sbom from given data - {e}")
