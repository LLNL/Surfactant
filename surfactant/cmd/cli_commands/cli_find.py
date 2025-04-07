import hashlib

from loguru import logger

from surfactant.cmd.cli_commands.cli_base import Cli
from surfactant.sbomtypes._sbom import SBOM


class Find(Cli):
    """
    A class that implements the surfactant cli find functionality

    Attributes:
    match_functions         A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    camel_case_conversions  A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case
    sbom                    An internal record of sbom entries the class adds to as it finds more matches.
    """

    def __init__(self):
        """Initializes the cli_find class"""
        self.match_functions = {
            int: self.match_single_value,
            str: self.match_single_value,
            list: self.match_array_value,
            dict: self.match_dict_value,
            float: self.match_none_or_unhandled,
            tuple: self.match_none_or_unhandled,
            type(None): self.match_none_or_unhandled,
        }
        self.camel_case_conversions = {
            "uuid": "UUID",
            "filename": "fileName",
            "containerpath": "containerPath",
            "installpath": "installPath",
            "capturetime": "captureTime",
            "relationshipassertion": "relationshipAssertion",
        }
        super().__init__()

    def handle_kwargs(self, kwargs: dict) -> dict:
        converted_kwargs = {}
        for k, v in kwargs.items():  # Convert key values to camelcase where appropriate
            if k == "file":
                sha256, sha1, md5 = self._calculate_hashes(v, sha256=True, sha1=True, md5=True)
                v = {"sha256": sha256, "sha1": sha1, "md5": md5}
            key = self.camel_case_conversions[k] if k in self.camel_case_conversions else k
            converted_kwargs[key] = v
        return converted_kwargs

    def execute(self, **kwargs):
        """Executes the main functionality of the cli_find class
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        self.sbom = self.load_current_sbom()
        if not self.sbom:
            logger.error("No sbom currently loaded. Load an sbom with `surfactant cli load`")
            return False
        self.subset = SBOM()

        converted_kwargs = self.handle_kwargs(kwargs)

        for sw in self.sbom.software:
            match = True
            for k, v in converted_kwargs.items():
                if k == "file":
                    entry_value = {"sha256": sw.sha256, "sha1": sw.sha1, "md5": sw.md5}
                else:
                    entry_value = vars(sw)[k] if k in vars(sw) else None
                if not self.match_functions[type(entry_value)](entry_value, v):
                    match = False
                    break
            if match:
                self.subset.add_software(sw)
        if not self.subset.software:
            logger.warning("No software matches found with given parameters.")
            return False
        self.save_changes()
        return True

    def match_single_value(self, first, second) -> bool:
        """Matches sbom entry on single value
        param: first   The entry value to match
        param: second: The value to match first to
        returns:       bool, True if a match, False if not
        """
        if first == second:
            return True
        return False

    def match_array_value(self, array, value) -> bool:
        """Matches sbom entry on array value. Will match if value is contained in any of the array values.
        param: entry    The entry array to match
        param: value:   The value to find in array
        returns:        bool, True if a match, False if not
        """
        if any(value in entry for entry in array):
            return True
        return False

    def match_dict_value(self, d1: dict, d2: dict) -> bool:
        """Matches dictonary values. Will match if two dictionaries have any k,v pairs in common. Used for file hash comparison.
        param: d1       The first dictionary of values
        param: d2:      The 2nd dictionary of values to find
        returns:        bool, True if a match, False if not
        """
        if set(d1.items()).intersection(set(d2.items())):
            return True
        return False

    def match_none_or_unhandled(self, value, match):
        """Default match function if no key value found in SBOM or match type unknown/unhandled
        param: value    Should only be None
        param: match:   Value that would have been matched
        returns:        False
        """
        logger.debug(f"SBOM entry_value of type={type(value)} is not currently handled.")
        return False

    def _calculate_hashes(self, file, sha256=False, sha1=False, md5=False):
        """Helper function to calculate hashes on a given file.
        param: file      The file to calculate hashes on
        param: sha256:   Bool to decide if sha256 hash should be calculated
        param: sha1:     Bool to decide if sha1 hash should be calculated
        param: md5:      Bool to decide if md5 hash should be calculated
        returns:         str, str, str, Hashes calculated, None for those that aren't calculated
        """
        sha256_hash, sha1_hash, md5_hash = None, None, None
        with open(file, "rb") as f:
            if sha256:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
                f.seek(0)
            if sha1:
                sha1_hash = hashlib.sha1(f.read()).hexdigest()
                f.seek(0)
            if md5:
                md5_hash = hashlib.md5(f.read()).hexdigest()
        return sha256_hash, sha1_hash, md5_hash
