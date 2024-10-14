from loguru import logger

from surfactant.cmd.cli_commands.cli_base import Cli
from surfactant.sbomtypes._sbom import SBOM

class Add(Cli):
    """
    A class that implements the surfactant cli add functionality

    Attributes:
    match_functions         A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    camel_case_conversions  A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case
    sbom                    An internal record of sbom entries the class adds to as it finds more matches.
    """

    def __init__(self):
        """Initializes the cli_add class"""
        self.match_functions = {
            "relationship": self.add_relationship,
            "file": self.add_file,
            "installPath": self.add_installpath,
            "entry": self.add_entry,
        }
        self.camel_case_conversions = {
            "uuid": "UUID",
            "filename": "fileName",
            "installpath": "installPath",
            "capturetime": "captureTime",
            "relationshipassertion": "relationshipAssertion",
        }

    def handle_kwargs(self, kwargs: dict) -> dict:
        converted_kwargs = {}
        for k, v in kwargs.items():  # Convert key values to camelcase where appropriate
            key = self.camel_case_conversions[k] if k in self.camel_case_conversions else k
            converted_kwargs[key] = v
        return converted_kwargs

    def execute(self, input_sbom: SBOM, **kwargs):
        """Executes the main functionality of the cli_find class
        param: input_sbom   The sbom to add entries to
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        converted_kwargs = self.handle_kwargs(kwargs)
        self.sbom = input_sbom

        for key, value in converted_kwargs.items():
            if key in self.match_functions:
                self.match_functions[key](value)
            else:
                logger.warning(f"Parameter {key} is not supported")
        return self.sbom

    def add_relationship(self, value: dict) -> bool:
        self.sbom.add_relationship(Relationship(**value))

    def add_file(self, path):
        self.sbom.software.append(Software.create_software_from_file(path))

    def add_entry(self, entry):
        self.sbom.software.append(Software.from_dict(entry))

    def add_installpath(self, prefixes: tuple):
        cleaned_prefixes = (p.rstrip("/") for p in prefixes)
        containerPathPrefix, installPathPrefix = cleaned_prefixes
        for sw in self.sbom.software:
            for path in sw.containerPath:
                if containerPathPrefix in path:
                    sw.installPath.append(path.replace(containerPathPrefix, installPathPrefix))