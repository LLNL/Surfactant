from loguru import logger

from surfactant.cmd.cli_commands.cli_base import Cli
from surfactant.sbomtypes import SBOM, Relationship, Software


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
        super().__init__()

    def handle_kwargs(self, kwargs: dict) -> dict:
        converted_kwargs = {}
        for k, v in kwargs.items():  # Convert key values to camelcase where appropriate
            key = self.camel_case_conversions[k] if k in self.camel_case_conversions else k
            converted_kwargs[key] = v
        return converted_kwargs

    def execute(self, **kwargs):
        """Executes the main functionality of the cli_find class
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        working_sbom = None
        self.subset = self.load_current_subset()
        if not self.subset:
            self.sbom = self.load_current_sbom()
            if not self.sbom:
                logger.error("No sbom currently loaded. Load an sbom with `surfactant cli load`")
                return False
            working_sbom = self.sbom
        else:
            working_sbom = self.subset

        converted_kwargs = self.handle_kwargs(kwargs)

        for key, value in converted_kwargs.items():
            if key in self.match_functions:
                self.match_functions[key](working_sbom, value)
            else:
                logger.warning(f"Parameter {key} is not supported")
        self.save_changes()
        return True

    def add_relationship(self, sbom: SBOM, value: dict) -> bool:
        sbom.add_relationship(Relationship(**value))

    def add_file(self, sbom: SBOM, path):
        sbom.software.append(Software.create_software_from_file(path))

    def add_entry(self, sbom: SBOM, entry):
        try:
            sbom.software.append(Software.from_dict(entry))
        except AttributeError:
            logger.warning("Entry not valid, could not add.")

    def add_installpath(self, sbom: SBOM, prefixes: tuple):
        cleaned_prefixes = (p.rstrip("/") for p in prefixes)
        containerPathPrefix, installPathPrefix = cleaned_prefixes
        for sw in sbom.software:
            for path in sw.containerPath:
                if containerPathPrefix in path:
                    sw.installPath.append(path.replace(containerPathPrefix, installPathPrefix))
