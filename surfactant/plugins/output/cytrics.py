import json

from surfactant import pluginsystem
from surfactant.sbomtypes import SBOM


class CyTRICS(pluginsystem.OutputPlugin):
    PLUGIN_NAME = "CYTRICS"

    @classmethod
    def write(cls, sbom: SBOM, outfile):
        # outfile is a file pointer, not a file name
        outfile.write(sbom.to_json(indent=4))
