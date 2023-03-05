import json

import surfactant.pluginsystem as pluginsystem


class CyTRICS(pluginsystem.OutputPlugin):
    PLUGIN_NAME = "CYTRICS"

    @classmethod
    def write(cls, sbom, outfile):
        # outfile is a file pointer, not a file name
        json.dump(sbom, outfile, indent=4)
