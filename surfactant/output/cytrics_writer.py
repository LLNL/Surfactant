import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    # outfile is a file pointer, not a file name
    outfile.write(sbom.to_json(indent=4))
