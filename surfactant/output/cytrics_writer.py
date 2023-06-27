import surfactant.plugin
from surfactant.sbomtypes import SBOM
from typing import Optional


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    # outfile is a file pointer, not a file name
    outfile.write(sbom.to_json(indent=2))


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "cytrics"
