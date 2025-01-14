# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import json
import subprocess
import tempfile

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


class DockerScoutManager:
    def __init__(self) -> None:
        self.disable_docker_scout = True
        self.docker_scout_installed = False
        self.check_docker_scout_installed()

    def check_docker_scout_installed(self) -> None:
        """Check if Docker Scout is installed and update the state accordingly."""
        try:
            result = subprocess.run(["docker", "scout"], capture_output=True, check=False)
            self.docker_scout_installed = result.returncode == 0
        except FileNotFoundError:
            self.docker_scout_installed = False

        self.disable_docker_scout = not self.docker_scout_installed
        if not self.docker_scout_installed:
            logger.warning("Install Docker Scout to scan containers for additional information")


# Initialize DockerScoutManager to check installation status
dsManager = DockerScoutManager()


def supports_file(filetype: str) -> bool:
    """Check if the file type is supported."""
    return filetype in ("DOCKER_TAR", "DOCKER_GZIP")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    """Extract file information using Docker Scout if supported."""
    if dsManager.disable_docker_scout or not supports_file(filetype):
        return None
    return extract_docker_info(filetype, filename)


def extract_docker_info(filetype: str, filename: str) -> object:
    """Extract Docker information based on file type."""
    if filetype == "DOCKER_GZIP":
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            gzip_out.flush()  # Ensure data is written before reading
            return run_docker_scout(gzip_out.name)
    return run_docker_scout(filename)


def run_docker_scout(filename: str) -> object:
    """Run Docker Scout on the given file and return the results."""
    try:
        result = subprocess.run(
            ["docker", "scout", "sbom", "--format", "spdx", f"fs://{filename}"],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(f"Running Docker Scout on {filename} failed")
            return {}
        spdx_out = json.loads(result.stdout)
        return {"dockerSPDX": spdx_out}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Docker Scout output for {filename}: {e}")
        return {}


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    if command_name != "update-db":
        logger.info("Initializing docker scout...")
        dsManager.check_docker_scout_installed()
        logger.info("Initializing docker scout complete.")
