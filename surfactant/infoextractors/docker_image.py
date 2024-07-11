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


def is_docker_scout_installed():
    # Check that Docker Scout can be run
    try:
        result = subprocess.run(["docker", "scout"], capture_output=True, check=False)
        if result.returncode != 0:
            logger.warning("Install Docker Scout to scan containers for additional information")
            return False
        return True
    except FileNotFoundError:
        return False


# Check if Docker Scout is installed when this Python module gets loaded
disable_docker_scout = not is_docker_scout_installed()


def supports_file(filetype: str) -> bool:
    return filetype in ("DOCKER_TAR", "DOCKER_GZIP")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if disable_docker_scout or not supports_file(filetype):
        return None
    return extract_docker_info(filetype, filename)


def extract_docker_info(filetype: str, filename: str) -> object:
    if filetype == "DOCKER_GZIP":
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            return run_docker_scout(gzip_out.name)
    return run_docker_scout(filename)


# Function that extract_docker_info delegates to to actually run Docker scout
def run_docker_scout(filename: str) -> object:
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
