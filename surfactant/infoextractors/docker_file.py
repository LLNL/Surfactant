# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import json
import subprocess
import tempfile

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: str) -> bool:
    return filetype in ("Docker archive tar", "Docker archive gzip")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_docker_info(filetype, filename)


def extract_docker_info(filetype: str, filename: str) -> object:
    if filetype == "Docker archive gzip":
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            return run_docker(gzip_out.name)
    return run_docker(filename)


# Function that extract_docker_info delegates to to actually run Docker scout
def run_docker(filename: str) -> object:
    result = subprocess.run(
        ["docker", "scout", "sbom", "--format", "spdx", f"fs://{filename}"], capture_output=True, check=True
    )
    spdx_out = json.loads(result.stdout)
    return {"dockerSPDX": spdx_out}
