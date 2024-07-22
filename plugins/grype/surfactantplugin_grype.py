# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import subprocess
import tempfile
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def check_if_grype_installed() -> bool:
    try:
        result = subprocess.run(["grype", "--help"], capture_output=True, check=False).returncode
    except FileNotFoundError:
        result = 1
    if result != 0:
        logger.warning("Install grype for the grype plugin to run")
    return result == 0


disable_plugin = not check_if_grype_installed()


def run_grype(filename: str) -> object:
    result = subprocess.run(["grype", filename], capture_output=True, check=False)
    if result.returncode != 0:
        logger.warning(f"Running grype on {filename} failed")
        return None
    output = result.stdout.decode()
    to_ret = []
    # skip the header on the first line
    for line in output.split("\n")[1:]:
        columns = [s.strip() for s in line.split("  ") if s.strip()]
        # Skip empty lines
        if len(columns) == 0:
            continue
        # Assume that the "Fixed In" field is missing if there's only 5 entries
        name = columns[0]
        installed = columns[1]
        if len(columns) == 5:
            fixed_in = ""
            type_ = columns[2]
            vuln = columns[3]
            severity = columns[4]
        else:
            fixed_in = columns[2]
            type_ = columns[3]
            vuln = columns[4]
            severity = columns[5]
        to_ret.append(
            {
                "name": name,
                "installed": installed,
                "fixed_in": fixed_in,
                "type": type_,
                "vulnerability": vuln,
                "severity": severity,
            }
        )
    return {"grype_output": to_ret}


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str, children: list
) -> Optional[List[Software]]:
    if disable_plugin or filetype not in ("DOCKER_TAR", "DOCKER_GZIP"):
        return None
    if filetype == "DOCKER_GZIP":
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            return run_grype(gzip_out.name)
    return run_grype(filename)
