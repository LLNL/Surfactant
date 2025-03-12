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

from surfactant.plugin.manager import get_plugin_manager, is_plugin_blocked  # Import the helper function

# Configure loguru to show logs at DEBUG level or higher
import sys
logger.remove()  # Remove the default logger configuration
logger.add(sys.stdout, level="DEBUG")  # Add a new logger that outputs to console


def check_if_grype_installed() -> bool:
    try:
        result = subprocess.run(["grype", "--help"], capture_output=True, check=False).returncode
        if result == 0:
            logger.info("Grype is installed and ready to use.")
        else:
            logger.warning("Grype is not installed or not functioning correctly.")
        return result == 0
    except FileNotFoundError:
        logger.error("Grype is not installed. Please install it to use this plugin.")
        return False

# Initialize the plugin manager
plugin_manager = get_plugin_manager()
disable_plugin = not check_if_grype_installed() or is_plugin_blocked(plugin_manager, __name__)


def run_grype(filename: str) -> object:
    logger.debug(f"Starting grype scan for file: {filename}")
    result = subprocess.run(["grype", filename], capture_output=True, check=False)
    if result.returncode != 0:
        logger.warning(f"Running grype on {filename} failed with return code {result.returncode}")
        logger.debug(f"Grype stderr: {result.stderr.decode().strip()}")
        return None
    logger.debug(f"Grype scan completed successfully for file: {filename}")
    output = result.stdout.decode()
    logger.debug(f"Grype raw output: {output[:200]}...")  # Log the first 200 characters of the output
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
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str, children: list) -> Optional[List[Software]]:
    logger.info(f"Extracting file info for {filename} of type {filetype}")
    
    if disable_plugin:
        logger.warning("Grype plugin is disabled. Skipping file analysis.")
        return None
    
    if filetype not in ("DOCKER_TAR", "DOCKER_GZIP"):
        logger.debug(f"File type {filetype} is not supported by the grype plugin.")
        return None

    try:
        if filetype == "DOCKER_GZIP":
            logger.debug(f"Decompressing gzip file: {filename}")
            with open(filename, "rb") as gzip_in:
                gzip_data = gzip_in.read()
            with tempfile.NamedTemporaryFile() as gzip_out:
                gzip_out.write(gzip.decompress(gzip_data))
                logger.debug(f"Decompressed file written to temporary file: {gzip_out.name}")
                return run_grype(gzip_out.name)
        
        # For DOCKER_TAR or other supported types
        return run_grype(filename)
    
    except Exception as e:
        logger.error(f"Error while processing file {filename}: {e}")
        return None


@surfactant.plugin.hookimpl
def update_db():
    logger.info("Starting grype database update...")
    # Example update logic
    try:
        subprocess.check_call(["grype", "db", "update"])
        logger.info("Grype database updated successfully.")
        return "Database updated successfully."
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update Grype database: {e}")
        return f"Failed to update database: {e}"


@surfactant.plugin.hookimpl
def short_name():
    return "grype"
