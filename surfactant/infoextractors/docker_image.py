# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import json
import subprocess
import tempfile
import tarfile
from typing import IO, Any, Union

from loguru import logger

### ===============================
### Utility Predicates
### ===============================

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

def is_oci_archive(filename: str) -> bool:
    """Return True if given file is a tarball 
    roughly matching the OCI specification"""

    with tarfile.open(filename) as this_tarfile: # oci-layout only path ensured
       return "oci-layout" in this_tarfile.getmembers()

def supports_file(filetype: str) -> bool:
    return filetype in ("DOCKER_TAR", "DOCKER_GZIP")

### ===============================
### Archive Utilities
### ===============================
def gunzip_tarball(filename: str) -> object:
    """ Unzip a gzipped tarball to a temporary file
    and return the name of the corresponding file. """

    with open(filename, "rb") as gzip_in:
        gzip_data = gzip_in.read()
    with tempfile.NamedTemporaryFile() as gzip_out:
        gzip_out.write(gzip.decompress(gzip_data))
        return gzip_out.name
    
### ===============================
### Extraction Procedures
### ===============================
def extract_info_via_docker_scout(filename: str) -> object:
    """ Dispatch to `docker-scout` subprocess,
        returning captured SPDX output""" 
    result = subprocess.run(
        ["docker", "scout", "sbom", "--format", "spdx", f"fs://{filename}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        logger.warning(f"Running Docker Scout on {filename} failed")
        return {}
    spdx_out = json.loads(result.stdout)
    return spdx_out

def extract_configs(filename: str):
    """Return image configuration objects mapped by their paths."""
    def get_manifest_file_from_tarball(tarball: tarfile.TarFile) -> IO[bytes] | None:
        return tarball.extractfile(
            {tarinfo.name: tarinfo for tarinfo in tarball.getmembers()}["manifest.json"]
        )

    def get_config_file_from_tarball(
        tarball: tarfile.TarFile, path: str
    ) -> Union[IO[bytes], None]:
        return tarball.extractfile(
            {tarinfo.name: tarinfo for tarinfo in tarball.getmembers()}[path]
        )

    def get_config_path_from_manifest(manifest: list[dict[str, Any]]) -> list[str]:
        path = "Config"
        return [entry[path] for entry in manifest]

    # currently unused
    def get_repo_tags_from_manifest(manifest: list[dict[str, Any]]) -> list[str]:
        path = "RepoTags"
        return [entry[path] for entry in manifest]
    
    image_configs = []
    with tarfile.open(filename) as tarball:
        # we know the manifest file is present or we wouldn't be this far
        assert (manifest_file := get_manifest_file_from_tarball(tarball))
        manifest = json.load(manifest_file)
        for config_path in get_config_path_from_manifest(manifest):
            assert (config_file := get_config_file_from_tarball(tarball, config_path))
            config = json.load(config_file)
            image_configs.append(config)
    return image_configs

### =================================
### Hook Implementation
### =================================

@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    
    ## Conditionally extract tarball if gzipped
    filename = gunzip_tarball(filename) if filetype == "DOCKER_GZIP" else filename
    
    ## Establish metadata object 
    metadata = {}

    ## Extract config files
    metadata["dockerImageConfigs"] = extract_configs(filename)

    ## Use docker-scout if available
    if is_docker_scout_installed():
        metadata["dockerSPDX"] = extract_info_via_docker_scout(filename)

    ## Return final metadata object
    return metadata
