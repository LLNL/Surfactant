# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import json
import subprocess
import tarfile
import tempfile
from typing import IO, Any, Optional

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software

### ===============================
### Utility Predicates
### ===============================


def is_oci_archive(filename: str) -> bool:
    """Return True if given file is a tarball
    roughly matching the OCI specification"""

    with tarfile.open(filename) as this_tarfile:  # oci-layout only path ensured
        return "oci-layout" in this_tarfile.getmembers()


def supports_file(filetype: str) -> bool:
    """Check if the file type is supported."""
    return filetype in ("DOCKER_TAR", "DOCKER_GZIP")


### ===============================
### Archive Utilities
### ===============================


def gunzip_tarball(filename: str) -> object:
    """Unzip a gzipped tarball to a temporary file
    and return the name of the corresponding file."""
    with open(filename, "rb") as gzip_in:
        gzip_data = gzip_in.read()
    with tempfile.NamedTemporaryFile() as gzip_out:
        gzip_out.write(gzip.decompress(gzip_data))
        gzip_out.flush()  # Ensure data is written before reading
        return gzip_out.name


### ===============================
### Extraction Procedures
### ===============================


class DockerScoutManager:
    def __init__(self) -> None:
        # Initialize ConfigManager
        config_manager = ConfigManager()

        # Retrieve the configuration option
        enable_docker_scout = config_manager.get("docker", "enable_docker_scout", True)

        # Set disable_docker_scout based on the configuration
        self.disable_docker_scout = not enable_docker_scout
        self.docker_scout_installed = False

    def check_docker_scout_installed(self) -> None:
        """Check if Docker Scout is installed and update the state accordingly."""
        if self.disable_docker_scout:
            return  # Do nothing if Docker Scout is disabled by config

        try:
            result = subprocess.run(["docker", "scout"], capture_output=True, check=False)
            self.docker_scout_installed = result.returncode == 0
        except FileNotFoundError:
            self.docker_scout_installed = False

        self.disable_docker_scout = not self.docker_scout_installed
        if not self.docker_scout_installed:
            logger.warning(
                "Install Docker Scout to scan containers for additional information. "
                "You can also disable this check by running 'surfactant config docker.enable_docker_scout false'."
            )

    def run_docker_scout(self, filename: str) -> Optional[object]:
        """Run Docker Scout on the given file and return the results."""
        if self.disable_docker_scout:
            return {}  # Do nothing if Docker Scout is disabled by config

        try:
            result = subprocess.run(
                ["docker", "scout", "sbom", "--format", "spdx", f"fs://{filename}"],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(f"Running Docker Scout on {filename} failed")
                return None
            spdx_out = json.loads(result.stdout)
            return spdx_out
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Docker Scout output for {filename}: {e}")
            return None


# Initialize DockerScoutManager to check installation status
dsManager = DockerScoutManager()


def extract_configs(filename: str):
    """Return image configuration objects mapped by their paths."""

    def get_manifest_file_from_tarball(tarball: tarfile.TarFile) -> IO[bytes] | None:
        return tarball.extractfile(
            {tarinfo.name: tarinfo for tarinfo in tarball.getmembers()}["manifest.json"]
        )

    def get_config_file_from_tarball(tarball: tarfile.TarFile, path: str) -> Optional[IO[bytes]]:
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
    """Extract file information using Docker Scout if supported."""
    if not supports_file(filetype):
        return None

    ## Conditionally extract tarball if gzipped
    filename = gunzip_tarball(filename) if filetype == "DOCKER_GZIP" else filename

    ## Establish metadata object
    metadata = {}

    ## Extract config files
    metadata["dockerImageConfigs"] = extract_configs(filename)

    ## Use docker scout if available and enabled
    if not dsManager.disable_docker_scout:
        metadata["dockerSPDX"] = dsManager.run_docker_scout(filename)

    return metadata


def extract_docker_info(filetype: str, filename: str) -> object:
    """Extract Docker information based on file type."""
    if filetype == "DOCKER_GZIP":
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            gzip_out.flush()  # Ensure data is written before reading
            return dsManager.run_docker_scout(gzip_out.name)
    return dsManager.run_docker_scout(filename)


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    if command_name != "update-db" and not dsManager.disable_docker_scout:
        dsManager.check_docker_scout_installed()
