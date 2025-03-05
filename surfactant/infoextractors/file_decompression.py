# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import atexit
import os
import shutil
import tarfile
import tempfile
import zipfile
from queue import Queue
from typing import Any, Dict, Optional

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.sbomtypes import SBOM, Software

# Global list to track temp dirs
GLOBAL_TEMP_DIRS_LIST = []


def supports_file(filetype: str) -> str:
    if filetype in ("TAR", "GZIP", "ZIP", "TAR BZIP2", "TAR XZ"):
        return filetype
    return None


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str, context: "Queue[ContextEntry]"
) -> Optional[Dict[str, Any]]:
    # Check if the file is compressed and get its format
    compression_format = supports_file(filetype)
    if not compression_format:
        return None

    # Decompress the file based on its format
    temp_folder = check_compression_type(filename, compression_format)

    # Add a new ContextEntry for the temp dir
    new_entry = ContextEntry(
        archive=filename, installPrefix="", extractPaths=[temp_folder], skipProcessingArchive=True
    )

    # Add new ContextEntry to queue
    context.put(new_entry)
    logger.info(f"New ContextEntry added for extracted files: {temp_folder}")

    return None


def check_compression_type(filename: str, compression_format: str) -> str:
    temp_folder = None

    if compression_format == "ZIP":
        temp_folder = decompress_zip_file(filename)
    elif compression_format == "TAR":
        temp_folder = extract_tar_file(filename)
    elif compression_format in {"GZIP", "TAR BZIP2", "TAR XZ"}:
        tar_modes = {
            "GZIP": "r:gz",
            "TAR BZIP2": "r:bz2",
            "TAR XZ": "r:xz",
        }
        temp_folder = decompress_tar_file(filename, tar_modes[compression_format])
    else:
        raise ValueError(f"Unsupported compression format: {compression_format}")

    return temp_folder


def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="surfactant-temp")

    # Add to global list of temp dirs to facilitate easier clean up at the end
    GLOBAL_TEMP_DIRS_LIST.append(temp_dir)
    return temp_dir


def decompress_zip_file(filename):
    temp_folder = create_temp_dir()
    with zipfile.ZipFile(filename, "r") as f:
        f.extractall(path=temp_folder)
    return temp_folder


def decompress_tar_file(filename, compression_type):
    temp_folder = create_temp_dir()
    with tarfile.open(filename, compression_type) as tar:
        tar.extractall(path=temp_folder)
        logger.info("Finished TAR file decompression")
    return temp_folder


def extract_tar_file(filename):
    temp_dir = create_temp_dir()
    try:
        with tarfile.open(filename, "r") as tar:
            tar.extractall(path=temp_dir)
    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
    except tarfile.TarError as e:
        logger.error(f"Error extracting tar file: {e}")

    return temp_dir


def delete_temp_dirs():
    for temp_dir in GLOBAL_TEMP_DIRS_LIST:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")


# Register exit handler
atexit.register(delete_temp_dirs)
