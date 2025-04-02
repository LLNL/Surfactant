# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import atexit
import bz2
import gzip
import lzma
import os
import pathlib
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
    if filetype in ("TAR", "GZIP", "ZIP", "BZIP2", "XZ"):
        return filetype
    return None


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    context_queue: "Queue[ContextEntry]",
    current_context: Optional[ContextEntry],
) -> Optional[Dict[str, Any]]:
    # Check if the file is compressed and get its format

    compression_format = supports_file(filetype)
    if not compression_format:
        return None

    install_prefix = ""
    extract_paths = []

    # Check that archive key exists and filename is same as archive file
    if current_context.archive and current_context.archive == filename:
        # If archive has empty list of extractPaths, an entry to the queue will be added
        if current_context.extractPaths == []:
            temp_folder = check_compression_type(current_context.archive, compression_format)
            install_prefix = current_context.installPrefix
            extract_paths = [temp_folder]
            logger.info(f"New ContextEntry added for archive: {current_context.archive}")
        # Assume archive is already extracted if the extractPaths is not empty
        else:
            logger.info(
                f"Already extracted, skipping extraction for archive: {current_context.archive}"
            )
            return None
    # Assume there is a compressed file in the extractPaths
    elif current_context.installPrefix == "/":
        # Decompress the file based on its format
        temp_folder = check_compression_type(filename, compression_format)
        extract_paths = [temp_folder]
        logger.info(f"New ContextEntry added for extracted files: {temp_folder}")

    # Create a new context entry and add it to the queue
    new_entry = ContextEntry(
        archive=filename, installPrefix="", extractPaths=extract_paths, skipProcessingArchive=True
    )
    context_queue.put(new_entry)

    return None


def check_compression_type(filename: str, compression_format: str) -> str:
    temp_folder = None
    if compression_format == "ZIP":
        temp_folder = decompress_zip_file(filename)
    elif compression_format == "TAR":
        temp_folder = extract_tar_file(filename)
    elif compression_format in {"GZIP", "BZIP2", "XZ"}:
        try:
            tar_modes = {
                "GZIP": "r:gz",
                "BZIP2": "r:bz2",
                "XZ": "r:xz",
            }
            temp_folder = decompress_tar_file(filename, tar_modes[compression_format])
        except tarfile.ReadError as e:
            # Check if we expected it to be readable as a compressed tar file
            if (
                ".tar" in pathlib.Path(filename).suffixes
                or ".tgz" in pathlib.Path(filename).suffixes
            ):
                logger.error(f"Error decompressing tar file {filename}: {e}")
                logger.info(
                    f"Attempting to decompress {filename} using the appropriate library as a single file"
                )
            # Since it doesn't seem to be a compressed tar file, try just decompressing the file
            temp_folder = decompress_file(filename, compression_format)
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


def decompress_file(filename, compression_type):
    temp_folder = create_temp_dir()
    output_filename = pathlib.Path(filename).name
    if compression_type == "GZIP" and filename.endswith(".gz"):
        output_filename = pathlib.Path(filename).stem
    elif compression_type == "BZIP2" and filename.endswith(".bz2"):
        output_filename = pathlib.Path(filename).stem
    elif compression_type == "XZ" and filename.endswith(".xz"):
        output_filename = pathlib.Path(filename).stem

    if compression_type == "GZIP":
        with gzip.open(filename, "rb") as f_in:
            with open(os.path.join(temp_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    elif compression_type == "BZIP2":
        with bz2.open(filename, "rb") as f_in:
            with open(os.path.join(temp_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    elif compression_type == "XZ":
        with lzma.open(filename, "rb") as f_in:
            with open(os.path.join(temp_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

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
