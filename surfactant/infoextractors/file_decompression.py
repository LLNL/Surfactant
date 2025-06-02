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
from typing import Any, Callable, Dict, Literal, Optional

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.sbomtypes import SBOM, Software

# Global list to track temp dirs
GLOBAL_TEMP_DIRS_LIST = []


def supports_file(filetype: str) -> Optional[str]:
    if filetype in {"TAR", "GZIP", "ZIP", "BZIP2", "XZ"}:
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

    if compression_format:
        create_extraction(
            filename,
            context_queue,
            current_context,
            lambda f, t: decompress_to(f, t, compression_format),
        )


def create_extraction(
    filename: str,
    context_queue: "Queue[ContextEntry]",
    current_context: Optional[ContextEntry],
    decompress: "Callable[[str, str], None]",
):
    install_prefix = ""
    extract_paths = []

    # Check that archive key exists and filename is same as archive file
    if current_context.archive and current_context.archive == filename:
        if current_context.extractPaths is not None and current_context.extractPaths != []:
            logger.info(
                f"Already extracted, skipping extraction for archive: {current_context.archive}"
            )
            return

        # Inherit the context entry install prefix for the extracted files
        install_prefix = current_context.installPrefix

    # Create a temporary directory for extraction
    temp_folder = create_temp_dir()
    # Decompress the file
    decompress(filename, temp_folder)
    extract_paths = [temp_folder]

    # Create a new context entry and add it to the queue
    new_entry = ContextEntry(
        archive=filename,
        installPrefix=install_prefix,
        extractPaths=extract_paths,
        skipProcessingArchive=True,
    )
    context_queue.put(new_entry)
    logger.info(f"New ContextEntry added for extracted files: {temp_folder}")


def decompress_to(filename: str, output_folder: str, compression_format: str):
    if compression_format == "ZIP":
        decompress_zip_file(filename, output_folder)
    elif compression_format == "TAR":
        extract_tar_file(filename, output_folder)
    elif compression_format in {"GZIP", "BZIP2", "XZ"}:
        try:
            tar_modes = {
                "GZIP": "r:gz",
                "BZIP2": "r:bz2",
                "XZ": "r:xz",
            }
            extract_tar_file(filename, output_folder, tar_modes[compression_format], True)
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
            decompress_file(filename, output_folder, compression_format)
    else:
        raise ValueError(f"Unsupported compression format: {compression_format}")


def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="surfactant-temp")

    # Add to global list of temp dirs to facilitate easier clean up at the end
    GLOBAL_TEMP_DIRS_LIST.append(temp_dir)
    return temp_dir


def decompress_zip_file(filename: str, output_folder: str):
    try:
        with zipfile.ZipFile(filename, "r") as f:
            f.extractall(path=output_folder)
    except zipfile.BadZipFile as e:
        logger.error(f"Error extracting ZIP file {filename}: {e}")
    logger.info(f"Extracted ZIP contents to {output_folder}")


def decompress_file(filename: str, output_folder: str, compression_type: str):
    output_filename = pathlib.Path(filename).name
    if compression_type == "GZIP" and filename.endswith(".gz"):
        output_filename = pathlib.Path(filename).stem
    elif compression_type == "BZIP2" and filename.endswith(".bz2"):
        output_filename = pathlib.Path(filename).stem
    elif compression_type == "XZ" and filename.endswith(".xz"):
        output_filename = pathlib.Path(filename).stem

    if compression_type == "GZIP":
        with gzip.open(filename, "rb") as f_in:
            with open(os.path.join(output_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    elif compression_type == "BZIP2":
        with bz2.open(filename, "rb") as f_in:
            with open(os.path.join(output_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
    elif compression_type == "XZ":
        with lzma.open(filename, "rb") as f_in:
            with open(os.path.join(output_folder, output_filename), "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)


def extract_tar_file(
    filename: str,
    output_folder: str,
    open_mode: Literal["r", "r:*", "r:", "r:gz", "r:bz2", "r:xz"] = "r",
    throw_on_read_error: bool = True,
):
    try:
        with tarfile.open(filename, open_mode) as tar:
            tar.extractall(path=output_folder)
    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
    except tarfile.TarError as e:
        if throw_on_read_error and isinstance(e, tarfile.ReadError):
            raise e
        logger.error(f"Error extracting tar file: {e}")
    logger.info(f"Extracted TAR contents to {output_folder}")


def delete_temp_dirs():
    for temp_dir in GLOBAL_TEMP_DIRS_LIST:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")


# Register exit handler
atexit.register(delete_temp_dirs)
