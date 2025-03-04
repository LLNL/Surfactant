# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from queue import Queue
from tempfile import TemporaryDirectory

from loguru import logger

import tarfile
import zipfile
import tempfile
import shutil

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant import ContextEntry

def is_compressed(filename):
    # Map file extensions to their compression formats
    compression_formats = {
        '.zip': 'zip',
        '.tar': 'tar',
        '.tar.gz': 'tar.gz',
        '.tar.bz2': 'tar.bz2',
        '.tar.xz': 'tar.xz',
    }
    for ext, fmt in compression_formats.items():
        if filename.endswith(ext):
            return fmt
    return None

@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str, context: Queue[ContextEntry]
) -> Optional[Dict[str, Any]]:

    # Check if the file is compressed and get its format
    compression_format = is_compressed(filename)
    if not compression_format:
        return None
    
    # Decompress the file based on its format
    temp_folder = check_compression_type(filename, compression_format)

    # Add a new ContextEntry for the temp dir
    new_entry = ContextEntry(
        archive = filename,
        installPrefix = "",
        extractPaths=[temp_folder],
        skipProcessingArchive=True
    )

    # Add new ContextEntry to queue
    context.put(new_entry)
    logger.info(f"New ContextEntry added for extracted files: {temp_folder}")
    return None
    
def check_compression_type(filename: str, compression_format: str) -> str:
    temp_folder = None

    if compression_format == 'zip':
        temp_folder = decompress_zip_file(filename)
    elif compression_format == 'tar':
        temp_folder = extract_tar_file(filename)
    elif compression_format in {'tar.gz', 'tar.bz2', 'tar.xz'}:
        tar_modes = {
            'tar.gz': 'r:gz',
            'tar.bz2': 'r:bz2',
            'tar.xz': 'r:xz',
        }
        temp_folder = decompress_tar_file(filename, tar_modes[compression_format])
    else:
        raise ValueError(f"Unsupported compression format: {compression_format}")

    return temp_folder

def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix='surfactant-temp')
    return temp_dir

def decompress_zip_file(filename):
    temp_folder = create_temp_dir()
    with zipfile.ZipFile(filename, 'r') as f:
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
        with tarfile.open(filename, 'r') as tar:
            tar.extractall(path=temp_dir)     
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except tarfile.TarError as e:
        print(f"Error extracting tar file: {e}")

    return temp_dir

