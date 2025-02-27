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

from loguru import logger

import tarfile
import zipfile
import tempfile

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
    for ext, format in compression_formats.items():
        if filename.endswith(ext):
            return format
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

    # Add a new ContextEntry to the context queue
    new_entry = ContextEntry(
        archive=filename,  # Original archive file
        installPrefix=str(Path(temp_folder).parent),  # Parent directory of the extracted folder
        extractPaths=[temp_folder]  # Path to the extracted folder
    )
    context.put(new_entry)

    # Return metadata about the decompression process
    return {
        "decompressed": True,
        "original_file": filename,
        "compression_format": compression_format,
        "extract_dir": temp_folder,
    }
    
def check_compression_type(filename: str, compression_format: str) -> str:
    temp_folder = None

    if compression_format == 'zip':
        temp_folder = decompress_zip_file(filename)
    elif compression_format == 'tar':
        temp_folder = extract_tar_file(filename)
    elif compression_format in {'.tar.gz', 'tar.bz2', '.tar.xz'}:
        tar_modes = {
            'tar.gz': 'r:gz',
            'tar.bz2': 'r:bz2',
            'tar.xz': 'r:xz',
        }
        temp_folder = decompress_tar_file(filename, tar_modes[compression_format])
    # elif compression_format == 'tar.gz':
    #     temp_folder = decompress_tar_file(filename, 'r:gz')
    # elif compression_format == 'tar.bz2':
    #     temp_folder = decompress_tar_file(filename, 'r:bz2')
    # elif compression_format == 'tar.xz':
    #     temp_folder = decompress_tar_file(filename, 'r:xz')
    else:
        raise ValueError(f"Unsupported compression format: {compression_format}")

    return temp_folder
    # mode = ''

    # if filename.endswith('.zip'):
    #     print("It's a zip file")
    #     temp_folder = decompress_zip_file(filename)
    # elif filename.endswith('.tar'):
    #     print("this is a tar file")
    #     temp_folder = extract_tar_file(filename)
    # elif filename.endswith('.tar.gz'):
    #     mode = 'r:gz'
    # elif filename.endswith('.tar.bz2'):
    #     print("Mode is bz2")
    #     mode = 'r:bz2'
    # elif filename.endswith('.tar.xz'):
    #     mode = 'r:xz'
    # else:
    #     print("Compression format not supported")
    #     raise ValueError("Compression format not supported")
    
    # if mode:
    #     print("Calling decompress tar file")
    #     temp_folder = decompress_tar_file(filename, mode)
    #     print("After calling decompress_tar_file: ", temp_folder)
    # elif temp_folder is None:
    #     raise ValueError("Failed to decompress file")
    # return temp_folder

def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix='surfactant-temp')
    print("temp dir: ", temp_dir)
    #with tempfile.TemporaryDirectory() as temp:
    return temp_dir

def decompress_zip_file(filename):
    # use temp dir
    print("Decompressing zip files")
    temp_folder = create_temp_dir()
    with zipfile.ZipFile(filename, 'r') as zip:
        zip.extractall(path=temp_folder)
    return temp_folder
    
def decompress_tar_file(filename, compression_type):
    print("Inside decompress_tar_file")
    temp_folder = create_temp_dir()
    with tarfile.open(filename, compression_type) as tar:
        # insert extract path
        tar.extractall(path=temp_folder)
        print("Temp Folder: ", temp_folder)
        print("Finished extraction")
    return temp_folder

def extract_tar_file(filename):
    temp_dir = create_temp_dir()
    try:
        with tarfile.open(filename, 'r') as tar:
            print("Opened tarfile")
            tar.extractall(path=temp_dir)
            print("All files extracted of tar file")      
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except tarfile.TarError as e:
        print(f"Error extracting tar file: {e}")

    return temp_dir
