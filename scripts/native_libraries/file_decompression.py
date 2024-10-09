import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger
import tarfile
import zipfile
import tempfile
import os

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

def check_compression_type(filename):
    mode = ''

    if filename.endswith('.zip'):
        print("It's a zip file")
        temp_folder = decompress_zip_file(filename)
    elif filename.endswith('.tar'):
        print("this is a tar file")
        temp_folder = extract_tar_file(filename)
    elif filename.endswith('.tar.gz'):
        mode = 'r:gz'
    elif filename.endswith('.tar.bz2'):
        print("Mode is bz2")
        mode = 'r:bz2'
    elif filename.endswith('.tar.xz'):
        mode = 'r:xz'
    else:
        print("Compression format not supported")
    
    if mode:
        print("Calling decompress tar file")
        temp_folder = decompress_tar_file(filename, mode)
        print("After calling decompress_tar_file: ", temp_folder)
    return temp_folder

def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix='surfactant-temp')
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
        print("this is Temp Folder: ", temp_folder)
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