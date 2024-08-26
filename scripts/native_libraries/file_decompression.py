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
        decompress_zip_file(filename)
    elif filename.endswith('.tar'):
        open_tar_file(filename)
    elif filename.endswith('.tar.gz'):
        mode = 'r:gz'
    elif filename.endswith('.tar.bz2'):
        print("hello")
        mode = 'r:bz2'
    elif filename.endswith('.tar.xz'):
        mode = 'r:xz'
    else:
        print('not supported')
    
    if mode:
        print("we have mode")
        decompress_tar_file(filename, mode)

def create_temp_dir():
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix='surfactant-temp')
    #with tempfile.TemporaryDirectory() as temp:
    return temp_dir


def decompress_zip_file(filename):
    # use temp dir
    pass
    
def decompress_tar_file(filename, compression_type):
    # use temp dir
    temp_dir = create_temp_dir()
    with tarfile.open(filename, compression_type) as tar:
        # insert extract path
        tar.extractall(path=temp_dir)
        print("extracted")
        # return extracted file to native_lib_file ? so the func should return this dir

def open_tar_file(filename):
    #use temp dir
    temp_dir = create_temp_dir()
    try:
        contents = {}
        with tarfile.open(filename, 'r') as tar:
            print("Opened tarfile")
            tar.extractall(path=temp_dir)
            print("All files extracted")
                               
    except FileNotFoundError:
        print(f"File not found: {filename}")





# tar_file = open_tar_file("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/bgpd.pl-0.08.tar")
# print(tar_file)