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

# Check if it's a tar file or zip file
# if tar, check if it's just .tar or a compressed tar
# extract accordingly

# if zip: use zipfile module 

def check_compression_type(filename):
    mode = ''

    if filename.endswith('.zip'):
        decompress_zip_file(filename)
    elif filename.endswith('.tar'):
        open_tar_file(filename)
    elif filename.endswith('.tar.gz'):
        mode = 'r:gz'
    elif filename.endswith('.tar.bz2'):
        mode = 'r:bz2'
    elif filename.endswith('.tar.xz'):
        mode = 'r:xz'
    else:
        print('not supported')
        return
    
    if mode:
        decompress_file(filename, mode)

    if filename.endswith('.zip'):
        decompress_zip_file(filename)


def create_temp_dir(filename):
    with tempfile.TemporaryDirectory() as temp:
        pass


def decompress_zip_file(filename):
    # use temp dir
    pass
    
def decompress_file(filename, compression_type):
    # use temp dir
    with tarfile.open(filename, compression_type) as tar:
        tar.exrtactall()

def open_tar_file(filename):
    #use temp dir
    try:
        if tar_file():
            contents = {}
            with tarfile.open(filename, 'r') as tar:
                print("Opened tarfile")
                tar.extractall(path="scripts/native_libraries/new_dir")
                print("All files extracted")
                               
    except FileNotFoundError:
        print(f"File not found: {filename}")


        # if filename.endswith('.tar'):
        #     with tarfile.open(filename, 'r') as tar:
                
        #         print("Opened tarfile")
        #     tar.extractall(path="./extraction_dir")
        #     print("All files extracted")

        # else:    
        #     with tarfile.open(filename, mode) as tar:
        #         tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3")



tar_file = open_tar_file("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/bgpd.pl-0.08.tar")
print(tar_file)


#try to use tempfile module here so it takes care of cleanup
        # with tarfile.open(filename, "r:bz2") as tar:
        #     tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/new_files")
        
        #     # Save all decompressed files in temp dir
        #     for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/new_files"):
        #         for file_name in files:
        #             file_path = os.path.join(root, file_name)             
    
    # Delete all temp files after matches are found to keep dir clean?  
    # 
    # 