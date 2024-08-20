import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger
import tarfile
import os

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

def open_tar_file(filename):
    try:
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
        contents = {}
        with tarfile.open(filename, 'r') as tar:
            print("Opened tarfile")
            tar.extractall(path="scripts/native_libraries/new_dir")
            print("All files extracted")
                               
    except FileNotFoundError:
        print(f"File not found: {filename}")



tar_file = open_tar_file("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/bgpd.pl-0.08.tar")
print(tar_file)