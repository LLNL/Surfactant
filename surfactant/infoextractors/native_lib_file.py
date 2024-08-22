import json
import pathlib
import re
from typing import Any, Dict, List

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant.filetypeid import id_magic
#from enum import Enum, auto

def check_compression(filename):
    if is_tar_file() or is_zip_file:
        # call file_decompression
        pass

def supports_file(filetype) -> bool:
    return filetype in ("PE", "ELF", "MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_native_lib_info(filename)

def extract_native_lib_info(filename):
    native_lib_info: Dict[str, Any] = {"nativeLibraries": []}
    native_lib_patterns = pathlib.Path(__file__).parent / "native_lib_patterns.json"
    with open(native_lib_patterns, "r") as f:
        patterns = json.load(f)

    for name, library in patterns.items():
        if "filename" in library:
            for pattern in library["filename"]:
                try:
                    if re.search(pattern, filename):
                        print("found through filename")
                        return name
                except re.error as e:
                    print(f"Invalid regex filename pattern '{pattern}': {e}")

    try:
        #try to use tempfile module here so it takes care of cleanup
        # first check to see if file is compressed? .tar is not compressed
        # if not compressed, keep it here
        # if compressed, call tar_decompression() -> 
        
        # check to see if file is compressed (tar or zip file)
        



        with tarfile.open(filename, "r:bz2") as tar:
            tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_5")

        match_list = []
        
        for name, library in expressions.items():
            if "filecontent" in library:
                for pattern in library["filecontent"]:
                    try:
                        # Save all decompressed files in temp dir
                        # loop through all files in temp dir and search against patterns below
                        for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_5"):
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                try:
                                    with open(file_path, "r", encoding="ISO-8859-1") as f:
                                        contents = f.read()
                                        if re.search(pattern, contents):
                                            print("found through filecontent")
                                            match_list.append(name)
                                except Exception as e:
                                    print(f"Could not read file {file_path}: {e}")            
                    except re.error as e:
                        print(f"Regex error with filecontent pattern '{pattern}': {e}")     
        return match_list  
    
    # Delete all temp files after matches are found to keep dir clean?
                                     
    except FileNotFoundError:
        print(f"File not found: {filename}")
    print("No matches found.")
    return None

def is_tar_file(filename: str) -> bool:
    pattern = r'\.tar(\.(gz|bz2|xz))?$'
    return bool(re.search(pattern, filename))

def is_zip_file(filename: str) -> bool:
    pattern = r'\.zip$'
    return bool(re.search(pattern, filename))