# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import binary2strings as b2s
import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl
def extract_strings(filename: str, hash: str, filetype: str, min_len=4):
    """
    Extract ASCII strings from a binary file using binary2strings.
    :param filename (str): The full path to the file to extract information from.
    :param hash (str): md5 hash of the file
    :param filetype (str): File type information based on magic bytes.
    :param min_len (int): Minimum length of strings to be considered valid.
    """
    # Only parsing executable files
    if filetype not in ["ELF", "PE"]:
        pass

    filename = Path(filename)
    flist = []
    # Performing check to see if file has been analyzed already
    for f in Path.cwd().glob("*.json"):
        flist.append((f.stem).split("_")[0])
    if hash in flist:
        print("Already extracted {}".format(filename.name))
        pass
    else:
        try:
            # Validate the file path
            if not filename.exists():
                raise FileNotFoundError(f"No such file: '{filename}'")
            string_dict = {}
            # Extract filename without extension
            string_dict["md5hash"] = hash
            string_dict["filename"] = filename.name
            string_dict["strings"] = []

            # Extract and write strings using binary2strings
            with open(filename, "rb") as f_bin:
                data = f_bin.read()
                for string, type, span, is_interesting in b2s.extract_all_strings(
                    data, only_interesting=True
                ):
                    if len(string) >= min_len:
                        string_dict["strings"].append(string)

            return string_dict
        except Exception as e:
            print("String Extract Error\nFile:{} Caused error:{}".format(filename, e))
