# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path

import binary2strings as b2s
from loguru import logger

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
    existing_json = None
    output_name = None
    for f in Path.cwd().glob("*.json"):
        flist.append((f.stem).split("_")[0])
        if hash == (f.stem).split("_")[0]:
            existing_json = f
            output_name = f

    if existing_json:
        with open(existing_json, "r") as json_file:
            existing_data = json.load(json_file)
        if "strings" in existing_data:
            logger.info(f"Already extracted {filename.name}")
        else:
            logger.info(
                f"Found existing JSON file for {filename.name} but without 'strings' key. Proceeding with extraction."
            )
            # Add your extraction code here.
            if filename.name not in existing_data["filename"]:
                existing_data["filename"].append(filename.name)

            existing_data["strings"] = []
            # Extract and write strings using binary2strings
            with open(filename, "rb") as f_bin:
                data = f_bin.read()
                for string, type, span, is_interesting in b2s.extract_all_strings(
                    data, only_interesting=True
                ):
                    if len(string) >= min_len:
                        existing_data["strings"].append(string)
            # Write the string_dict to the output JSON file
            with open(output_name, "w") as json_file:
                json.dump(existing_data, json_file, indent=4)

    else:
        try:
            # Validate the file path
            if not filename.exists():
                raise FileNotFoundError(f"No such file: '{filename}'")

            # Extract filename without extension
            output_path = Path.cwd() / f"{hash}_additional_metadata.json"
            string_dict = {}
            string_dict["md5hash"] = hash
            string_dict["filename"] = [filename.name]
            string_dict["strings"] = []

            # Extract and write strings using binary2strings
            with open(filename, "rb") as f_bin:
                data = f_bin.read()
                for string, type, span, is_interesting in b2s.extract_all_strings(
                    data, only_interesting=True
                ):
                    # you might adjust the condition below to filter strings based on your needs
                    if len(string) >= min_len:
                        string_dict["strings"].append(string)

            # Write the string_dict to the output JSON file
            with open(output_path, "w") as json_file:
                json.dump(string_dict, json_file, indent=4)

            logger.info(f"Data written to {output_path}")
        except Exception as e:
            logger.info("String Extract Error\nFile:{} Caused error:{}".format(filename, e))
