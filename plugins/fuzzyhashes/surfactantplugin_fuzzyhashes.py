# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT


# TODO: Read and write file once

import json
from pathlib import Path
import logging

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
import ssdeep
import tlsh


def do_tlsh(bin_data: bytes):
    return tlsh.hash(bin_data)

def do_ssdeep(bin_data: bytes):
    return ssdeep.hash(bin_data)

@surfactant.plugin.hookimpl(specname="extract_file_info")
# extract_strings(sbom: SBOM, software: Software, filename: str, filetype: str):
# def fuzzyhashes(filename: str, filetype: str, filehash: str):
def fuzzyhashes(sbom: SBOM, software: Software, filename: str, filetype: str):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """

    hashdata = [(do_ssdeep, "ssdeep"), (do_tlsh, "tlsh")]

    # Only parsing executable files
    # if filetype not in ["ELF", "PE"]:
    #     pass
    # filehash = str(software.sha256)
    # filename = Path(filename)
    # flist = []

    # # Performing check to see if file has been analyzed already
    # existing_json = None
    # output_name = None
    # for f in Path.cwd().glob("*.json"):
    #     flist.append((f.stem).split("_")[0])
    #     if filehash == (f.stem).split("_")[0]:
    #         existing_json = f
    #         output_name = f

    # output_path = Path.cwd() / f"{filehash}_additional_metadata.json"

    # if existing_json:
    #     with open(existing_json, "r") as json_file:
    #         existing_data = json.load(json_file)
        # Validate the file path
    existing_data = {}
    filename = Path(filename)
    if not filename.exists():
        raise FileNotFoundError(f"No such file: '{filename}'")

    # if filename.name not in existing_data["filename"]:
    #     existing_data["filename"].append(filename.name)

    if all([hashname in existing_data for _, hashname in hashdata]):
        # if everything is already in there, we just want to terminate without writing
        return None
    with open(filename, "rb") as f_bin:
        bin_data = f_bin.read()

    for hashfunc, hashname in hashdata:
        if hashname in existing_data:
            logging.info(f"Already {hashname} hashed {filename.name}")
        else:
            logging.info(
                f"Found existing JSON file for {filename.name} but without '{hashname}' key. Proceeding with hashing."
            )
            existing_data[hashname] = hashfunc(bin_data)
    return existing_data
           
