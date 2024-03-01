# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT


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
# def fuzzyhashes(filename: str, filetype: str, filehash: str):
def fuzzyhashes(sbom: SBOM, software: Software, filename: str, filetype: str):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """

    hashdata = [(do_ssdeep, "ssdeep"), (do_tlsh, "tlsh")]

    # Validate the file path
    existing_data = {}
    filename = Path(filename)
    if not filename.exists():
        raise FileNotFoundError(f"No such file: '{filename}'")

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
           
