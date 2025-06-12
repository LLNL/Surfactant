# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
from pathlib import Path

import angr
from cle import CLECompatibilityError
from loguru import logger

import surfactant.plugin


@surfactant.plugin.hookimpl(specname="extract_file_info")
# extract_strings(sbom: SBOM, software: Software, filename: str, filetype: str):
# def angrimport_finder(filename: str, filetype: str, filehash: str):
def reachability(filename: str, filetype: str):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """

    # Only parsing executable files
    if filetype not in ["ELF", "PE"]:
        pass
    filename = Path(filename)

    # Performing check to see if the file exists or not
    output_path = Path.cwd() / "reachability.json"

    if output_path.exists():
        with open(output_path, "r") as json_file:
            database = json.load(json_file)
    else:
        database = {}

    try:
        if not filename.exists():
            raise FileNotFoundError(f"No such file: '{filename}'")
        # Add your extraction code here.
        # Create an angr project
        project = angr.Project(filename, load_options={"auto_load_libs": True})

        # library dependencies {import: library}
        lookup = {}
        for obj in project.loader.main_object.imports.keys():
            library = project.loader.find_symbol(obj).owner.provides
            lookup[obj] = library

        # recreates our angr project without the libraries loaded to save on time
        project = angr.Project(filename, load_options={"auto_load_libs": False})

        cfg = project.analyses.CFGFast()

        # holds every export address error is here
        exports = [
            func.rebased_addr for func in project.loader.main_object.symbols if func.is_export
        ]  # _exports is only available for PE files
        database[filename.name] = {}

        # go through every exported function
        for exp_addr in exports:
            exp_name = cfg.functions.get(exp_addr).name
            database[filename.name][exp_name] = {}

            # goes through every function that is reachable from exported function
            for imported_address in cfg.functions.callgraph.successors(exp_addr):
                imported_function = cfg.functions.get(imported_address)

                # checks if the function is imported
                if imported_function.name in project.loader.main_object.imports.keys():
                    library = lookup[imported_function.name]

                    if library not in database[filename.name][exp_name].keys():
                        database[filename.name][exp_name][library] = []

                    # adds our reachable imported function as a dependency
                    if imported_function.name not in database[filename.name][exp_name][library]:
                        database[filename.name][exp_name][library].append(imported_function.name)

        # Write the string_dict to the output JSON file
        with open(output_path, "w") as json_file:
            json.dump(database, json_file, indent=4)

    except CLECompatibilityError as e:
        logger.info(f"Angr Error {filename} {e}")
