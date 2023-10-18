# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from pathlib import Path
import angr
import surfactant.plugin
import json
from loguru import logger


@surfactant.plugin.hookimpl
def angrimport_finder(filename: str, filetype: str, filehash:str):
    """
    Extract list of imported function names from a binary file using angr.
    :param filename (str): The full path to the file.
    :param filetype (str): File type information based on magic bytes.
    :param filehash (str): MD5 hash of the file.
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
        if filehash == (f.stem).split("_")[0]:
            existing_json = f
            output_name = f

    if existing_json:
        with open(existing_json, "r") as json_file:
            existing_data = json.load(json_file)
        if "imported function names" in existing_data:
            logger.info(f"Already extracted {filename.name}")
        else:
            try:
                logger.info(
                    f"Found existing JSON file for {filename.name} but without 'imported functions' key. Proceeding with extraction."
                )
                # Add your extraction code here.
                if filename.name not in existing_data["filename"]:
                    existing_data["filename"].append(filename.name)
                existing_data["imported function names"] = []
                # Create an angr project
                project = angr.Project(filename, auto_load_libs=False)

                # Get the imported functions using symbol information
                for symbol in project.loader.main_object.symbols:
                    if symbol.is_function:
                        existing_data["imported function names"].append(symbol.name)

                # Write the string_dict to the output JSON file
                with open(output_name, "w") as json_file:
                    json.dump(existing_data, json_file, indent=4)
            except Exception as e:
                logger.info("Angr Error {} {}".format(filename, e))
    else:
        try:
            # Validate the file path
            if not filename.exists():
                raise FileNotFoundError(f"No such file: '{filename}'")

            # Extract filename without extension
            output_path = Path.cwd() / f"{hash}_additional_metadata.json"
            metadata = {}
            metadata["md5hash"] = filehash
            metadata["filename"] = [filename.name]
            metadata["imported function names"] = []
            # Create an angr project
            project = angr.Project(filename._str, auto_load_libs=False)

            # Get the imported functions using symbol information
            for symbol in project.loader.main_object.symbols:
                if symbol.is_function:
                    metadata["imported function names"].append(symbol.name)

            # Write the string_dict to the output JSON file
            with open(output_path, "w") as json_file:
                json.dump(metadata, json_file, indent=4)

            logger.info(f"Data written to {output_path}")
        except Exception as e:
            logger.info("Angr Error {} {}".format(filename._str, e))
