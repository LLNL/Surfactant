# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import r2pipe
import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


#@surfactant.plugin.hookimpl
def r2import_finder(filename: str, filetype: str):
    """
    Extract list of imported function from a binary file using radare2.
    :param filename (str): The full path to the file.
    :param filetype (str): File type information based on magic bytes.
    """
    # Only parsing executable files
    if filetype not in ["ELF", "PE"]:
        pass
    print("r2import {}".format(filename))
    filename = Path(filename)
    if not filename.exists():
        raise FileNotFoundError(f"No such file: '{filename}'")

    # Extract filename without extension
    output_path = Path.cwd() / f"imports_{filename.stem}.json"
    string_dict = {}
    string_dict["filename"] = filename.name
    string_dict["imported functions"] = []
    try:
        # Create a radare2 instance
        r2 = r2pipe.open(filename._str)
        # Enable radare2 to analyze the binary
        r2.cmd('aaa')
        # Exporting Imported Functions
        imported_functions = json.loads(r2.cmd('iij'))
        with open(output_path, 'w') as f:
            json.dump(imported_functions, f, indent=4)
        print(f"Exported imported functions to {output_path}")
        # Close the radare2 instance
        r2.quit()
    except Exception as e:
        print("r2error {}".format(e))
    return print("r2out")