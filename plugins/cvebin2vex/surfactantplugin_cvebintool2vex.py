# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
from pathlib import Path
from cle import CLECompatibilityError
from loguru import logger
import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
import subprocess
from datetime import datetime
import uuid
import sys


def run_cve_bin_tool(input_file_path, shaHash, output_dir):
    cvebin_file_name = f"{shaHash}_{input_file_path.stem}.json"
    output_file_path = output_dir / cvebin_file_name

    cdxvex_file_name = f"{shaHash}_{input_file_path.stem}.cdxvex"
    vex_output_path = output_dir / cdxvex_file_name

    try:
        command = [
            'cve-bin-tool',
            '--offline',
            '--output', str(output_file_path),
            '--format', 'json',
            '--vex',
            str(vex_output_path),
            '--input-file',
            str(input_file_path)
        ]
        subprocess.run(command, check=True)
        logger.info(f"Output saved to {output_file_path}")
        return output_file_path  # Return path to the generated JSON file
    except subprocess.CalledProcessError as e:
        logger.info(f"Error running CVE-bin-tool: {e}", file=sys.stderr)
        return None


def convert_cve_to_openvex(json_output_path, shaHash, output_dir):
    openvex_file_name = f"{shaHash}_{json_output_path.stem}.vex"
    openvex_output = output_dir / openvex_file_name
    
    # Open and read the .json file
    try:
        with open(json_output_path, 'r') as file:
            cve_data = json.load(file)
    except Exception as e:
        logger.info(f"Error reading JSON file: {e}")
        return

    openvex_template = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "Surfactant plugin cvebintool2vex",
        "timestamp": datetime.now().isoformat(),
        "version": 1,
        "tooling": "Surfactant (https://github.com/LLNL/Surfactant)",
        "statements": []
    }

    for entry in cve_data:
        # Convert CVE data to OpenVEX format
        statement = {
            "vulnerability": {
                "name": entry["cve_number"]
            },
            "products": [
                {
                    "@id": f"cpe:2.3:a:{entry['vendor']}:{entry['product']}:{entry['version']}:::::"
                }
            ],
            "status": "under_investigation",
            "source": entry["source"],
            "cvss_version": entry["cvss_version"],
            "cvss_vector": entry["cvss_vector"],
            "severity": entry["severity"]
        }
        openvex_template["statements"].append(statement)

    # Save the OpenVEX output to a new file
    try:
        with open(openvex_output, 'w') as outfile:
            json.dump(openvex_template, outfile, indent=4)
        logger.info(f"OpenVEX Output Path: {openvex_output}")
    except Exception as e:
        logger.info(f"Error writing OpenVEX file: {e}")


def process_input(input_path, shaHash, output_dir=None):
    input_path = Path(input_path)
    if output_dir is None:
        output_dir = Path.cwd() / 'cvebintool2vexoutput'
        if not output_dir.exists():
            output_dir.mkdir(parents=True)

    output_directory = Path(output_dir)
    output_directory.mkdir(exist_ok=True)

    if input_path.is_dir():
        for input_file in input_path.glob('*.*'):
            if input_file.suffix.lower() not in ['.bin', '.exe', '.jar']:
                continue
            process_file(input_file, shaHash, output_directory)
    elif input_path.is_file():
        process_file(input_path, shaHash, output_directory)
    else:
        logger.info(f"Error: {input_path} is neither a file nor a directory.")


def process_file(input_file, shaHash, output_directory):
    try:
        run_cve_bin_tool(input_file, shaHash, output_directory)
    except Exception as e:
        logger.info(f"Proccess file exception: {e}")


    cvebin_file_name = f"{shaHash}_{input_file.stem}.json"
    jsonfile = output_directory / cvebin_file_name

    if jsonfile and jsonfile.exists():
        convert_cve_to_openvex(jsonfile, shaHash, output_directory)


@surfactant.plugin.hookimpl(specname="extract_file_info")
# cvebintool2vwx(sbom: SBOM, software: Software, filename: str, filetype: str):
def cvebintool2vex(sbom: SBOM, software: Software, filename: str, filetype: str):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """
    # Only parsing executable files
    if filetype not in ["ELF", "PE"]:
        pass
    shaHash = str(software.sha256)
    filename = Path(filename)
    process_input(filename, shaHash)
