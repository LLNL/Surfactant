# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import argparse
import json
import os
import re

# The following code adds the data present in additional_metadata.json files to an input
# sbom and outputs it at a new location.

#     - It uses the sha256hash field to perform linkages
#     - It does overwrite the output location

# Usage:
#     python3 scripts/merge_additional_metadata.py . sbom_without_metadata.json output_sbom_file.json


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "metadata_dir",
        help='The directory that contains the "additional metadata" files',
    )
    parser.add_argument("input_sbom", help="The SBOM for the additional metadata to be merged into")
    parser.add_argument("output_file", help="The output file")
    _args = parser.parse_args()
    return _args


if __name__ == "__main__":
    args = parse_args()
    with open(args.input_sbom) as f:
        sbom_data = json.load(f)
    lookup_table = {
        sbom_node["sha256"]: index for index, sbom_node in enumerate(sbom_data["software"])
    }
    for path in os.scandir(args.metadata_dir):
        if re.match("[a-z0-9]{64}_additional_metadata.json", path.name):
            with open(path) as f:
                additional_data = json.load(f)
            if additional_data["sha256hash"] in lookup_table:
                index = lookup_table[additional_data["sha256hash"]]
                if "metadata" not in sbom_data["software"][index]:
                    sbom_data["software"][index]["metadata"] = []
                sbom_data["software"][index]["metadata"].append(additional_data)
    with open(args.output_file, "w") as f:
        json.dump(sbom_data, f, indent=4)
