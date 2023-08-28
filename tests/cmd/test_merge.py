# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import os
import pathlib
import random
import string

import pytest

from surfactant.cmd.merge import merge
from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

# Generate Sample SBOMs
sbom1 = SBOM(
    software=[
        Software(UUID="dd6f7f6b-7c31-4a4a-afef-14678b9942bf", fileName=["helics.tar.gz"]),
        Software(
            UUID="08526f02-8f08-485d-bfd1-ea16ce964fd2",
            fileName=["helics_binary"],
            installPath=["/bin/helics_binary"],
            containerPath=["dd6f7f6b-7c31-4a4a-afef-14678b9942bf/bin/helics_binary"],
        ),
        Software(
            UUID="a5db7e12-fe3d-490e-90b8-98a8bfaace09",
            fileName=["lib1.so"],
            installPath=["/lib64/lib1.so"],
            containerPath=["dd6f7f6b-7c31-4a4a-afef-14678b9942bf/lib64/lib1.so"],
        ),
    ],
    relationships=[
        Relationship(
            xUUID="08526f02-8f08-485d-bfd1-ea16ce964fd2",
            yUUID="a5db7e12-fe3d-490e-90b8-98a8bfaace09",
            relationship="Uses",
        ),
        Relationship(
            xUUID="dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
            yUUID="08526f02-8f08-485d-bfd1-ea16ce964fd2",
            relationship="Contains",
        ),
        Relationship(
            xUUID="dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
            yUUID="a5db7e12-fe3d-490e-90b8-98a8bfaace09",
            relationship="Contains",
        ),
    ],
)

sbom2 = SBOM(
    software=[
        Software(
            UUID="625a07da-7eed-47b9-a0fa-47dcbf76574a",
            fileName=["helics_plugin.tar.gz"],
        ),
        Software(
            UUID="820d3ddc-14d7-4ce5-833c-beede8725366",
            fileName=["helics_plugin"],
            installPath=["/bin/helics_plugin"],
            containerPath=["625a07da-7eed-47b9-a0fa-47dcbf76574a/bin/helics_plugin"],
        ),
        Software(
            UUID="df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            fileName=["lib_plugin.so"],
            installPath=["/lib64/lib_plugin.so"],
            containerPath=["625a07da-7eed-47b9-a0fa-47dcbf76574a/lib64/lib_plugin.so"],
        ),
    ],
    relationships=[
        Relationship(
            xUUID="820d3ddc-14d7-4ce5-833c-beede8725366",
            yUUID="df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            relationship="Uses",
        ),
        Relationship(
            xUUID="625a07da-7eed-47b9-a0fa-47dcbf76574a",
            yUUID="820d3ddc-14d7-4ce5-833c-beede8725366",
            relationship="Contains",
        ),
        Relationship(
            xUUID="625a07da-7eed-47b9-a0fa-47dcbf76574a",
            yUUID="df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            relationship="Contains",
        ),
    ],
)

sbom3 = None
sbom4 = None

config = {
    "system": {
        "UUID": "6a0ee431-842f-4963-8867-ef0ef6998003",
        "name": "",
        "vendor": None,
        "captureStart": 1689186121,
        "captureEnd": 1689186146,
    }
}

with open(
    pathlib.Path(__file__).parent / "../data/sample_sboms/helics_binaries_sbom.json", "r"
) as f:
    sbom3 = SBOM.from_json(f.read())
with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_libs_sbom.json", "r") as f:
    sbom4 = SBOM.from_json(f.read())


# Test Functions
def test_simple_merge_method():
    merged_sbom = sbom1
    merged_sbom.merge(sbom2)
    softwares = sbom1.software
    softwares.extend(sbom2.software)
    assert merged_sbom.software.sort(key=lambda x: x.UUID) == softwares.sort(key=lambda x: x.UUID)
    relations = sbom1.relationships
    relations.extend(sbom2.relationships)
    assert merged_sbom.relationships.sort(key=lambda x: x.xUUID) == relations.sort(
        key=lambda x: x.xUUID
    )


@pytest.mark.skip(reason="No way of validating this test yet")
def test_merge_with_circular_dependency():
    circular_dependency_sbom = sbom1
    circular_dependency_sbom.relationships.append(
        Relationship(
            xUUID="a5db7e12-fe3d-490e-90b8-98a8bfaace09",
            yUUID="dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
            relationship="Contains",
        )
    )

    outfile_name = generate_filename("test_merge_with_circular_dependency")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [circular_dependency_sbom, sbom2]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config, output_writer)
    # TODO add validation checks here
    os.remove(os.path.abspath(outfile_name))


@pytest.mark.skip(reason="No way of properly validating this test yet")
def test_cmdline_merge():
    # Test simple merge of two sboms
    outfile_name = generate_filename("test_cmdline_merge")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    config_file = config
    input_sboms = [sbom3, sbom4]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer)

    # TODO add validation checks here
    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_sbom.json", "r") as j:
        ground_truth_sbom = json.loads(j.read())
    os.remove(os.path.abspath(outfile_name))


def generate_filename(name, ext=".json"):
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return str(name + "_" + res + ext)
