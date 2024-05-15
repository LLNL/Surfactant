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
from surfactant.sbomtypes import SBOM, Relationship

# Generate Sample SBOMs
sbom1_json = """{
  "software": [
    {
      "UUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "fileName": [
        "helics.tar.gz"
      ]
    },
    {
      "UUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "fileName": [
        "helics_binary"
      ],
      "installPath": [
        "/bin/helics_binary"
      ],
      "containerPath": [
        "dd6f7f6b-7c31-4a4a-afef-14678b9942bf/bin/helics_binary"
      ]
    },
    {
      "UUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "fileName": [
        "lib1.so"
      ],
      "installPath": [
        "/lib64/lib1.so"
      ],
      "containerPath": [
        "dd6f7f6b-7c31-4a4a-afef-14678b9942bf/lib64/lib1.so"
      ]
    }
  ],
  "relationships": [
    {
      "xUUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "yUUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "relationship": "Uses"
    },
    {
      "xUUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "yUUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "relationship": "Contains"
    },
    {
      "xUUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "yUUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "relationship": "Contains"
    }
  ]
}"""


def get_sbom1():
    return SBOM.from_json(sbom1_json)


sbom2_json = """{
        "software": [
            {
            "UUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "name": null,
            "size": null,
            "fileName": [
                "helics_plugin.tar.gz"
            ]
            },
            {
            "UUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "fileName": [
                "helics_plugin"
            ],
            "installPath": [
                "/bin/helics_plugin"
            ],
            "containerPath": [
                "625a07da-7eed-47b9-a0fa-47dcbf76574a/bin/helics_plugin"
            ]
            },
            {
            "UUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "fileName": [
                "lib_plugin.so"
            ],
            "installPath": [
                "/lib64/lib_plugin.so"
            ],
            "containerPath": [
                "625a07da-7eed-47b9-a0fa-47dcbf76574a/lib64/lib_plugin.so"
            ]
            }
        ],
        "relationships": [
            {
            "xUUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "yUUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "relationship": "Uses"
            },
            {
            "xUUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "yUUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "relationship": "Contains"
            },
            {
            "xUUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "yUUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "relationship": "Contains"
            }
        ]
        }"""


def get_sbom2():
    return SBOM.from_json(sbom2_json)


def get_config():
    return {
        "system": {
            "UUID": "6a0ee431-842f-4963-8867-ef0ef6998003",
            "name": "",
            "vendor": None,
            "captureStart": 1689186121,
            "captureEnd": 1689186146,
        }
    }


def get_sbom3():
    with open(
        pathlib.Path(__file__).parent / "../data/sample_sboms/helics_binaries_sbom.json",
        "r",
    ) as f:
        return SBOM.from_json(f.read())


def get_sbom4():
    with open(
        pathlib.Path(__file__).parent / "../data/sample_sboms/helics_libs_sbom.json", "r"
    ) as f:
        return SBOM.from_json(f.read())


# Test Functions
def test_simple_merge_method():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    merged_sbom = sbom1
    merged_sbom.merge(sbom2)
    softwares = sbom1.software
    softwares.extend(sbom2.software)
    assert merged_sbom.software.sort(key=lambda x: x.UUID) == softwares.sort(key=lambda x: x.UUID)
    relations = sbom1.relationships
    relations.update(sbom2.relationships)
    assert sorted(merged_sbom.relationships, key=lambda x: x.xUUID) == sorted(
        relations, key=lambda x: x.xUUID
    )


@pytest.mark.skip(reason="No way of validating this test yet")
def test_merge_with_circular_dependency():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    circular_dependency_sbom = sbom1
    circular_dependency_sbom.relationships.add(
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
        merge(input_sboms, sbom_outfile, get_config(), output_writer)
    # TODO add validation checks here
    os.remove(os.path.abspath(outfile_name))


@pytest.mark.skip(reason="No way of properly validating this test yet")
def test_cmdline_merge():
    sbom3 = get_sbom3()
    sbom4 = get_sbom4()
    # Test simple merge of two sboms
    outfile_name = generate_filename("test_cmdline_merge")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    config_file = get_config()
    input_sboms = [sbom3, sbom4]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer)

    # TODO add validation checks here
    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_sbom.json", "r") as j:
        ground_truth_sbom = json.loads(j.read())
    os.remove(os.path.abspath(outfile_name))


def test_merge_with_add_system_true():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_merge_with_add_system_true")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["system"]["UUID"] = "6a0ee431-842f-4963-8867-ef0ef6998003"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    assert generated_sbom["systems"]
    assert generated_sbom["systems"][0]["UUID"] == config_file["system"]["UUID"]

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_add_system_false():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_merge_with_add_system_false")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["system"]["UUID"] = "6a0ee431-842f-4963-8867-ef0ef6998003"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=False)

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    assert not generated_sbom["systems"]

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_custom_system_relationship():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_merge_with_custom_system_relationship")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["systemRelationship"] = "DependsOn"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    for relationship in generated_sbom["relationships"]:
        if relationship["xUUID"] == config_file["system"]["UUID"]:
            assert relationship["relationship"] == "DependsOn"

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_specified_system_uuid():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_merge_with_specified_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    system_uuid = "123e4567-e89b-12d3-a456-426614174000"
    with open(outfile_name, "w") as sbom_outfile:
        merge(
            input_sboms,
            sbom_outfile,
            config_file,
            output_writer,
            add_system=True,
            system_uuid=system_uuid,
        )

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    assert any(system["UUID"] == system_uuid for system in generated_sbom["systems"])

    os.remove(os.path.abspath(outfile_name))


def test_prevent_orphaned_system_uuid():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_prevent_orphaned_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    # Get rid of the system UUID field from the config file
    # This will make it try to generate a random UUID, but won't add it since add_system is False
    del config_file["system"]["UUID"]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=False)

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    assert not generated_sbom["systems"]

    os.remove(os.path.abspath(outfile_name))


def test_add_random_system_uuid():
    sbom1 = get_sbom1()
    sbom2 = get_sbom2()
    outfile_name = generate_filename("test_prevent_orphaned_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    # Get rid of the system UUID field from the config file
    # This will make it try to generate a random UUID, but won't add it since add_system is False
    original_config_system_UUID = config_file["system"]["UUID"]
    del config_file["system"]["UUID"]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name, "r") as j:
        generated_sbom = json.loads(j.read())
    assert generated_sbom["systems"]
    # Check that the UUID of the generated system is actually random
    assert generated_sbom["systems"][0]["UUID"] != original_config_system_UUID

    os.remove(os.path.abspath(outfile_name))


def generate_filename(name, ext=".json"):
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return str(name + "_" + res + ext)
