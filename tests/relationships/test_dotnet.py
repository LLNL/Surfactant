# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

sbom = SBOM(
    software=[
        Software(
            UUID="application",
            fileName=["application"],
            installPath=["C:\\application"],
            metadata=[
                {
                    "dotnetAssemblyRef": [{"Name": "samedirlib"}],
                },
                {
                    "dotnetAssemblyRef": [{"Name": "subdirlib"}],
                },
                {
                    "dotnetAssemblyRef": [
                        {
                            "Name": "culturelib",
                            "Culture": "culture",
                        }
                    ],
                },
            ],
        ),
        Software(
            UUID="samedirlib",
            fileName=["samedirlib.dll"],
            installPath=["C:\\samedirlib.dll"],
        ),
        Software(
            UUID="subdirlib",
            fileName=["subdirlib.dll"],
            installPath=["C:\\subdirlib\\subdirlib.dll"],
        ),
        Software(
            UUID="culturelib",
            fileName=["culturelib.dll"],
            installPath=["C:\\culture\\culturelib.dll"],
        ),
    ],
)


def test_same_directory():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[0]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship("application", "samedirlib", "Uses")
    ]


def test_subdir():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[1]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship("application", "subdirlib", "Uses")
    ]


def test_culture():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[2]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship("application", "culturelib", "Uses")
    ]
