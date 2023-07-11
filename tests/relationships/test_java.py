# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

sbom = SBOM(
    software=[
        Software(
            UUID="supplier",
            fileName=["supplier"],
            installPath=["supplier"],
            metadata=[{"javaClasses": {"dummy": {"javaExports": ["someFunc():void"]}}}],
        ),
        Software(
            UUID="consumer",
            fileName=["consumer"],
            installPath=["consumer"],
            metadata=[
                {
                    "javaClasses": {
                        "dummy": {
                            "javaExports": [],
                            "javaImports": ["someFunc():void"],
                        },
                    },
                },
            ],
        ),
    ],
    relationships=[],
)


def test_java_relationship():
    javaPlugin = get_plugin_manager().get_plugin("surfactant.relationships.java_relationship")
    sw = sbom.software[1]
    md = sw.metadata[0]
    assert javaPlugin.establish_relationships(sbom, sw, md) == [
        Relationship("consumer", "supplier", "Uses")
    ]
