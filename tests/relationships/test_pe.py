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
            fileName=["application.exe"],
            installPath=["C:\\application.exe"],
            metadata=[
                {
                    "peImport": ["library.dll"],
                }
            ],
        ),
        Software(
            UUID="library", fileName=["library.dll"], installPath=["C:\\library.dll"], metadata=[{}]
        ),
    ],
)


def test_same_directory():
    plugin = get_plugin_manager().get_plugin("surfactant.relationships.pe_relationship")
    app = sbom.software[0]
    md = app.metadata[0]
    assert plugin.establish_relationships(sbom, app, md) == [
        Relationship("application", "library", "Uses")
    ]
