# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pathlib

from surfactant.cmd.cli import cli_find
from surfactant.sbomtypes import SBOM

with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_sbom.json", "r") as f:
    in_sbom = SBOM.from_json(f.read())

bad_sbom = SBOM(
    {
        "software": [
            {
                "UUID": "477da45b-bb38-450e-93f7-e525aaaa6862",
                "name": None,
                "size": 16367492,
                "fileName": ["helics.tar.gz"],
                "installPath": [],
                "containerPath": [],
                "captureTime": 1689186121,
                "version": "",
                "vendor": [],
                "description": "",
                "sha1": "0d21026ee953eeaa31cafef5118be56f46867267",
                "sha256": "f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
                "md5": "5fbf80df5004db2f0ce1f78b524024fe",
                "relationshipAssertion": "Unknown",
                "comments": "",
                "supplementaryFiles": [],
                "provenance": None,
                "recordedInstitution": "LLNL",
                "components": [],
                "bad_key": 1.24553,
            }
        ]
    }
)


def test_find_by_sha256():
    out_bom = cli_find().execute(
        in_sbom, sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )
    assert len(out_bom.software) == 1
    assert (
        out_bom.software[0].sha256
        == "f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )


def test_find_by_multiple_hashes():
    out_bom = cli_find().execute(
        in_sbom,
        sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
        md5="5fbf80df5004db2f0ce1f78b524024fe",
    )
    assert len(out_bom.software) == 1
    assert (
        out_bom.software[0].sha256
        == "f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )


def test_find_by_mismatched_hashes():
    out_bom = cli_find().execute(
        in_sbom,
        sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
        md5="2ff380e740d2eb09e5d67f6f2cd17636",
    )
    assert len(out_bom.software) == 0


def test_find_by_containerPath():
    out_bom = cli_find().execute(in_sbom, containerpath="477da45b-bb38-450e-93f7-e525aaaa6862/")
    assert len(out_bom.software) == 7


def test_find_with_malformed_sbom():
    out_bom = cli_find().execute(bad_sbom, bad_key=1.24553)  # Unsupported Type
    assert len(out_bom.software) == 0
    out_bom = cli_find().execute(bad_sbom, bad_key="testing")  # Supported Type
    assert len(out_bom.software) == 0


def test_find_with_bad_filter():
    out_bom = cli_find().execute(bad_sbom, bad_filter="testing")  # Supported Type
    assert len(out_bom.software) == 0
    out_bom = cli_find().execute(bad_sbom, bad_filter=1.234)  # Unsupported Type
    assert len(out_bom.software) == 0
