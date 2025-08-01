# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional, Dict

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

def has_required_fields(metadata) -> bool:
    """Checks if the metadata is an RPM file containing associated files.
    Args:
        metadata (dict): Metadata dictionary to check."""
    return "rpm" in metadata and "associated_files" in metadata["rpm"]


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    if not has_required_fields(metadata) or len(sbom.software) == 0:
        return None

    relationships: List[Relationship] = []
    parent_uuid = software.UUID
    files: Dict = metadata["rpm"]["associated_files"]
    hashes: Dict[str, str] = {}
    for file_path, file_hash in files.items():
        hashes[file_hash] = file_path
    
    
    for item in sbom.software:
        if item.size >= 10 and item.md5 != "" and item.md5 in hashes:
            child_uuid = item.UUID
            relationship = Relationship(
                parent_uuid,
                child_uuid,
                "Installs",
            )
            relationships.append(relationship)
    return relationships