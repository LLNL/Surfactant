# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from collections.abc import Iterable

from loguru import logger

from surfactant.sbomtypes import SBOM


# TODO for an intermediate SBOM format, have ability to search more efficiently by hashes/filepath/filename
# currently, establishing relationships is something around O(n^2) due to searching entire sbom for matches
def parse_relationships(pluginmanager, sbom: SBOM):
    for i, sw in enumerate(sbom.software):
        logger.info(f"Determining relationship {i + 1}/{len(sbom.software)}")
        # Skip for temporary files/installer that don't have any installPath or metadata to find dependencies with
        if sw.installPath is None or sw.metadata is None:
            continue

        # Find metadata saying what dependencies are used by the software entry
        for md in sw.metadata:
            # handle ELF dependencies, PE imports, and dotNet assembly references using included plugins
            for relationships in pluginmanager.hook.establish_relationships(
                sbom=sbom, software=sw, metadata=md
            ):
                if isinstance(relationships, Iterable):
                    for r in relationships:
                        if not sbom.find_relationship_object(r):
                            sbom.add_relationship(r)
