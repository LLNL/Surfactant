import pathlib
from collections.abc import Iterable
from typing import Dict, List, Optional, Tuple
import json

import cyclonedx.output
from cyclonedx.model import HashAlgorithm, HashType, OrganizationalEntity, Tool
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency

import surfactant.plugin
from surfactant import __version__ as surfactant_version
from surfactant.sbomtypes import SBOM, Software, System

# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from typing import Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def read_sbom(infile) -> SBOM:    
    bom = Bom.from_json(data=json.loads(infile.read()))
    sbom = SBOM()
    
    # Keep track of dependecies
    # bom_ref -> xuuid, dependencies -> yuuids
    # Keep track of which generated UUIDs map to which bom refs 
    for dependency in bom.dependencies:
        print(dependency)
        print(dependency.dependencies)

    # Create a CyTRICS software entry for each CycloneDX component
    for component in bom.components:
        print(component)
        # If a component detail can be mapped to a detail in a software entry, then add to software entry details
        # Otherwise, add detail to software entry's metadata section
        # Add CycloneDX metadata section to metadata section of each software entry?
    


    return sbom


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "cyclonedx"

def convert_cyclonedx_components_to_software(
    component: Component,
) -> List[Tuple[str, str, Software]]:
    return 