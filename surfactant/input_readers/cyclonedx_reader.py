from typing import Dict, Optional, Tuple
import json
import uuid

from cyclonedx.model import HashAlgorithm
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

import surfactant.plugin
from surfactant import __version__ as surfactant_version
from surfactant.sbomtypes import SBOM, Software, SoftwareComponent, Relationship

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
    uuids = {}

    for xdependency in bom.dependencies:
        #print(xdependency)
        #print(xdependency.dependencies)
        xbomref = xdependency.ref.value
        if not xbomref in uuids.keys():
            new_uuid = str(uuid.uuid4())
            uuids[xbomref] = new_uuid
        xuuid = uuids[xbomref]
        # xuuid = xbomref # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref
        
        for ydependency in xdependency.dependencies:
            ybomref = ydependency.ref.value
            if not ybomref in uuids.keys():
                new_uuid = str(uuid.uuid4())
                uuids[ybomref] = new_uuid
            yuuid = uuids[ybomref]
            # yuuid = ybomref # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref

            # It is unclear what different CycloneDX dependency types exist outside of the type shown in the official examples of CycloneDX SBOM types
            # and how those would map to CyTRICS's relationship types, so each relationship between CycloneDX components will be labeled as "Contains" for the time being
            # TODO: Add in other relationship type mappings
            rel_type = "Contains"
            cytrics_rel = Relationship(xUUID=xuuid,yUUID=yuuid,relationship=rel_type)
            sbom.add_relationship(cytrics_rel)

    # print(sbom.relationships)
    # Create a CyTRICS software entry for each CycloneDX component
    for component in bom.components:
        # print(component)
        # If a component detail can be mapped to a detail in a software entry, then add to software entry details
        # Otherwise, add detail to software entry's metadata section
        # Add CycloneDX metadata section to metadata section of each software entry?
        c_uuid, sw = convert_cyclonedx_components_to_software(component, uuids)
        sbom.add_software(sw)
        if component.bom_ref.value:
            uuids[component.bom_ref.value] = c_uuid
    
    # Do the same thing for the component from the CycloneDX metadata section (if there is one) because its bom-ref can appear in the dependencies
    if bom.metadata.component:
        mc_uuid, msw = convert_cyclonedx_components_to_software(bom.metadata.component, uuids)
        sbom.add_software(msw)
        if bom.metadata.component.bom_ref.value:
            uuids[bom.metadata.component.bom_ref.value] = mc_uuid


    return sbom


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "cyclonedx"

def convert_cyclonedx_components_to_software(
    component: Component, uuids: Dict
) -> Tuple[str, Software]:
    print(component.bom_ref)
    bomref = component.bom_ref.value
    if (not bomref) or (not bomref in uuids.keys()):
        cytrics_uuid = str(uuid.uuid4())
    else:
        cytrics_uuid = uuids[bomref]
    
    # cytrics_uuid = bomref # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref

    name = component.name
    description = component.description
    # CycloneDX only supports one supplier, so the vendor list will only contain one vendor
    vendor = [component.supplier]
    version = component.version
    hashes = {
        "SHA-1": None,
        "SHA-256": None,
        "MD5": None
    }
    for hash in component.hashes:
        if hash.alg == HashAlgorithm.SHA_1:
            hashes.update({"SHA-1": hash.content})
        elif hash.alg == HashAlgorithm.SHA_256:
            hashes.update({"SHA-256": hash.content})
        elif hash.alg == HashAlgorithm.MD5:
            hashes.update({"MD5": hash.content})
    
    # Convert subcomponents of CycloneDX components into components of the corresponding CyTRICS software entry
    sw_components = []
    for subcomp in component.components:
        sw_comp = convert_cyclonedx_subcomponents_to_software_components(subcomp)
        sw_components.append[sw_comp]
    
    # Add remaining data that is exclusive to CycloneDX component entries into the metadata section of the CyTRICS software entry
    metadata = {}
    if component.type:
        metadata["type"] = component.type
    if component.mime_type:
        metadata["mime_type"] = component.mime_type
    if component.publisher:
        metadata["publisher"] = component.publisher
    if component.group:
        metadata["group"] = component.group
    if component.scope:
        metadata["scope"] = component.scope
    if component.licenses:
        metadata["licenses"] = component.licenses
    if component.copyright:
        metadata["copyright"] = component.copyright
    if component.purl:
        metadata["purl"] = component.purl
    if component.external_references:
        metadata["external_references"] = component.external_references
    if component.properties:
        metadata["properties"] = component.properties
    if component.release_notes:
        metadata["release_notes"] = component.release_notes
    if component.cpe:
        metadata["cpe"] = component.cpe
    if component.swid:
        metadata["swid"] = component.swid
    if component.pedigree:
        metadata["pedigree"] = component.pedigree
    if component.evidence:
        metadata["evidence"] = component.evidence
    if component.modified:
        metadata["modified"] = component.modified
    if component.manufacturer:
        metadata["manufacturer"] = component.manufacturer
    if component.authors:
        metadata["authors"] = component.authors
    if component.omnibor_ids:
        metadata["omnibor_ids"] = component.omnibor_ids
    if component.swhids:
        metadata["swhids"] = component.swhids
    if component.crypto_properties:
        metadata["crypto_properties"] = component.crypto_properties
    if component.tags:
        metadata["tags"] = component.tags

    # TODO: Is it possible to distinguish CycloneDX files from containers?

    sw_entry = Software(
        UUID=cytrics_uuid,
        name=name,
        fileName="",
        installPath=[""],
        containerPath=[""],
        version=version,
        vendor=vendor,
        description=description,
        sha1=hashes["SHA-1"],
        sha256=hashes["SHA-256"],
        md5=hashes["MD5"],
        metadata=metadata,
        components=sw_components
    )

    return cytrics_uuid, sw_entry

def convert_cyclonedx_subcomponents_to_software_components(
    component: Component,
) -> SoftwareComponent:
    name = component.name
    description = component.description
    # CycloneDX only supports one supplier, so vendor list will only contain one vendor
    vendor = [component.supplier]
    version = component.version

    sw_component = SoftwareComponent(
        name=name,
        version=version,
        vendor=vendor,
        description=description
    )

    return sw_component