import json
import subprocess
import time
from typing import List, Optional

import surfactant.plugin
from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: str, children: list
) -> Optional[List[Software]]:
    pm = get_plugin_manager()
    # Change to properly filter filetypes, add to if statement for filetypes syft should run for
    if filetype == "TAR":
        data = subprocess.check_output(
            "anchore_syft " + filename + " -o json --scope all-layers", shell=True
        )
        data = json.loads(data.decode())
        for i in data["artifacts"]:
            sw_entry = Software(
                sha1=None,
                # Syft does not provide a SHA256 for each artifact.
                # This uses their unique IDs in place since surfactant is dependent on this hash.
                # TODO (Ryan) discuss how to handle software entry without a hash with Lucas in the CyTRICS SBOM schema
                sha256=i["id"],
                md5=None,
                name=[i["name"]],
                fileName=None,
                installPath=[i["locations"][0]["path"]],
                containerPath=[filename],
                size=i["metadata"]["installedSize"],
                captureTime=int(time.time()),
                version=i["metadata"]["version"],
                vendor=[i["metadata"]["maintainer"]],
                description="",
                relationshipAssertion="Unknown",
                comments="Discovered using the Syft plugin with this cataloger: " + i["foundBy"],
                metadata=[],
                supplementaryFiles=[],
                provenance=None,
                components=[],
            )
            for file in i["metadata"]["files"]:
                if file["path"] not in sw_entry.supplementaryFiles:
                    sw_entry.supplementaryFiles.append(file["path"])
            for file in i["locations"]:
                if file["path"] not in sw_entry.supplementaryFiles:
                    sw_entry.supplementaryFiles.append(file["path"])
            children.append(sw_entry)
        gather_relationship_data(software, data, children)


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    relationship_list = []
    for meta in software.metadata:
        if "syftRelationships" in meta:
            for rel in meta["syftRelationships"]:
                relationship_list.append(Relationship(rel[0], rel[1], rel[2]))
    return relationship_list


def gather_relationship_data(image_sw: Software, data: str, sw_list: list):
    uuid_dict = {}
    # Build UUID dict for fast lookup
    # First entry is the image sw entry
    uuid_dict[data["source"]["id"]] = [-1, image_sw.UUID]
    for count, sw in enumerate(sw_list):
        index_uuid_list = [count, sw.UUID]
        uuid_dict[sw.sha256] = index_uuid_list
    for rel in data["artifactRelationships"]:
        # Both the parent and the child must have an existing software object
        if rel["parent"] in uuid_dict and rel["child"] in uuid_dict:
            parent_info = uuid_dict[rel["parent"]]
            child_info = uuid_dict[rel["child"]]
            if parent_info[0] == -1:
                sw = image_sw
            else:
                sw = sw_list[parent_info[0]]
            sw.relationshipAssertion = "Known"
            sw_list[child_info[0]].relationshipAssertion = "Known"
            relationship_list = []
            for meta in sw.metadata:
                if "syftRelationships" in meta:
                    relationship_list = meta["syftRelationships"]
                    break
            # Software object did not already have a list of syft relationships
            if len(relationship_list) == 0:
                sw.metadata.append({})
                sw.metadata[-1]["syftRelationships"] = relationship_list
            relationship_list.append([parent_info[1], child_info[1], rel["type"]])
