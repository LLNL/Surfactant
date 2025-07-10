# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import uuid as uuid_module
from dataclasses import asdict, dataclass, field, fields
from typing import Dict, List, Optional, Set

import networkx as nx
from dataclasses_json import config, dataclass_json
from loguru import logger

from ._analysisdata import AnalysisData
from ._file import File
from ._hardware import Hardware
from ._observation import Observation
from ._provenance import SoftwareProvenance
from ._relationship import Relationship, StarRelationship
from ._software import Software, SoftwareComponent
from ._system import System

INTERNAL_FIELDS = {"software_lookup_by_sha256"}


def recover_serializers(cls):
    """
    After dataclass_json has bound its own to_dict/to_json,
    restore any _to_dict/_to_json overrides.
    """
    if hasattr(cls, "to_dict_override"):
        cls.to_dict = cls.to_dict_override
    if hasattr(cls, "to_json_override"):
        cls.to_json = cls.to_json_override
    return cls


@recover_serializers
@dataclass_json
@dataclass
class SBOM:
    # pylint: disable=R0902
    systems: List[System] = field(default_factory=list)
    hardware: List[Hardware] = field(default_factory=list)
    software: List[Software] = field(default_factory=list)
    # relationships: Set[Relationship] = field(default_factory=set)  # (removed relationships field. Graph is now the single source of truth)
    _loaded_relationships: List[Relationship] = (
        field(  # this metadata will capture the old array on load (but won’t re-emit it)
            default_factory=list,
            metadata=config(field_name="relationships", exclude=lambda _: True),
        )
    )
    analysisData: List[AnalysisData] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    starRelationships: Set[StarRelationship] = field(default_factory=set)
    software_lookup_by_sha256: Dict = field(default_factory=dict)
    graph: nx.MultiDiGraph = field(
        init=False,
        repr=False,
        # metadata=config(exclude=lambda _: True),  # internal graph; excluded from JSON
        metadata=config(exclude=lambda _: True),
    )  # Add a NetworkX directed graph for quick traversal/query

    def __post_init__(self):
        # If called like SBOM(raw_dict), raw_dict will be in .systems
        if isinstance(self.systems, dict) and not self.hardware and not self.software:
            raw = self.systems

            # zero out every container
            self.systems = []
            self.hardware = []
            self.software = []
            self.analysisData = []
            self.observations = []
            self._loaded_relationships = []
            self.starRelationships = set()

            # prepare valid field-name sets
            SYSTEM_FIELDS = {f.name for f in fields(System)}
            HARDWARE_FIELDS = {f.name for f in fields(Hardware)}
            SOFTWARE_FIELDS = {f.name for f in fields(Software)}
            REL_FIELDS = {f.name for f in fields(Relationship)}
            AD_FIELDS = {f.name for f in fields(AnalysisData)}
            OBS_FIELDS = {f.name for f in fields(Observation)}
            STAR_FIELDS = {f.name for f in fields(StarRelationship)}

            # rehydrate systems
            for sys_data in raw.get("systems", []):
                clean = {k: v for k, v in sys_data.items() if k in SYSTEM_FIELDS}
                self.systems.append(System(**clean))

            # rehydrate hardware
            for hw_data in raw.get("hardware", []):
                clean = {k: v for k, v in hw_data.items() if k in HARDWARE_FIELDS}
                self.hardware.append(Hardware(**clean))

            # rehydrate software
            for sw_data in raw.get("software", []):
                clean = {k: v for k, v in sw_data.items() if k in SOFTWARE_FIELDS}
                self.software.append(Software(**clean))

            # rehydrate relationships into the loader list
            for rel_data in raw.get("relationships", []):
                clean = {k: v for k, v in rel_data.items() if k in REL_FIELDS}
                self._loaded_relationships.append(Relationship(**clean))

            # rehydrate analysisData
            for ad_data in raw.get("analysisData", []):
                clean = {k: v for k, v in ad_data.items() if k in AD_FIELDS}
                self.analysisData.append(AnalysisData(**clean))

            # rehydrate observations
            for obs_data in raw.get("observations", []):
                clean = {k: v for k, v in obs_data.items() if k in OBS_FIELDS}
                self.observations.append(Observation(**clean))

            # rehydrate starRelationships
            for sr_data in raw.get("starRelationships", []):
                clean = {k: v for k, v in sr_data.items() if k in STAR_FIELDS}
                self.starRelationships.add(StarRelationship(**clean))

        # Strip out internal-only fields so dataclass logic and JSON serializers ignore them
        # pylint: disable=access-member-before-definition
        self.__dataclass_fields__ = {
            k: v for k, v in self.__dataclass_fields__.items() if k not in INTERNAL_FIELDS
        }

        # Build the NetworkX graph from systems/software and loaded relationships
        self.build_graph()

    def build_graph(self) -> None:
        """Rebuild the directed graph from systems, software, and any loaded relationships."""
        self.graph = nx.MultiDiGraph()
        for sys in self.systems:
            self.graph.add_node(sys.UUID, type="System")
        for sw in self.software:
            self.graph.add_node(sw.UUID, type="Software")
        # rehydrate edges from loaded JSON (if any)
        for rel in self._loaded_relationships:
            self.graph.add_edge(rel.xUUID, rel.yUUID, key=rel.relationship)

    def add_relationship(self, rel: Relationship) -> None:
        # The Relationship object get wired into the graph key=…
        if not self.graph.has_node(rel.xUUID):
            self.graph.add_node(rel.xUUID, type="Unknown")
        if not self.graph.has_node(rel.yUUID):
            self.graph.add_node(rel.yUUID, type="Unknown")

        # the edge key is the relationship type
        self.graph.add_edge(rel.xUUID, rel.yUUID, key=rel.relationship)

    def create_relationship(self, xUUID: str, yUUID: str, relationship: str) -> Relationship:
        # ensure nodes exist
        if not self.graph.has_node(xUUID):
            self.graph.add_node(xUUID, type="Unknown")
        if not self.graph.has_node(yUUID):
            self.graph.add_node(yUUID, type="Unknown")

        # record the edge, keyed by the relationship
        self.graph.add_edge(xUUID, yUUID, key=relationship)

        # return a Relationship object for backwards-compat
        return Relationship(xUUID, yUUID, relationship)

    def find_relationship_object(self, r: Relationship) -> bool:
        """
        Return True if an exact edge (r.xUUID → r.yUUID) exists
        in the graph with key=r.relationship.
        """
        return self.graph.has_edge(r.xUUID, r.yUUID, key=r.relationship)

    def find_relationship(self, xUUID: str, yUUID: str, relationship: str) -> bool:
        """
        Same as find_relationship_object, but takes raw args.
        """
        return self.graph.has_edge(xUUID, yUUID, key=relationship)

    def has_relationship(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> bool:
        """
        Return True if there exists at least one edge u→v in the graph
        matching the optional filters (u, v, and/or relationship key).
        """
        # Fast-path if all three are specified
        if xUUID and yUUID and relationship:
            return self.graph.has_edge(xUUID, yUUID, key=relationship)

        # Otherwise scan all edges with keys
        for u, v, key in self.graph.edges(keys=True):
            if xUUID and u != xUUID:
                continue
            if yUUID and v != yUUID:
                continue
            if relationship and key.upper() != relationship.upper():
                continue
            return True
        return False

    def find_software(self, sha256: Optional[str]) -> Optional[Software]:
        if sha256 in self.software_lookup_by_sha256:
            return self.software_lookup_by_sha256[sha256]
        return None

    def add_software(self, sw: Software) -> None:
        if sw.sha256 is not None:
            self.software_lookup_by_sha256[sw.sha256] = sw
        self.software.append(sw)

        # Add a node for the new software
        if not self.graph.has_node(sw.UUID):
            self.graph.add_node(sw.UUID, type="Software")

    def add_software_entries(
        self, entries: Optional[List[Software]], parent_entry: Optional[Software] = None
    ):
        """Add software entries, merging duplicates and preserving all relationship edges.

        Args:
            entries (Optional[List[Software]]): A list of Software entries to add to the SBOM.
            parent_entry (Optional[Software]): An optional parent software entry to add "Contains" relationships to.
        """
        if not entries:
            return
        # if a software entry already exists with a matching file hash, augment the info in the existing entry
        for e in entries:
            existing = self.find_software(e.sha256)
            if existing and Software.check_for_hash_collision(existing, e):
                logger.warning(f"Hash collision between {existing.name} and {e.name}")

            if not existing:
                # new software → add node
                self.add_software(e)
                entry_uuid = e.UUID
            else:
                # duplicate → merge and redirect edges
                kept_uuid, old_uuid = existing.merge(e)

                # redirect *incoming* edges to the kept node
                for src, _, key, attrs in list(self.graph.in_edges(old_uuid, keys=True, data=True)):
                    self.graph.add_edge(src, kept_uuid, key=key, **attrs)

                # redirect *outgoing* edges from the old node
                for _, dst, key, attrs in list(
                    self.graph.out_edges(old_uuid, keys=True, data=True)
                ):
                    self.graph.add_edge(kept_uuid, dst, key=key, **attrs)

                # remove the old UUID entirely
                if self.graph.has_node(old_uuid):
                    self.graph.remove_node(old_uuid)
                entry_uuid = kept_uuid

            # if a parent/package container was provided, attach a "Contains" edge
            if parent_entry:
                parent_uuid = parent_entry.UUID
                if not self.graph.has_edge(parent_uuid, entry_uuid, key="Contains"):
                    self.graph.add_edge(parent_uuid, entry_uuid, key="Contains")

    # pylint: disable=too-many-arguments
    def create_software(
        self,
        *,  # all arguments are keyword-only
        name: Optional[str] = None,
        size: Optional[int] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        fileName: Optional[List[str]] = None,
        installPath: Optional[List[str]] = None,
        containerPath: Optional[List[str]] = None,
        captureTime: Optional[int] = None,
        version: Optional[str] = None,
        vendor: Optional[List[str]] = None,
        description: Optional[str] = None,
        relationshipAssertion: Optional[str] = None,
        comments: Optional[str] = None,
        metadata: Optional[List[object]] = None,
        supplementaryFiles: Optional[List[File]] = None,
        provenance: Optional[List[SoftwareProvenance]] = None,
        recordedInstitution: Optional[str] = None,
        components: Optional[List[SoftwareComponent]] = None,
    ) -> Software:
        sw = Software(
            name=name,
            size=size,
            sha1=sha1,
            sha256=sha256,
            md5=md5,
            fileName=fileName,
            installPath=installPath,
            containerPath=containerPath,
            captureTime=captureTime,
            version=version,
            vendor=vendor,
            description=description,
            relationshipAssertion=relationshipAssertion,
            comments=comments,
            metadata=metadata,
            supplementaryFiles=supplementaryFiles,
            provenance=provenance,
            recordedInstitution=recordedInstitution,
            components=components,
        )
        self.software_lookup_by_sha256[sw.sha256] = sw
        self.software.append(sw)
        return sw

    def merge(self, sbom_m: SBOM):
        # merged/old to new UUID map
        uuid_updates: Dict[str, str] = {}

        # 1) Merge systems
        if sbom_m.systems:
            for system in sbom_m.systems:
                # check for duplicate UUID/name, merge with existing entry
                if existing_system := self._find_systems_entry(uuid=system.UUID, name=system.name):
                    # merge system entries
                    u1, u2 = existing_system.merge(system)
                    logger.info(f"MERGE_DUPLICATE_SYS: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1

                    # Redirect any existing edges from u2 -> u1 in self.graph
                    if hasattr(self, "graph") and self.graph.has_node(u2):
                        # for each predecessor of u2, add edge (pred -> u1)
                        # Redirect incoming edges to the merged node u1
                        for pred, _, key, attrs in self.graph.in_edges(u2, keys=True, data=True):
                            self.graph.add_edge(pred, u1, key=key, **attrs)

                        # For each successor of u2, add edge (u1 -> succ)
                        # Redirect outgoing edges from u2 → u1
                        for _, succ, key, attrs in self.graph.out_edges(u2, keys=True, data=True):
                            self.graph.add_edge(u1, succ, key=key, **attrs)

                        # Then drop the old node
                        self.graph.remove_node(u2)

                else:
                    self.systems.append(system)

                    # Add the new system node into the graph
                    if hasattr(self, "graph"):
                        self.graph.add_node(system.UUID, type="System")

        # 2) Merge software
        if sbom_m.software:
            for sw in sbom_m.software:
                # NOTE: Do we want to pass in teh UUID here? What if we have two different UUIDs for the same file? Should hashes be required?
                if existing_sw := self._find_software_entry(
                    uuid=sw.UUID, sha256=sw.sha256, md5=sw.md5, sha1=sw.sha1
                ):
                    u1, u2 = existing_sw.merge(sw)
                    logger.info(f"MERGE DUPLICATE: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1

                    # Redirect any existing edges from u2 -> u1 in self.graph
                    if hasattr(self, "graph") and self.graph.has_node(u2):
                        # Redirect incoming edges to the merged node u1
                        for pred, _, key, attrs in self.graph.in_edges(u2, keys=True, data=True):
                            self.graph.add_edge(pred, u1, key=key, **attrs)
                        # Redirect outgoing edges from u2 → u1
                        for _, succ, key, attrs in self.graph.out_edges(u2, keys=True, data=True):
                            self.graph.add_edge(u1, succ, key=key, **attrs)

                        # Then drop the old node
                        self.graph.remove_node(u2)

                else:
                    self.software.append(sw)

                    # Add the new software node in the graph
                    if hasattr(self, "graph"):
                        self.graph.add_node(sw.UUID, type="Software")

        # 3) Merge relationships from the incoming SBOM’s MultiDiGraph
        for src, dst, rel_type in sbom_m.graph.edges(keys=True):
            # apply any UUID remaps from merged systems/software
            xUUID = uuid_updates.get(src, src)
            yUUID = uuid_updates.get(dst, dst)

            # skip exact duplicates
            if self.graph.has_edge(xUUID, yUUID, key=rel_type):
                logger.info(f"DUPLICATE RELATIONSHIP: {xUUID} → {yUUID} [{rel_type}]")
            else:
                # add a new edge, keyed by the relationship
                self.graph.add_edge(xUUID, yUUID, key=rel_type)

        # 4) Rewrite any containerPath UUIDs
        for sw in self.software:
            if sw.containerPath:
                for idx, path in enumerate(sw.containerPath):
                    u = path[:36]
                    # if container path starts with an invalid uuid4, sbom might not be valid
                    if self.is_valid_uuid4(u):
                        if u in uuid_updates:
                            updated_path = path.replace(u, uuid_updates[u], 1)
                            sw.containerPath[idx] = updated_path
                # remove duplicates
                sw.containerPath = [*set(sw.containerPath)]

        logger.info(f"UUID UPDATES: {uuid_updates}")

        # 5) Merge analysisData, observations, starRelationships
        for ad in sbom_m.analysisData:
            self.analysisData.append(ad)
        for obs in sbom_m.observations:
            self.observations.append(obs)
        for star_rel in sbom_m.starRelationships:
            # rewrite UUIDs before doing the search
            if star_rel.xUUID in uuid_updates:
                star_rel.xUUID = uuid_updates[star_rel.xUUID]
            if star_rel.yUUID in uuid_updates:
                star_rel.yUUID = uuid_updates[star_rel.yUUID]
            if existing_star_rel := self._find_star_relationship_entry(
                xUUID=star_rel.xUUID,
                yUUID=star_rel.yUUID,
                relationship=star_rel.relationship,
            ):
                logger.info(f"DUPLICATE STAR RELATIONSHIP: {existing_star_rel}")
            else:
                self.starRelationships.add(star_rel)

    def _find_systems_entry(
        self, uuid: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[System]:
        """Merge helper function to find and return
        the matching system entry in the provided sbom.

        Args:
            uuid (Optional[str]): The uuid of the desired system entry.
            name (Optional[str]): The name of the desired system entry.

        Returns:
            Optional[System]: The system found that matches the given criteria, otherwise None.
        """
        for system in self.systems:
            if uuid:
                if system.UUID != uuid:
                    continue
            if name:
                if system.name != name:
                    continue
            return system
        return None

    def _find_software_entry(
        self,
        uuid: Optional[str] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
    ) -> Optional[Software]:
        """Merge helper function to find and return
        the matching software entry in the provided sbom.

        Args:
            uuid (Optional[str]): The uuid of the desired software entry to match against if no hashes were provided.
            sha256 (Optional[str]): The sha256 of the desired software entry.
            md5 (Optional[str]): The md5 of the desired software entry.
            sha1 (Optional[str]): The sha1 of the desired software entry.

        Returns:
            Optional[Software]: The software entry found that matches the given criteria, otherwise None.
        """
        for sw in self.software:
            match = False
            # If we have hashes to check
            if sha256 or md5 or sha1:
                # Check if we have both sides of the comparison, then compare. At least one hash must match
                if sw.sha256 and sha256:
                    if sw.sha256 == sha256:
                        match = True
                if sw.md5 and md5:
                    if sw.md5 == md5:
                        match = True
                if sw.sha1 and sha1:
                    if sw.sha1 == sha1:
                        match = True
            # If no hashes to check, match by UUID
            else:
                if sw.UUID == uuid:
                    match = True
            if match:
                return sw
        return None

    def _find_relationship_entry(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> Optional[Relationship]:
        """Merge helper function to find and return
        the matching relationship entry in the provided sbom.

        Locate and return the first matching Relationship object
        found in the MultiDiGraph.

        Args:
            xUUID (Optional[str]): The xUUID of the desired relationship entry.
            yUUID (Optional[str]): The yUUID of the desired relationship entry.
            relationship (Optional[str]): The relationship type of the desired relationship entry.

        Returns:
            Optional[Relationship]: The relationship entry found that matches the given criteria, otherwise None.
        """
        for u, v, key in self.graph.edges(keys=True):
            if xUUID and u != xUUID:
                continue
            if yUUID and v != yUUID:
                continue
            if relationship and key.upper() != relationship.upper():
                continue
            # reconstruct the Relationship object for merge‐logic
            return Relationship(xUUID=u, yUUID=v, relationship=key)
        return None

    def _find_star_relationship_entry(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> Optional[StarRelationship]:
        """Merge helper function to find and return
        the matching star relationship entry in the provided sbom.

        Args:
            xUUID (Optional[str]): The xUUID of the desired relationship entry.
            yUUID (Optional[str]): The yUUID of the desired relationship entry.
            relationship (Optional[str]): The relationship type of the desired relationship entry.

        Returns:
            Optional[StarRelationship]: The star relationship found that matches the given criteria, otherwise None.
        """
        for rel in self.starRelationships:
            if xUUID:
                if rel.xUUID != xUUID:
                    continue
            if yUUID:
                if rel.yUUID != yUUID:
                    continue
            if relationship:
                if rel.relationship != relationship:
                    continue
            return rel
        return None

    def is_valid_uuid4(self, u: str) -> bool:
        """Merge helper function to check if a uuid is valid.

        Args:
            u (str):  The UUID to check.

        Returns:
            bool: True if the UUID is valid, otherwise False.
        """
        try:
            u_test = uuid_module.UUID(u, version=4)
        except ValueError:
            return False
        return str(u_test) == u

    def get_children(self, xUUID: str, rel_type: Optional[str] = None) -> List[str]:
        """
        Return all v such that there is an edge xUUID → v,
        optionally filtered by relationship key.
        """
        children = []
        for _, v, key in self.graph.out_edges(xUUID, keys=True):
            if rel_type is None or key.upper() == rel_type.upper():
                children.append(v)
        return children

    def get_parents(self, yUUID: str, rel_type: Optional[str] = None) -> List[str]:
        """
        Return all u such that there is an edge u → yUUID,
        optionally filtered by relationship key.
        """
        parents = []
        for u, _, key in self.graph.in_edges(yUUID, keys=True):
            if rel_type is None or key.upper() == rel_type.upper():
                parents.append(u)
        return parents

    def to_dict_override(self) -> dict:
        """
        Dump all SBOM dataclass fields (via asdict), strip out internal-only
        fields, convert sets→lists, and then build a fresh
        'relationships' list by iterating every edge key in the MultiDiGraph.
        """
        # Grab everything as a dict
        data = asdict(self)

        # Remove fields we never want in JSON
        data.pop("graph", None)
        data.pop("_loaded_relationships", None)

        # Turn any sets into lists for JSON
        for k, v in list(data.items()):
            if isinstance(v, set):
                data[k] = list(v)

        # Rebuild 'relationships' from the graph's edge keys
        data["relationships"] = [
            {"xUUID": u, "yUUID": v, "relationship": key}
            for u, v, key in self.graph.edges(keys=True)
        ]

        return data

    def to_json_override(self, *args, **kwargs) -> str:
        """
        Serialize via our to_dict_override, passing through any json.dumps kwargs.
        """
        return json.dumps(self.to_dict_override(), *args, **kwargs)
