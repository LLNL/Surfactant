# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid as uuid_module
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from dataclasses_json import dataclass_json
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


@dataclass_json
@dataclass
class SBOM:
    # pylint: disable=R0902
    systems: List[System] = field(default_factory=list)
    hardware: List[Hardware] = field(default_factory=list)
    software: List[Software] = field(default_factory=list)
    relationships: Set[Relationship] = field(default_factory=set)
    analysisData: List[AnalysisData] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    starRelationships: Set[StarRelationship] = field(default_factory=set)
    software_lookup_by_sha256: Dict = field(default_factory=dict)

    def __post_init__(self):
        self.__dataclass_fields__ = {
            k: v for k, v in self.__dataclass_fields__.items() if k not in INTERNAL_FIELDS
        }

    def add_relationship(self, rel: Relationship) -> None:
        self.relationships.add(rel)

    def create_relationship(self, xUUID: str, yUUID: str, relationship: str) -> Relationship:
        rel = Relationship(xUUID, yUUID, relationship)
        self.relationships.add(rel)
        return rel

    def find_relationship_object(self, relationship: Relationship) -> bool:
        return relationship in self.relationships

    def find_relationship(self, xUUID: str, yUUID: str, relationship: str) -> bool:
        return Relationship(xUUID, yUUID, relationship) in self.relationships

    def has_relationship(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> bool:
        for rel in self.relationships:
            # We iterate until we find a relationship that meets all the conditions
            if xUUID and rel.xUUID != xUUID:
                continue
            if yUUID and rel.yUUID != yUUID:
                continue
            if relationship and rel.relationship.upper() != relationship.upper():
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

    def add_software_entries(
        self, entries: Optional[List[Software]], parent_entry: Optional[Software] = None
    ):
        """Add software entries to the SBOM, merging into existing entries as needed.

        Args:
            entries (Optional[List[Software]]): A list of Software entries to add to the SBOM.
            parent_entry (Optional[Software]): An optional parent software entry to add "Contains" relationships to.
        """
        if not entries:
            return
        # if a software entry already exists with a matching file hash, augment the info in the existing entry
        for e in entries:
            existing_sw = self.find_software(e.sha256)
            if existing_sw and Software.check_for_hash_collision(existing_sw, e):
                logger.warning(
                    f"Hash collision between {existing_sw.name} and {e.name}; unexpected results may occur"
                )
            if not existing_sw:
                self.add_software(e)
            else:
                existing_uuid, entry_uuid = existing_sw.merge(e)
                # go through relationships and see if any need existing entries updated for the replaced uuid (e.g. merging SBOMs)
                for rel in self.relationships:
                    if rel.xUUID == entry_uuid:
                        rel.xUUID = existing_uuid
                    if rel.yUUID == entry_uuid:
                        rel.yUUID = existing_uuid
            # if a parent/container was specified for the file, add the new entry as a "Contains" relationship
            if parent_entry:
                parent_uuid = parent_entry.UUID
                child_uuid = existing_uuid if existing_sw else e.UUID
                # avoid duplicate relationships if the software entry already existed
                if not existing_sw or not self.find_relationship(
                    parent_uuid, child_uuid, "Contains"
                ):
                    self.create_relationship(parent_uuid, child_uuid, "Contains")
            # TODO a pass later on to check for and remove duplicate relationships should be added just in case

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
        uuid_updates = {}

        # merge systems entries
        if sbom_m.systems:
            for system in sbom_m.systems:
                # check for duplicate UUID/name, merge with existing entry
                if existing_system := self._find_systems_entry(uuid=system.UUID, name=system.name):
                    # merge system entries
                    u1, u2 = existing_system.merge(system)
                    logger.info(f"MERGE_DUPLICATE_SYS: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1
                else:
                    self.systems.append(system)

        # merge software entries
        if sbom_m.software:
            for sw in sbom_m.software:
                # NOTE: Do we want to pass in teh UUID here? What if we have two different UUIDs for the same file? Should hashes be required?
                if existing_sw := self._find_software_entry(
                    uuid=sw.UUID, sha256=sw.sha256, md5=sw.md5, sha1=sw.sha1
                ):
                    u1, u2 = existing_sw.merge(sw)
                    logger.info(f"MERGE DUPLICATE: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1
                else:
                    self.software.append(sw)

        # merge relationships
        if sbom_m.relationships:
            for rel in sbom_m.relationships:
                # rewrite UUIDs before doing the search
                if rel.xUUID in uuid_updates:
                    rel.xUUID = uuid_updates[rel.xUUID]
                if rel.yUUID in uuid_updates:
                    rel.yUUID = uuid_updates[rel.yUUID]
                if existing_rel := self._find_relationship_entry(
                    xUUID=rel.xUUID,
                    yUUID=rel.yUUID,
                    relationship=rel.relationship,
                ):
                    logger.info(f"DUPLICATE RELATIONSHIP: {existing_rel}")
                else:
                    self.relationships.add(rel)

        # rewrite container path UUIDs using rewrite map/list
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
        # merge analysisData
        if sbom_m.analysisData:
            for analysisData in sbom_m.analysisData:
                self.analysisData.append(analysisData)
        # merge observations
        if sbom_m.observations:
            for observation in sbom_m.observations:
                self.observations.append(observation)
        # merge starRelationships
        if sbom_m.starRelationships:
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

        Args:
            xUUID (Optional[str]): The xUUID of the desired relationship entry.
            yUUID (Optional[str]): The yUUID of the desired relationship entry.
            relationship (Optional[str]): The relationship type of the desired relationship entry.

        Returns:
            Optional[Relationship]: The relationship entry found that matches the given criteria, otherwise None.
        """
        for rel in self.relationships:
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
