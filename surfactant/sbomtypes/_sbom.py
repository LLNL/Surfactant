from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import dataclass_json

from ._analysisdata import AnalysisData
from ._file import File
from ._hardware import Hardware
from ._observation import Observation
from ._provenance import SoftwareProvenance
from ._relationship import Relationship, StarRelationship
from ._software import Software, SoftwareComponent
from ._system import System


@dataclass_json
@dataclass
class SBOM:
    systems: List[System] = field(default_factory=list)
    hardware: List[Hardware] = field(default_factory=list)
    software: List[Software] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    analysisData: List[AnalysisData] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    starRelationships: List[StarRelationship] = field(default_factory=list)

    def add_relationship(self, rel: Relationship) -> None:
        self.relationships.append(rel)

    def create_relationship(self, xUUID: str, yUUID: str, relationship: str) -> Relationship:
        rel = Relationship(xUUID, yUUID, relationship)
        self.relationships.append(rel)
        return rel

    def find_relationship_object(self, relationship: Relationship) -> bool:
        return relationship in self.relationships

    def find_relationship(self, xUUID: str, yUUID: str, relationship: str) -> bool:
        return Relationship(xUUID, yUUID, relationship) in self.relationships

    def find_software(self, sha256: Optional[str]) -> Optional[Software]:
        for sw in self.software:
            if sha256 == sw.sha256:
                return sw
        return None

    def add_software(self, sw: Software) -> None:
        self.software.append(sw)

    # pylint: disable=too-many-arguments
    def create_software(
        self,
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
        self.software.append(sw)
        return sw
