from dataclasses import dataclass


@dataclass
class Relationship:
    xUUID: str
    yUUID: str
    relationship: str


@dataclass
class StarRelationship:
    xUUID: str
    yUUID: str
    relationship: str
