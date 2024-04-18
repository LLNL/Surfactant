# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass


@dataclass
class Relationship:
    xUUID: str
    yUUID: str
    relationship: str

    def __hash__(self) -> int:
        return hash(repr(self))


@dataclass
class StarRelationship:
    xUUID: str
    yUUID: str
    relationship: str

    def __hash__(self) -> int:
        return hash(repr(self))
