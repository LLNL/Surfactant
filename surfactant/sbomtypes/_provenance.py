# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from typing import List, Optional

# pylint: disable=too-many-instance-attributes


@dataclass
class SystemProvenance:
    fieldName: str  # enum: captureStart, captureEnd, name, officialName, vendor, description
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None


@dataclass
class HardwareProvenance:
    fieldName: str  # enum: name, captureTime, officialName, countryOfOrigin, countryOfOriginSource, quantity, description, vendor, identifiers, hardwareType, comments, metadata, packageType, boardLocation, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None


@dataclass
class SoftwareComponentProvenance:
    fieldName: str  # enum: name, captureTime, version, vendor, description, comments, metadata, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None


@dataclass
class SoftwareProvenance:
    fieldName: str  # enum: name, size, fileName, installPath, containerPath, captureTime, version, vendor, description, sha1, sha256, md5, relationshipAssertion, comments, metadata, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None


@dataclass
class AnalysisDataProvenance:
    fieldName: str  # enum: origin, testName, testVersion, specificEnvironment, linksToKnownVulnerabilities
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None


@dataclass
class ObservationProvenance:
    fieldName: str  # enum: flag, CWEClass, targetEnvironmentOrDevice, potentialEffectOrImpact, CVE, CVSS, analystInfo, discovery, toRecreate, mitigationSuggestions, confidenceLevel
    capturedBy: Optional[str] = None
    captureTime: Optional[int] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None
