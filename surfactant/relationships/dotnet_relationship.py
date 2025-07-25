import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path

def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes .NET assembly references.
    """
    return "dotnetAssemblyRef" in metadata


import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path

def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes .NET assembly references.
    """
    return "dotnetAssemblyRef" in metadata


import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path
from surfactant.relationships._internal.windows_utils import find_installed_software

def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes .NET assembly references.
    """
    return "dotnetAssemblyRef" in metadata or "dotnetImplMap" in metadata


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: Establish 'Uses' relationships for .NET assembly dependencies.

    Implements a 3-phase resolution strategy:
      1. Primary: Exact path match using sbom.get_software_by_path() (fs_tree)
      2. Secondary: Legacy match using installPath + fileName
      3. Tertiary: Heuristic fallback using fileName and shared parent directories

    Also supports:
    - Resolving unmanaged native libraries via dotnetImplMap
    - Honor .NET app.config probing and codeBase href paths
    - Filter matches using version and culture info

    Args:
        sbom (SBOM): The current SBOM graph.
        software (Software): The importing software.
        metadata (dict): Parsed metadata for .NET imports.

    Returns:
        Optional[List[Relationship]]: A list of relationships (or None).
    """
    if not has_required_fields(metadata):
        logger.debug(f"[.NET] Skipping: No usable .NET metadata for {software.UUID}")
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID

    # --- Handle unmanaged libraries from dotnetImplMap ---
    if "dotnetImplMap" in metadata:
        for entry in metadata["dotnetImplMap"]:
            ref = entry.get("Name")
            if not ref:
                continue

            logger.debug(f"[.NET] Resolving unmanaged import: {ref}")
            combinations = [ref]
            if not (ref.endswith(".dll") or ref.endswith(".exe")):
                combinations.append(f"{ref}.dll")
            combinations.extend([
                f"{ref}.so", f"lib{ref}.so",
                f"{ref}.dylib", f"lib{ref}.dylib", f"lib{ref}"
            ])

            probedirs = []
            if isinstance(software.installPath, Iterable):
                for ip in software.installPath:
                    probedirs.append(pathlib.PureWindowsPath(ip).parent.as_posix())

            for match in find_installed_software(sbom, probedirs, combinations):
                if match.UUID != dependent_uuid:
                    logger.debug(f"[.NET] Unmanaged DLL resolved: {ref} → {match.UUID}")
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))

    # --- Extract appConfig metadata ---
    probing_paths = []
    dependent_assemblies = []
    if "appConfigFile" in metadata:
        cfg = metadata["appConfigFile"]
        if "runtime" in cfg:
            rt = cfg["runtime"]
            if "assemblyBinding" in rt:
                ab = rt["assemblyBinding"]
                dependent_assemblies = ab.get("dependentAssembly", [])
                probing = ab.get("probing", {})
                if "privatePath" in probing:
                    for path in probing["privatePath"].split(";"):
                        probing_paths.append(pathlib.PureWindowsPath(path).as_posix())

    imports = metadata.get("dotnetAssemblyRef", [])
    logger.debug(f"[.NET] {software.UUID} importing {len(imports)} assemblies")

    for asmRef in imports:
        refName = asmRef.get("Name")
        refVersion = asmRef.get("Version")
        refCulture = asmRef.get("Culture")
        if not refName:
            continue

        logger.debug(f"[.NET] Resolving assembly: {refName} (version={refVersion}, culture={refCulture})")
        fname_variants = [refName]
        if not (refName.endswith(".dll") or refName.endswith(".exe")):
            fname_variants.append(f"{refName}.dll")

        # --- Check codeBase hrefs first ---
        for dep in dependent_assemblies:
            href = dep.get("codeBase", {}).get("href")
            if href and not href.startswith("http") and not href.startswith("file://"):
                for ip in software.installPath or []:
                    cb_path = normalize_path(pathlib.PurePath(ip).parent, href)
                    match = sbom.get_software_by_path(cb_path)
                    if match and match.UUID != dependent_uuid:
                        logger.debug(f"[.NET][codeBase] Matched {href} → {match.UUID}")
                        relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))

        # --- Build probing dirs (installPath + privatePath) ---
        probedirs = []
        if isinstance(software.installPath, Iterable):
            for ip in software.installPath:
                base = pathlib.PurePath(ip).parent
                probedirs.append(base.as_posix())
                probedirs.extend([normalize_path(base, p) for p in probing_paths])

        matched_uuids = set()
        used_method = {}

        def is_valid_match(sw: Software) -> bool:
            if sw.UUID == dependent_uuid:
                return False
            for md in sw.metadata or []:
                asm = md.get("dotnetAssembly")
                if asm:
                    sw_version = asm.get("Version")
                    sw_culture = asm.get("Culture")
                    if refVersion and sw_version and sw_version != refVersion:
                        logger.debug(f"[.NET] Skipping {sw.UUID}: version {sw_version} ≠ {refVersion}")
                        return False
                    if refCulture and sw_culture and sw_culture != refCulture:
                        logger.debug(f"[.NET] Skipping {sw.UUID}: culture {sw_culture} ≠ {refCulture}")
                        return False
            return True

        # Phase 1: fs_tree lookup
        for dir in probedirs:
            for fname in fname_variants:
                path = normalize_path(dir, fname)
                match = sbom.get_software_by_path(path)
                if match and is_valid_match(match):
                    logger.debug(f"[.NET][fs_tree] {path} → {match.UUID}")
                    matched_uuids.add(match.UUID)
                    used_method[match.UUID] = "fs_tree"

        # Phase 2: Legacy installPath + fileName
        if not matched_uuids:
            for sw in sbom.software:
                if not is_valid_match(sw):
                    continue
                if isinstance(sw.fileName, Iterable) and any(fn in sw.fileName for fn in fname_variants):
                    if isinstance(sw.installPath, Iterable):
                        for ip in sw.installPath:
                            if any(ip.endswith(fn) for fn in fname_variants):
                                logger.debug(f"[.NET][legacy] Matched {refName} in {ip}")
                                matched_uuids.add(sw.UUID)
                                used_method[sw.UUID] = "legacy_installPath"

        # Phase 3: Heuristic matching by shared directory
        if not matched_uuids:
            for sw in sbom.software:
                if not is_valid_match(sw):
                    continue
                if isinstance(sw.fileName, Iterable) and any(fn in sw.fileName for fn in fname_variants):
                    if isinstance(sw.installPath, Iterable):
                        for sw_path in sw.installPath:
                            sw_dir = pathlib.PurePath(sw_path).parent
                            for refdir in probedirs:
                                if sw_dir == pathlib.PurePath(refdir):
                                    logger.debug(f"[.NET][heuristic] {refName} matched via {sw_path}")
                                    matched_uuids.add(sw.UUID)
                                    used_method[sw.UUID] = "heuristic"

        for uuid in matched_uuids:
            rel = Relationship(dependent_uuid, uuid, "Uses")
            if rel not in relationships:
                logger.debug(f"[.NET] Final relationship: {dependent_uuid} → {uuid} [{used_method[uuid]}]")
                relationships.append(rel)

        if not matched_uuids:
            logger.debug(f"[.NET] No match found for {refName}")

    return relationships
