# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import Any, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path


def has_required_fields(metadata: dict[str, Any]) -> bool:
    """Returns True if any known PE import fields are present in the metadata."""
    return any(k in metadata for k in ("peImport", "peBoundImport", "peDelayImport"))


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata: dict
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: establish 'Uses' relationships based on PE import metadata.

    Handles peImport, peBoundImport, and peDelayImport using a Windows-specific resolver.
    Phases:
      1. [fs_tree] Exact path match via sbom.get_software_by_path()
      2. [legacy]  installPath + fileName matching
      3. [heuristic] fileName match + shared directory (symlink-aware)
    """
    if not has_required_fields(metadata):
        logger.debug(f"[PE][skip] No PE import metadata for UUID={software.UUID} ({software.name})")
        return None

    relationships: List[Relationship] = []
    field_map = {
        "peImport": "Direct",
        "peBoundImport": "Bound",
        "peDelayImport": "Delay",
    }

    for field, label in field_map.items():
        if field in metadata:
            entries = metadata[field] or []
            logger.debug(
                f"[PE][import] {label} imports for {software.name} ({software.UUID}): {len(entries)}"
            )
            relationships.extend(get_windows_pe_dependencies(sbom, software, entries))

    logger.debug(f"[PE][final] emitted {len(relationships)} relationships")
    return relationships


def get_windows_pe_dependencies(sbom: SBOM, sw: Software, peImports) -> List[Relationship]:
    """
    Resolve dynamically loaded PE (Windows) DLL dependencies and generate 'Uses' relationships.

    This function attempts dependency resolution in three phases:
      1. Primary: Exact path match using sbom.fs_tree via get_software_by_path()
      2. Secondary: Legacy string-based matching using installPath and fileName
      3. Tertiary: Heuristic match based on fileName and shared parent directory (symlink-aware)

    Args:
        sbom (SBOM): The software bill of materials object with fs_tree and software entries.
        sw (Software): The importing software that declares PE DLL dependencies.
        peImports (list[str]): List of imported DLL base names (e.g., ['KERNEL32.dll']).

    Returns:
        List[Relationship]: A list of Relationship(xUUID=sw.UUID, yUUID=match.UUID, relationship="Uses").
    """
    relationships: List[Relationship] = []

    if sw.installPath is None:
        logger.debug(f"[PE][skip] No installPath for {sw.name} ({sw.UUID}); skipping resolution")
        return relationships

    dependent_uuid = sw.UUID

    for fname in peImports:
        if not fname:
            continue

        logger.debug(f"[PE][import] resolving '{fname}' for UUID={dependent_uuid}")

        matched_uuids = set()
        used_method: dict[str, str] = {}

        # -----------------------------------
        # Phase 1: Direct fs_tree resolution
        # -----------------------------------
        probedirs = []
        if isinstance(sw.installPath, Iterable):
            for ipath in sw.installPath or []:
                parent_dir = pathlib.PureWindowsPath(ipath).parent.as_posix()
                probedirs.append(parent_dir)
        logger.debug(f"[PE][import] probedirs for '{fname}': {probedirs}")

        for directory in probedirs:
            full_path = normalize_path(directory, fname)
            match = sbom.get_software_by_path(full_path)
            ok = bool(match and match.UUID != dependent_uuid)
            logger.debug(
                f"[PE][fs_tree] {full_path} → {'UUID=' + match.UUID if ok else 'no match'}"
            )
            if ok:
                matched_uuids.add(match.UUID)
                used_method[match.UUID] = "fs_tree"

        # ----------------------------------------
        # Phase 2: Legacy installPath + fileName
        # ----------------------------------------
        if not matched_uuids:
            for item in sbom.software:
                # Need a name match first
                has_name = isinstance(item.fileName, Iterable) and fname in (item.fileName or [])
                if not has_name:
                    continue

                # Then ensure any of the item's install paths share a probedir dir
                if isinstance(item.installPath, Iterable):
                    for ipath in item.installPath or []:
                        ip_dir = pathlib.PurePosixPath(ipath).parent.as_posix()
                        if ip_dir in probedirs:
                            if item.UUID != dependent_uuid:
                                logger.debug(f"[PE][legacy] {fname} in {ipath} → UUID={item.UUID}")
                                matched_uuids.add(item.UUID)
                                used_method[item.UUID] = "legacy_installPath"

        # ---------------------------------------------------------
        # Phase 3: Symlink-aware heuristic (same fileName + folder)
        # ---------------------------------------------------------
        if not matched_uuids:
            for item in sbom.software:
                has_name = isinstance(item.fileName, Iterable) and fname in (item.fileName or [])
                if not has_name or not isinstance(item.installPath, Iterable):
                    continue
                for ipath in item.installPath or []:
                    ip_dir = pathlib.PurePosixPath(ipath).parent
                    for refdir in probedirs:
                        if ip_dir == pathlib.PurePosixPath(refdir):
                            if item.UUID != dependent_uuid:
                                logger.debug(
                                    f"[PE][heuristic] {fname} via {ipath} → UUID={item.UUID}"
                                )
                                matched_uuids.add(item.UUID)
                                used_method[item.UUID] = "heuristic"

        # ----------------------------------------
        # Emit final relationships (if any found)
        # ----------------------------------------
        if matched_uuids:
            for uuid in matched_uuids:
                if uuid == dependent_uuid:
                    continue
                rel = Relationship(dependent_uuid, uuid, "Uses")
                if rel not in relationships:
                    method = used_method.get(uuid, "unknown")
                    logger.debug(
                        f"[PE][final] {dependent_uuid} Uses {fname} → UUID={uuid} [{method}]"
                    )
                    relationships.append(rel)
        else:
            logger.debug(f"[PE][final] {dependent_uuid} Uses {fname} → no match")

    return relationships


# def get_windows_pe_dependencies(sbom: SBOM, sw: Software, peImports) -> List[Relationship]:
#     relationships: List[Relationship] = []
#     # No installPath is probably temporary files/installer
#     # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
#     if sw.installPath is None:
#         return relationships

#     # https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
#     # Desktop Applications (we can only check a subset of these without much more info gathering, disassembly + full filesystem + environment details)
#     # 1. Specifying full path, using DLL redirection, or using a manifest
#     # - https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
#     # - DLL redirection summary: redirection file with name_of_exe.local (contents are ignored) makes a check for mydll.dll happen in the application directory first, regardless of what the full path specified for LoadLibrary or LoadLibraryEx is (if no dll found in local directory, uses the typical search order)
#     # - manifest files cause any .local files to be ignored (also, enabling DLL redirection may require setting DevOverrideEnable registry key)
#     # 2. If DLL with same module name is loaded in memory, no search will happen. If DLL is in KnownDLLs registry key, it uses the system copy of the DLL instead of searching.
#     # 3. If LOAD_LIBRARY_SEARCH flags are set for LoadLibraryEx, it will search dir LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, paths explicitly added by AddDllDirectory (LOAD_LIBRARY_SEARCH_USER_DIRS) or the SetDllDirectory (multiple paths added have unspecified search order), then system directory (LOAD_LIBRARY_SEARCH_SYSTEM32)
#     # 4. Look in dir the app was loaded from (or specified by absolute path lpFileName if LoadLibraryEx is called with LOAD_WITH_ALTERED_SEARCH_PATH)
#     # 5. If SetDllDirectory function called with lpPathName: the directory specified
#     # 6. If SafeDllSearchMode is disabled: the current directory
#     # 7. Look in the system directory (GetSystemDirectory to get the path)
#     # 8. The 16-bit system directory (no function to get this directory; %windir%\SYSTEM on 32-bit systems, not supported on 64-bit systems)
#     # 9. Windows system directory (GetWindowsDirectory to get this path)
#     # 10. If SafeDllSearchMode is enabled (default): the current directory
#     # 11. Directories listed in PATH environment variable (per-application path in App Paths registry key is not used for searching)

#     # In addition, Windows 10 + 11 add a feature called API sets: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
#     # these use special dll names that aren't actually a physical file on disk

#     # Of those steps, without gathering much more information that is likely not available or manual/dynamic analysis, we can do:
#     # 4. Look for DLL in the directory the application was loaded from
#     dependent_uuid = sw.UUID
#     for fname in peImports:
#         probedirs = []
#         if isinstance(sw.installPath, Iterable):
#             for ipath in sw.installPath:
#                 probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())
#         # likely just one found, unless sw entry has the same file installed to multiple places
#         for e in find_installed_software(sbom, probedirs, fname):
#             dependency_uuid = e.UUID
#             relationships.append(Relationship(dependent_uuid, dependency_uuid, "Uses"))
#         # logging DLLs not found would be nice, but is excessively noisy due being almost exclusively system DLLs

#     return relationships
