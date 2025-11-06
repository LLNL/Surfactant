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

    Background and References:
    --------------------------
    This function models how Windows determines which DLLs a process loads when calling
    `LoadLibrary`, `LoadLibraryEx`, or related APIs. It partially reconstructs the DLL
    search order used by the Windows loader, focusing on statically analyzable aspects.

    See also:
        - Dynamic-link library search order:
          https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
        - DLL redirection:
          https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
        - API sets overview:
          https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

    DLL Search Order (Desktop Applications):
    ---------------------------------------
    The Windows loader uses multiple strategies to locate DLLs, depending on how
    they are loaded, manifest configuration, SafeDllSearchMode, and other factors.
    The typical order is:

      1. **Explicit path, redirection, or manifest-based loading**
         - A full path is specified in `LoadLibrary` or `LoadLibraryEx`.
         - DLL redirection: presence of a `.local` file (e.g., `myapp.exe.local`)
           causes the loader to check the application directory first, regardless
           of the full path specified. The `.local` file’s contents are ignored.
         - Manifests can disable `.local` redirection behavior.
           (Note: enabling DLL redirection may require setting the `DevOverrideEnable`
           registry key.)

      2. **In-memory or KnownDLLs**
         - If a DLL with the same module name is already loaded in memory, no search occurs.
         - If the DLL name is found in the `KnownDLLs` registry key, the system copy is used.

      3. **LOAD_LIBRARY_SEARCH flags (for LoadLibraryEx)**
         - The loader searches directories in the following order when flags are set:
             - `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`
             - `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`
             - Paths added via `AddDllDirectory()` or `SetDllDirectory()`
               (if multiple directories are added, search order is unspecified)
             - System directory (`LOAD_LIBRARY_SEARCH_SYSTEM32`)
             - Paths added via `AddDllDirectory()` (`LOAD_LIBRARY_SEARCH_USER_DIRS`) or `SetDllDirectory()`

      4. **Application directory**
         - The directory from which the application was loaded.
           If `LoadLibraryEx` is called with `LOAD_WITH_ALTERED_SEARCH_PATH`,
           the directory containing the specified absolute path (`lpFileName`) is used instead.

      5. **SetDllDirectory paths**
         - The directory explicitly added using `SetDllDirectory()`.

      6. **Current directory**
         - Only checked if SafeDllSearchMode is disabled.

      7. **System directory**
         - Retrieved via `GetSystemDirectory()`.

      8. **16-bit system directory**
         - Typically `%windir%\\SYSTEM` on 32-bit systems.
           There is no dedicated API to retrieve this directory.
           (Not supported or relevant on 64-bit Windows.)

      9. **Windows directory**
         - Retrieved via `GetWindowsDirectory()`.

     10. **Current directory (SafeDllSearchMode enabled)**
         - When SafeDllSearchMode is on (default behavior), this check occurs later in the sequence.

     11. **PATH environment variable**
         - Each directory in the PATH environment variable is searched.
           The per-application “App Paths” registry entries are *not* used for DLL lookup
           (they only apply to executable search resolution).

    Additional Windows Features:
    ----------------------------
    Windows 10 and Windows 11 introduced **API sets**, a redirection mechanism that maps
    logical DLL names (e.g., `api-ms-win-core-file-l1-1-0.dll`) to actual implementation
    DLLs. These API set DLLs are not physical files on disk — they are resolved internally
    by the Windows loader and cannot be statically traced via file presence.

    Implementation Scope in Static Analysis:
    ----------------------------------------
    Because this static analysis lacks access to runtime information such as manifests,
    registry settings, environment variables, and system search modes, we only approximate
    the search behavior by checking a *subset* of possible locations.

    Practically, this function performs:
      - **Step 4**: Searches the directory the importing executable or shared object
        was loaded from (derived from `installPath`).
      - Optionally extends this to a few heuristic matching phases (see below).

    Notes and Implementation Details:
    ---------------------------------
    - If `installPath` is missing, the file is likely a temporary artifact or installer
      and cannot be resolved safely.
    - Future improvement (TODO): attempt resolution using relative locations within
      `containerPath`, for cases where files originate from the same container UUID.
    - While logging missing DLLs could be informative, it would be excessively noisy,
      as most unresolved DLLs are standard Windows system libraries.

    Args:
        sbom (SBOM): The software bill of materials object with fs_tree and software entries.
        sw (Software): The importing software that declares PE DLL dependencies.
        peImports (list[str]): List of imported DLL base names (e.g., ['KERNEL32.dll']).

    Returns:
        List[Relationship]: A list of Relationship(xUUID=sw.UUID, yUUID=match.UUID, relationship="Uses").
    """
    relationships: List[Relationship] = []

    # No installPath is probably temporary files/installer
    # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
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
