# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

from ._internal.windows_utils import find_installed_software


def has_required_fields(metadata) -> bool:
    return "peImport" in metadata or "peBoundImport" in metadata or "peDelayImport" in metadata


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    if not has_required_fields(metadata):
        return None

    relationships = []
    if "peImport" in metadata:
        # NOTE: UWP apps have their own search order for libraries; they use a .appx or .msix file extension and appear to be zip files, so our SBOM probably doesn't even include them
        relationships.extend(get_windows_pe_dependencies(sbom, software, metadata["peImport"]))
    if "peBoundImport" in metadata:
        relationships.extend(get_windows_pe_dependencies(sbom, software, metadata["peBoundImport"]))
    if "peDelayImport" in metadata:
        relationships.extend(get_windows_pe_dependencies(sbom, software, metadata["peDelayImport"]))
    return relationships


def get_windows_pe_dependencies(sbom: SBOM, sw: Software, peImports) -> List[Relationship]:
    relationships: List[Relationship] = []
    # No installPath is probably temporary files/installer
    # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
    if sw.installPath is None:
        return relationships

    # https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
    # Desktop Applications (we can only check a subset of these without much more info gathering, disassembly + full filesystem + environment details)
    # 1. Specifying full path, using DLL redirection, or using a manifest
    # - https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
    # - DLL redirection summary: redirection file with name_of_exe.local (contents are ignored) makes a check for mydll.dll happen in the application directory first, regardless of what the full path specified for LoadLibrary or LoadLibraryEx is (if no dll found in local directory, uses the typical search order)
    # - manifest files cause any .local files to be ignored (also, enabling DLL redirection may require setting DevOverrideEnable registry key)
    # 2. If DLL with same module name is loaded in memory, no search will happen. If DLL is in KnownDLLs registry key, it uses the system copy of the DLL instead of searching.
    # 3. If LOAD_LIBRARY_SEARCH flags are set for LoadLibraryEx, it will search dir LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, paths explicitly added by AddDllDirectory (LOAD_LIBRARY_SEARCH_USER_DIRS) or the SetDllDirectory (multiple paths added have unspecified search order), then system directory (LOAD_LIBRARY_SEARCH_SYSTEM32)
    # 4. Look in dir the app was loaded from (or specified by absolute path lpFileName if LoadLibraryEx is called with LOAD_WITH_ALTERED_SEARCH_PATH)
    # 5. If SetDllDirectory function called with lpPathName: the directory specified
    # 6. If SafeDllSearchMode is disabled: the current directory
    # 7. Look in the system directory (GetSystemDirectory to get the path)
    # 8. The 16-bit system directory (no function to get this directory; %windir%\SYSTEM on 32-bit systems, not supported on 64-bit systems)
    # 9. Windows system directory (GetWindowsDirectory to get this path)
    # 10. If SafeDllSearchMode is enabled (default): the current directory
    # 11. Directories listed in PATH environment variable (per-application path in App Paths registry key is not used for searching)

    # In addition, Windows 10 + 11 add a feature called API sets: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
    # these use special dll names that aren't actually a physical file on disk

    # Of those steps, without gathering much more information that is likely not available or manual/dynamic analysis, we can do:
    # 4. Look for DLL in the directory the application was loaded from
    dependent_uuid = sw.UUID
    for fname in peImports:
        probedirs = []
        if isinstance(sw.installPath, Iterable):
            for ipath in sw.installPath:
                probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())
        # likely just one found, unless sw entry has the same file installed to multiple places
        for e in find_installed_software(sbom, probedirs, fname):
            dependency_uuid = e.UUID
            relationships.append(Relationship(dependent_uuid, dependency_uuid, "Uses"))
        # logging DLLs not found would be nice, but is excessively noisy due being almost exclusively system DLLs

    return relationships
