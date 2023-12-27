# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import Any, List, Union

from surfactant.sbomtypes import SBOM, Software


# return all matching dotnet assemblies or DLLs that could be loaded on Windows
# TODO: an intermediate file format should keep files in different places but matching hashes separate until
# relationships are established; this would make so we can use .NET metadata about versions, strong names, etc
# and not accidentally mix and match cultures/app config info that could differ for different copies of the same
# file (due to app config files pointing to different assemblies despite DLL having same hash)
# culture information to find the right assembly from app config file is likely to vary (though almost always neutral/none)
def find_installed_software(
    sbom: SBOM, probedirs: List[Any], filename: Union[str, List[str]]
) -> List[Software]:
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom.software:
        # Skip if no install path (e.g. installer/temporary file)
        if e.installPath is None:
            continue
        for pdir in probedirs:
            if isinstance(filename, str):
                filename = [filename]
            for fname in filename:
                # installPath contains full path+filename, so check for all combinations of probedirs+filename
                pfile = pathlib.PureWindowsPath(pdir, fname)
                if isinstance(e.installPath, Iterable):
                    for ifile in e.installPath:
                        # PureWindowsPath is case-insensitive for file/directory names
                        if pfile == pathlib.PureWindowsPath(ifile):
                            # matching probe directory and filename, add software to list
                            possible_matches.append(e)
    return possible_matches
