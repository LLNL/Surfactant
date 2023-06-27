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
    # dotnetAssemblyRef must present, otherwise we have no info on .NET imports
    return "dotnetAssemblyRef" in metadata


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    if not has_required_fields(metadata):
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    dnName = None
    dnCulture = None
    dnVersion = None
    if "dotnetAssembly" in metadata:
        dnAssembly = metadata["dotnetAssembly"]
        if "Name" in dnAssembly:
            dnName = dnAssembly["Name"]
        if "Culture" in dnAssembly:
            dnCulture = dnAssembly["Culture"]
        if "Version" in dnAssembly:
            dnVersion = dnAssembly["Version"]

    # get additional probing paths if they exist
    dnProbingPaths = None
    dnDependentAssemblies = None

    windowsAppConfig = None
    windowsManifest = None
    if "appConfigFile" in metadata:
        windowsAppConfig = metadata["appConfigFile"]
    if "manifestFile" in metadata:
        windowsManifest = metadata["manifestFile"]

    if windowsAppConfig:
        if "runtime" in windowsAppConfig:
            wac_runtime = windowsAppConfig["runtime"]
            if "assemblyBinding" in wac_runtime:
                wac_asmbinding = wac_runtime["assemblyBinding"]
                if "dependentAssembly" in wac_asmbinding:
                    dnDependentAssemblies = wac_asmbinding["dependentAssembly"]
                if "probing" in wac_asmbinding:
                    wac_probing = wac_asmbinding["probing"]
                    if "privatePath" in wac_probing:
                        wac_paths = wac_probing["privatePath"]
                        for path in wac_paths.split(";"):
                            if dnProbingPaths is None:
                                dnProbingPaths = []
                            dnProbingPaths.append(pathlib.PureWindowsPath(path).as_posix())

    # https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
    # 1. Determine correct assembly version using configuration files (binding redirects, code location, etc)
    # 2. Check if assembly name bound before; if it is use previously loaded assembly
    # 3. Check global assembly cache (%windir%\Microsoft.NET\assembly in .NET framework 4, %windir%\assembly previously)
    # 4. Probe for assembly:
    # - a. Check for <codeBase> element in app config; check the given location and if assembly found great no probing; otherwise fail without probing
    # - b. If there is no <codeBase> element, begin probing using
    #    - application base + culture + assembly name directories
    #    - privatePath directories from a probing element, combined with culture/appbase/assemblyname (done before the standard probing directories)
    #    - the location of the calling assembly may be used as a hint for where to find the referenced assembly
    if "dotnetAssemblyRef" in metadata:
        for asmRef in metadata["dotnetAssemblyRef"]:
            refName = None
            refVersion = None
            refCulture = None
            if "Name" in asmRef:
                refName = asmRef["Name"]
            else:
                continue  # no name means we have no assembly to search for
            if "Culture" in asmRef:
                refCulture = asmRef["Culture"]
            if "Version" in asmRef:
                refVersion = asmRef["Version"]

            # check if codeBase element exists for this assembly in appconfig
            if dnDependentAssemblies is not None:
                for depAsm in dnDependentAssemblies:
                    # dependent assembly object contains info on assembly id and binding redirects that with a better internal SBOM
                    # representation could be used to also verify the right assembly is being found
                    if "codeBase" in depAsm:
                        if "href" in depAsm["codeBase"]:
                            codebase_href = depAsm["codeBase"]["href"]
                            # strong named assembly can be anywhere on intranet or Internet
                            if (
                                codebase_href.startswith("http://")
                                or codebase_href.startswith("https://")
                                or codebase_href.startswith("file://")
                            ):
                                # codebase references a url; interesting for manual analysis/gathering additional files, but not supported by surfactant yet
                                pass
                            else:
                                # most likely a private assembly, so path must be relative to application's directory
                                if isinstance(software.installPath, Iterable):
                                    for install_filepath in software.installPath:
                                        install_basepath = pathlib.PureWindowsPath(
                                            install_filepath
                                        ).parent.as_posix()
                                        cb_filepath = pathlib.PureWindowsPath(
                                            install_basepath, codebase_href
                                        )
                                        cb_file = cb_filepath.name
                                        cb_path = [cb_filepath.parent.as_posix()]
                                        for e in find_installed_software(sbom, cb_path, cb_file):
                                            dependency_uuid = e.UUID
                                            relationships.append(
                                                Relationship(
                                                    dependent_uuid, dependency_uuid, "Uses"
                                                )
                                            )

            # continue on to probing even if codebase element was found, since we can't guarantee the assembly identity required by the codebase element
            # get the list of paths to probe based on locations software is installed, assembly culture, assembly name, and probing paths from appconfig file
            probedirs = get_dotnet_probedirs(software, refCulture, refName, dnProbingPaths)
            for e in find_installed_software(sbom, probedirs, refName + ".dll"):
                dependency_uuid = e.UUID
                relationships.append(Relationship(dependent_uuid, dependency_uuid, "Uses"))
                # logging assemblies not found would be nice but is a lot of noise as it mostly just prints system/core .NET libraries
    return relationships


# construct a list of directories to probe for establishing dotnet relationships
def get_dotnet_probedirs(software: Software, refCulture, refName, dnProbingPaths):
    probedirs = []
    # probe for the referenced assemblies
    if isinstance(software.installPath, Iterable):
        for install_filepath in software.installPath:
            install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
            if refCulture is None or refCulture == "":
                # [application base] / [assembly name].dll
                # [application base] / [assembly name] / [assembly name].dll
                probedirs.append(pathlib.PureWindowsPath(install_basepath).as_posix())
                probedirs.append(pathlib.PureWindowsPath(install_basepath, refName).as_posix())
                if dnProbingPaths is not None:
                    # add probing private paths
                    for path in dnProbingPaths:
                        # [application base] / [binpath] / [assembly name].dll
                        # [application base] / [binpath] / [assembly name] / [assembly name].dll
                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path).as_posix())
                        probedirs.append(
                            pathlib.PureWindowsPath(install_basepath, path, refName).as_posix()
                        )
            else:
                # [application base] / [culture] / [assembly name].dll
                # [application base] / [culture] / [assembly name] / [assembly name].dll
                probedirs.append(pathlib.PureWindowsPath(install_basepath, refCulture).as_posix())
                probedirs.append(
                    pathlib.PureWindowsPath(install_basepath, refName, refCulture).as_posix()
                )
                if dnProbingPaths is not None:
                    # add probing private paths
                    for path in dnProbingPaths:
                        # [application base] / [binpath] / [culture] / [assembly name].dll
                        # [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
                        probedirs.append(
                            pathlib.PureWindowsPath(install_basepath, path, refCulture).as_posix()
                        )
                        probedirs.append(
                            pathlib.PureWindowsPath(
                                install_basepath, path, refName, refCulture
                            ).as_posix()
                        )
    return probedirs
