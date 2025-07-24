# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path


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

    # Extract probing and dependent assembly info from appConfig if present
    dnProbingPaths = None
    dnDependentAssemblies = None
    windowsAppConfig = metadata.get("appConfigFile")
    windowsManifest = metadata.get("manifestFile")  # Currently unused

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

    # https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/loading-unmanaged
    # 1. Check the active AssemblyLoadContext cache
    # 2. Calling the import resolver set by the setDllImportResolver function
    #    - a. Example using SetDllImportResolver: https://learn.microsoft.com/en-us/dotnet/standard/native-interop/native-library-loading
    #    - b. Checks PInvoke's or Assembly's DefaultDllImportSearchPathsAttribute, then the assembly's directory, then LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH flag
    #       - This attribute has no effect on non-Windows platforms / Mono runtime
    #       - https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.defaultdllimportsearchpathsattribute?view=net-7.0
    #       - i. This has a "Paths" property which is a bitwise combination of paths specified in ii:
    #       - ii. https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportsearchpath?view=net-7.0
    # 3. The active AssemblyLoadContext calls its LoadUnmanagedDll function (Default behavior is the same as AssemblyRef probing?)
    #    - a. Can be overridden, but the default implementation returns IntPtr.Zero, which tells the runtime to load with its default policy.
    #    - b. https://learn.microsoft.com/en-us/dotnet/api/system.runtime.loader.assemblyloadcontext.loadunmanageddll?view=net-7.0
    # 4. Run default unmanaged library probing logic by parsing *.deps.json probing properties
    #    - a. If the json file isn't present, assume the calling assembly's directory contains the library
    #    - b. https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/default-probing#unmanaged-native-library-probing

    # Handle unmanaged dependencies declared via [DllImport] or P/Invoke
    if "dotnetImplMap" in metadata:
        for asmRef in metadata["dotnetImplMap"]:
            if "Name" not in asmRef:
                continue
            refName = asmRef["Name"]

            # Absolute path: resolve directly using fs_tree
            if is_absolute_path(refName):
                ref_abspath = normalize_path(refName)
                match = sbom.get_software_by_path(ref_abspath)

                if match:
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                continue

                # for e in sbom.software:
                #     if e.installPath is None:
                #         continue
                #     if isinstance(e.installPath, Iterable):
                #         for ifile in e.installPath:
                #             if ref_abspath == pathlib.PureWindowsPath(ifile):
                #                 relationships.append(Relationship(dependent_uuid, e.UUID, "Uses"))
                # continue

            # Construct candidate paths relative to installPath
            probedirs = []
            if isinstance(software.installPath, Iterable):
                for ipath in software.installPath:
                    probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())

            # Construct a list of combinations specified in (2.a)
            # Refer to Issue #80 - Need to verify that this conforms with cross-platform behavior
            combinations = [refName]
            if not (refName.endswith(".dll") or refName.endswith(".exe")):
                combinations.append(f"{refName}.dll")
            combinations.extend(
                [
                    f"{refName}.so",
                    f"{refName}.dylib",
                    f"lib{refName}.so",
                    f"lib{refName}.dylib",
                    f"lib{refName}",
                ]
            )

            for directory in probedirs:
                for candidate in combinations:
                    path = normalize_path(directory, candidate)
                    match = sbom.get_software_by_path(path)
                    if match:
                        relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))

            # # On Linux, if the libname ends with .so or has .so. then version variations are tried
            # # Refer to Issue #79 - Need regex matching for version variations
            # for e in find_installed_software(sbom, probedirs, combinations):
            #     dependency_uuid = e.UUID
            #     relationships.append(Relationship(dependent_uuid, dependency_uuid, "Uses"))

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
            refVersion = asmRef.get("Version")
            refCulture = asmRef.get("Culture")
            refName = asmRef.get("Name")

            if not refName:
                continue  # no name means we have no assembly to search for

            # check if codeBase element exists for this assembly in appconfig
            # Resolve from <codeBase href="..."> entries in app config
            if dnDependentAssemblies:
                for depAsm in dnDependentAssemblies:
                    # dependent assembly object contains info on assembly id and binding redirects that with a better internal SBOM
                    # representation could be used to also verify the right assembly is being found
                    if "codeBase" in depAsm and "href" in depAsm["codeBase"]:
                        href = depAsm["codeBase"]["href"]

                        # strong named assembly can be anywhere on intranet or Internet
                        # Skip external URLs we cannot resolve locally
                        if (
                            href.startswith("http://")
                            or href.startswith("https://")
                            or href.startswith("file://")
                        ):
                            # codebase references a url; interesting for manual analysis/gathering additional files, but not supported by surfactant yet
                            continue

                        # most likely a private assembly, so path must be relative to application's directory
                        if isinstance(software.installPath, Iterable):
                            for ipath in software.installPath:
                                base_path = pathlib.PureWindowsPath(ipath).parent
                                cb_fullpath = normalize_path(base_path, href)
                                match = sbom.get_software_by_path(cb_fullpath)
                                if match:
                                    relationships.append(
                                        Relationship(dependent_uuid, match.UUID, "Uses")
                                    )

            # continue on to probing even if codebase element was found, since we can't guarantee the assembly identity required by the codebase element
            # get the list of paths to probe based on locations software is installed, assembly culture, assembly name, and probing paths from appconfig file

            # Probe using resolved directories and file name
            probedirs = get_dotnet_probedirs(
                software,
                refCulture,
                refName,
                dnProbingPaths,
            )

            for directory in probedirs:
                path = normalize_path(directory, refName + ".dll")
                match = sbom.get_software_by_path(path)
                if match:
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                # logging assemblies not found would be nice but is a lot of noise as it mostly just prints system/core .NET libraries

    return relationships


def is_absolute_path(fname: str) -> bool:
    givenpath = pathlib.PureWindowsPath(fname)
    return givenpath.is_absolute()


def get_dotnet_probedirs(software: Software, refCulture, refName, dnProbingPaths):
    """
    Construct a list of normalized directories to probe for .NET assembly resolution.

    Args:
        software (Software): The software object to base search paths from.
        refCulture (str | None): Culture value from AssemblyRef metadata.
        refName (str): Name of the referenced assembly.
        dnProbingPaths (list[str] | None): Optional private probing paths from app config.

    Returns:
        list[str]: List of normalized POSIX-style probe directories.
    """
    probedirs = []

    if not isinstance(software.installPath, Iterable):
        return probedirs

    for install_filepath in software.installPath:
        install_basepath = pathlib.PureWindowsPath(install_filepath).parent

        if not refCulture:
            # e.g. C:/app → C:/app, C:/app/samedirlib
            probedirs.append(normalize_path(install_basepath))
            probedirs.append(normalize_path(install_basepath, refName))

            if dnProbingPaths:
                for path in dnProbingPaths:
                    probedirs.append(normalize_path(install_basepath, path))
                    probedirs.append(normalize_path(install_basepath, path, refName))
        else:
            # e.g. C:/app → C:/app/culture, C:/app/lib/culture
            probedirs.append(normalize_path(install_basepath, refCulture))
            probedirs.append(normalize_path(install_basepath, refName, refCulture))

            if dnProbingPaths:
                for path in dnProbingPaths:
                    probedirs.append(normalize_path(install_basepath, path, refCulture))
                    probedirs.append(normalize_path(install_basepath, path, refName, refCulture))

    return probedirs
