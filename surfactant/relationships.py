import pathlib


def add_relationship(sbom, xUUID, yUUID, relationship):
    sbom['relationships'].append({"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship})


def find_relationship(sbom, xUUID, yUUID, relationship):
    return {"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship} in sbom['relationships']


# TODO for an intermediate SBOM format, have ability to search more efficiently by hashes/filepath/filename
# currently, establishing relationships is something around O(n^2) due to searching entire sbom for matches

# return all matching dotnet assemblies
# TODO: an intermediate file format should keep files in different places but matching hashes separate until
# relationships are established; this would make so we can use .NET metadata about versions, strong names, etc
# and not accidentally mix and match cultures/app config info that could differ for different copies of the same
# file (due to app config files pointing to different assemblies despite DLL having same hash)
# culture information to find the right assembly from app config file is likely to vary (though almost always neutral/none)
def find_dotnet_assemblies(sbom, probedirs, filename):
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom['software']:
        # Skip if no install path (e.g. installer/temporary file)
        if e['installPath'] == None:
            continue
        for pdir in probedirs:
            # installPath contains full path+filename, so check for all combinations of probedirs+filename
            pfile = pathlib.PureWindowsPath(pdir, filename)
            for ifile in e['installPath']:
                # PureWindowsPath is case-insensitive for file/directory names
                if pfile == pathlib.PureWindowsPath(ifile):
                    # matching probe directory and filename, add software to list
                    possible_matches.append(e)
    return possible_matches


# return a list of all possible matching DLLs that could be loaded on Windows
def find_windows_dlls(sbom, probedirs, filename):
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom['software']:
        # Skip if no install path (e.g. installer/temporary file)
        if e['installPath'] == None:
            continue
        for pdir in probedirs:
            # installPath contains full path+filename, so check for all combinations of probedirs+filename
            pfile = pathlib.PureWindowsPath(pdir, filename)
            for ifile in e['installPath']:
                # PureWindowsPath is case-insensitive for file/directory names
                if pfile == pathlib.PureWindowsPath(ifile):
                    # matching probe directory and filename, add software to list
                    possible_matches.append(e)
    return possible_matches


def add_windows_pe_dependencies(sbom, sw, peImports):
    # No installPath is probably temporary files/installer
    # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
    if sw['installPath'] == None:
        return

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
    dependent_uuid = sw.get('UUID')
    for fname in peImports:
        probedirs = []
        for ipath in sw['installPath']:
            probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())
        # likely just one found, unless sw entry has the same file installed to multiple places
        for e in find_windows_dlls(sbom, probedirs, fname):
            dependency_uuid = e['UUID']
            if not find_relationship(sbom, dependent_uuid, dependency_uuid, "Uses"):
                add_relationship(sbom, dependent_uuid, dependency_uuid, "Uses")
        # logging DLLs not found would be nice, but is excessively noisy due being almost exclusively system DLLs
        #print(f" Dependency {fname} not found for sbom['software'] entry={sw}")


# construct a list of directories to probe for establishing dotnet relationships
def get_dotnet_probedirs(sw, refCulture, refName, dnProbingPaths):
    probedirs = []
    # probe for the referenced assemblies
    for install_filepath in sw['installPath']:
        install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
        if refCulture == None or refCulture == '':
            # [application base] / [assembly name].dll
            # [application base] / [assembly name] / [assembly name].dll
            probedirs.append(pathlib.PureWindowsPath(install_basepath).as_posix())
            probedirs.append(pathlib.PureWindowsPath(install_basepath, refName).as_posix())
            if dnProbingPaths != None:
                # add probing private paths
                for path in dnProbingPaths:
                    # [application base] / [binpath] / [assembly name].dll
                    # [application base] / [binpath] / [assembly name] / [assembly name].dll
                    probedirs.append(pathlib.PureWindowsPath(install_basepath, path).as_posix())
                    probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refName).as_posix())
        else:
            # [application base] / [culture] / [assembly name].dll
            # [application base] / [culture] / [assembly name] / [assembly name].dll
            probedirs.append(pathlib.PureWindowsPath(install_basepath, refCulture).as_posix())
            probedirs.append(pathlib.PureWindowsPath(install_basepath, refName, refCulture).as_posix())
            if dnProbingPaths != None:
                # add probing private paths
                for path in dnProbingPaths:
                    # [application base] / [binpath] / [culture] / [assembly name].dll
                    # [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
                    probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refCulture).as_posix())
                    probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refName, refCulture).as_posix())
    return probedirs

def parse_relationships(sbom):
    for sw in sbom['software']:
        # Skip for temporary files/installer that don't have any installPath to find dependencies with
        if sw['installPath'] == None:
            continue
        dependent_uuid = sw.get('UUID')

        # Find metadata saying what dependencies are used by the software entry
        for md in sw['metadata']:
            dependency_uuid = []

            # handle ELF dependecies
            if 'elfDependencies' in md:
                for fname in md['elfDependencies']:
                    # TODO if there are many symlinks to the same file, if item.get('fileName')[0] should be changed to check against every name
                    # for multiple separate file systems, checking only a portion of sbom['software'] might need to be handled
                    if dependency_uuid := [item.get('UUID') for item in sbom['software'] if item.get('fileName')[0] == fname]:
                        # shouldn't find multiple entries with the same UUID
                        # if we did, there may be files outside of the correct search path that were considered in the previous step
                        add_relationship(sbom, dependent_uuid, dependency_uuid[0], "Uses")
                    else:
                        pass
                        # this mostly just prints system libraries
                        #print(f" Dependency {fname} not found for sbom['software'] entry={sw}")

            # handle PE imports
            if 'peImport' in md:
                # NOTE: UWP apps have their own search order for libraries; they use a .appx or .msix file extension and appear to be zip files, so our SBOM probably doesn't even include them
                add_windows_pe_dependencies(sbom, sw, md['peImport'])
            if 'peBoundImport' in md:
                add_windows_pe_dependencies(sbom, sw, md['peBoundImport'])
            if 'peDelayImport' in md:
                add_windows_pe_dependencies(sbom, sw, md['peDelayImport'])
            if 'dotnetAssemblyRef' in md:
                dnName = None
                dnCulture = None
                dnVersion = None
                if 'dotnetAssembly' in md:
                    dnAssembly = md['dotnetAssembly']
                    if 'Name' in dnAssembly:
                        dnName = dnAssembly['Name']
                    if 'Culture' in dnAssembly:
                        dnCulture = dnAssembly['Culture']
                    if 'Version' in dnAssembly:
                        dnVersion = dnAssembly['Version']

                # get additional probing paths if they exist
                dnProbingPaths = None
                dnDependentAssemblies = None

                windowsAppConfig = None
                windowsManifest = None
                if 'appConfigFile' in md:
                    windowsAppConfig = md['appConfigFile']
                if 'manifestFile' in md:
                    windowsManifest = md['manifestFile']

                if windowsAppConfig:
                    if 'runtime' in windowsAppConfig:
                        wac_runtime = windowsAppConfig['runtime']
                        if 'assemblyBinding' in wac_runtime:
                            wac_asmbinding = wac_runtime['assemblyBinding']
                            if 'dependentAssembly' in wac_asmbinding:
                                dnDependentAssemblies = wac_asmbinding['dependentAssembly']
                            if 'probing' in wac_asmbinding:
                                wac_probing = wac_asmbinding['probing']
                                if 'privatePath' in wac_probing:
                                    wac_paths = wac_probing['privatePath']
                                    for path in wac_paths.split(';'):
                                        if dnProbingPaths == None:
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
                if 'dotnetAssemblyRef' in md:
                    for asmRef in md['dotnetAssemblyRef']:
                        refName = None
                        refVersion = None
                        refCulture = None
                        if 'Name' in asmRef:
                            refName = asmRef['Name']
                        else:
                            continue # no name means we have no assembly to search for
                        if 'Culture' in asmRef:
                            refCulture = asmRef['Culture']
                        if 'Version' in asmRef:
                            refVersion = asmRef['Version']

                        # check if codeBase element exists for this assembly in appconfig
                        if dnDependentAssemblies != None:
                            for depAsm in dnDependentAssemblies:
                                # dependent assembly object contains info on assembly id and binding redirects that with a better internal SBOM
                                # representation could be used to also verify the right assembly is being found
                                if 'codeBase' in depAsm:
                                    if 'href' in depAsm['codeBase']:
                                        codebase_href = depAsm['codeBase']['href']
                                        # strong named assembly can be anywhere on intranet or Internet
                                        if codebase_href.startswith('http://') or codebase_href.startswith('https://') or codebase_href.startswith('file://'):
                                            # codebase references a url; interesting for manual analysis/gathering additional files, but not supported by surfactant yet
                                            pass
                                        else:
                                            # most likely a private assembly, so path must be relative to application's directory
                                            for install_filepath in sw['installPath']:
                                                install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
                                                cb_filepath = pathlib.PureWindowsPath(install_basepath, codebase_href)
                                                cb_file = cb_filepath.name
                                                cb_path = cb_filepath.parent.as_posix()
                                                for e in find_dotnet_assemblies(sbom, cb_path, cb_file):
                                                    dependency_uuid = e['UUID']
                                                    if not find_relationship(sbom, dependent_uuid, dependency_uuid, "Uses"):
                                                        add_relationship(sbom, dependent_uuid, dependency_uuid, "Uses")

                        # continue on to probing even if codebase element was found, since we can't guarantee the assembly identity required by the codebase element
                        # get the list of paths to probe based on locations sw is installed, assembly culture, assembly name, and probing paths from appconfig file
                        probedirs = get_dotnet_probedirs(sw, refCulture, refName, dnProbingPaths)
                        for e in find_dotnet_assemblies(sbom, probedirs, refName+".dll"):
                            dependency_uuid = e['UUID']
                            if not find_relationship(sbom, dependent_uuid, dependency_uuid, "Uses"):
                                add_relationship(sbom, dependent_uuid, dependency_uuid, "Uses")
                            # logging assemblies not found would be nice but is a lot of noise as it mostly just prints system/core .NET libraries
                            #print(f" Dependency {refName} not found for sbom['software'] entry={sw}")


