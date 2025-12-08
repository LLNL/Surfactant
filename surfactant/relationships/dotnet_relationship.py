import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.relationships._internal.windows_utils import find_installed_software
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path

# Optional legacy helper that encodes .NET probing directory patterns
# (culture-specific subdirs, assembly-name subdirs, privatePath combinations, etc.).
# We treat it as optional so this module can still import even if the legacy file
# is not available in a particular build.
try:
    from surfactant.relationships.dotnet_relationship_legacy import get_dotnet_probedirs
except ImportError:  # pragma: no cover - optional dependency
    get_dotnet_probedirs = None

# Feature flag: enable full legacy probe (O(n^2) fallback) when explicitly requested.
# This is used later as the "no compromises"
# TODO: Make this a CLI flag or config option instead of env var
# FULL_DOTNET_LEGACY_PROBE = os.getenv("SURFACTANT_DOTNET_FULL_PROBE", "").lower() in (
#     "1",
#     "true",
#     "yes",
#     "on",
# )
FULL_DOTNET_LEGACY_PROBE = 0
# -------------------------------------------------------------------------
# Legacy Documentation
# -------------------------------------------------------------------------
# Unmanaged (.dll/.so/.dylib) resolution background
#
# Reference:
#   https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/loading-unmanaged
#
# The .NET runtime resolves unmanaged/native libraries through a multistage
# search process:
#
# 1. Check the active AssemblyLoadContext cache.
#
# 2. Invoke any resolver registered via SetDllImportResolver().
#    - Example using SetDllImportResolver:
#        https://learn.microsoft.com/en-us/dotnet/standard/native-interop/native-library-loading
#    - Behavior:
#        * Checks the PInvoke or Assembly-level DefaultDllImportSearchPathsAttribute,
#          then the assembly's directory, then calls LoadLibraryEx with the
#          LOAD_WITH_ALTERED_SEARCH_PATH flag (on Windows).
#    - DefaultDllImportSearchPathsAttribute notes:
#        * Has no effect on non-Windows platforms / Mono runtime.
#        * API reference:
#            https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.defaultdllimportsearchpathsattribute?view=net-7.0
#        * Its "Paths" property is a bitwise combination of values from:
#            https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportsearchpath?view=net-7.0
#
# 3. The active AssemblyLoadContext calls its LoadUnmanagedDll function
#    (default behavior is effectively the same as assembly reference probing).
#    - a. This method can be overridden to provide custom unmanaged library
#         resolution logic.
#         * The default implementation returns IntPtr.Zero, which tells the
#           runtime to continue using its normal unmanaged library resolution
#           policy.
#    - b. API reference:
#         https://learn.microsoft.com/en-us/dotnet/api/system.runtime.loader.assemblyloadcontext.loadunmanageddll?view=net-7.0
#
# 4. Run default unmanaged library probing logic by parsing *.deps.json
#    probing properties.
#    - a. If the json file isn't present, assume the calling assembly's
#         directory contains the library.
#    - b. Reference:
#         https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/default-probing#unmanaged-native-library-probing
#
# 5. Platform-specific probing notes:
#    - On Linux, if the libname ends with ".so" or contains ".so.", the
#      runtime attempts version variations such as:
#         libfoo.so
#         libfoo.so.1
#         libfoo.so.1.2.3
#      (Legacy code references Issue #79 indicating regex-based matching for
#       version variations was needed but not yet implemented.)
#
# 6. Legacy Surfactant unmanaged resolution logic:
#    - Construct a list of candidate filenames following the rules outlined
#      earlier in SetDllImportResolver behavior.
#    - Candidate list includes:
#         refName
#         refName.dll
#         refName.exe
#         refName.so
#         refName.dylib
#         lib<refName>.so
#         lib<refName>.dylib
#         lib<refName>
#    - This list corresponds to the combinations described in (2.a).
#      (Legacy comments reference Issue #80, noting the need to verify that
#       these candidate combinations behave correctly across platforms.)
#    - Versioned ".so" variations were NOT evaluated.
#      (Related to Issue #79 — regex matching needed for versioned .so names.)
#    - Determine probing directories by taking the parent directory of each
#      entry in software.installPath.
#    - Search for all candidate filenames using find_installed_software().
#
# 7. Absolute-path unmanaged imports:
#    - If the DllImport / PInvoke name is an absolute Windows path:
#         * Convert to PureWindowsPath.
#         * Compare this absolute path against every installPath entry of every
#           software node in the SBOM.
#         * A relationship is created only if an exact match is found.
#    - When an absolute path is used, no probing or filename variants are
#      attempted.
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Managed (.dll/.exe) assembly resolution background
#
# Reference:
#   https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
#
# The .NET runtime locates managed assemblies using the following steps:
#
# 1. Determine the correct assembly version using configuration files
#    (binding redirects, code location, culture, version, etc.).
#
# 2. Check whether the assembly name has already been bound; if so, the runtime
#    uses the previously loaded assembly instead of probing.
#
# 3. Check the Global Assembly Cache (GAC)
#    - %WINDIR%\Microsoft.NET\assembly   (used by .NET Framework 4 and later)
#    - %WINDIR%\assembly                 (used by earlier .NET Framework versions)
#
# 4. Probe for assembly:
#
#    a. Check for a <codeBase> element in the app configuration file.
#       - If <codeBase href="..."> is present, the runtime checks the specified
#         location for the assembly.
#       - If the assembly is found, probing stops entirely.
#       - If the assembly is not found, the runtime fails without performing
#         any further probing.
#       - The href may be:
#           * http:// or https://
#           * file://
#           * a relative path (interpreted as relative to the application's
#             base directory, i.e., the parent of installPath).
#
#    b. If there is no <codeBase> element, begin standard probing:
#       - Search application base + culture + assembly name directories.
#       - Search privatePath directories from a <probing> element, combined
#         with culture / application base / assembly name.
#         (privatePath directories are evaluated before standard probing
#          locations.)
#       - The location of the calling assembly may be used as a hint for where
#         to find the referenced assembly.
#
# 5. Standard probing when no <codeBase> element is present:
#
#    Application-base probing:
#        [appBase] / <assemblyName>.dll
#        [appBase] / <assemblyName> / <assemblyName>.dll
#
#    Culture-specific probing:
#        [appBase] / <culture> / <assemblyName>.dll
#        [appBase] / <culture> / <assemblyName> / <assemblyName>.dll
#
#    Probing via <probing privatePath="bin;lib;...">:
#        - privatePath values are split on ";" (Windows convention).
#        - For each privatePath:
#            * [appBase] / <privatePath> / <assemblyName>.dll
#            * [appBase] / <privatePath> / <assemblyName> / <assemblyName>.dll
#
#    Calling-assembly influence:
#        - The location of the calling assembly may be used as a hint for
#          where to find the referenced assembly.
#        - The legacy implementation approximated this by probing the
#          parent directory of each installPath entry.
#
# 6. Missing assemblies:
#        - The legacy implementation intentionally did not log assemblies that
#          were not found, because such messages would overwhelmingly consist of
#          unresolved system/core .NET assemblies and produce excessive noise.
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Probing directory construction rules (legacy logic)
#
# For each software.installPath entry:
#     install_basepath = dirname(installPath)
#
# For each referenced assembly:
#
#   If Culture is None or empty ("neutral"):
#       Add directories corresponding to:
#           [application base] / [assembly name].dll
#           [application base] / [assembly name] / [assembly name].dll
#
#       If dnProbingPaths (from <probing privatePath="...">) exists:
#           For each binPath in dnProbingPaths:
#               [application base] / [binpath] / [assembly name].dll
#               [application base] / [binpath] / [assembly name] / [assembly name].dll
#
#   If Culture is specified:
#       Add directories corresponding to:
#           [application base] / [culture] / [assembly name].dll
#           [application base] / [culture] / [assembly name] / [assembly name].dll
#
#       If dnProbingPaths exists:
#           For each binPath in dnProbingPaths:
#               [application base] / [binpath] / [culture] / [assembly name].dll
#               [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
#
# Notes:
#   * dnProbingPaths is derived from:
#       appConfigFile.runtime.assemblyBinding.probing.privatePath
#     and is split on ";" (Windows convention).
#   * These directory patterns mirror the .NET Framework probing rules
#     documented in:
#       https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Absolute-path unmanaged imports behavior (legacy)
#
#   def is_absolute_path(fname: str) -> bool:
#       return PureWindowsPath(fname).is_absolute()
#
# Example:
#     <DllImport("C:\\path\\to\\foo.dll")>
#
# Legacy logic:
#   - If the import Name is an absolute path:
#       * Convert to PureWindowsPath.
#       * For each software entry in the SBOM:
#             For each installPath of that entry:
#                 If the absolute path exactly matches installPath:
#                     → Create a Relationship(dependent_uuid, match.UUID, "Uses")
#
#   - If absolute, no probing or variant-name construction occurs.
#
#   - If not absolute:
#       → Apply unmanaged probing behavior:
#            * Candidate filename list (dll/so/dylib/lib variants)
#            * Search installer directories via find_installed_software()
# -------------------------------------------------------------------------


def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes .NET assembly references.
    """
    return "dotnetAssemblyRef" in metadata


def is_absolute_path(fname: str) -> bool:
    givenpath = pathlib.PureWindowsPath(fname)
    return givenpath.is_absolute()


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: Establish 'Uses' relationships for .NET assembly dependencies.

    Implements a 3-phase resolution strategy:

      1. Primary: Exact path match using sbom.get_software_by_path() (fs_tree)
         - Uses legacy .NET probing directory patterns (get_dotnet_probedirs)
           combined with fs_tree’s symlink and hash-equivalence resolution.

      2. Secondary: Legacy-style match using installPath + fileName
         - Matches assemblies whose installPath basename aligns with the
           referenced assembly's filename variants (e.g., Foo, Foo.dll).

      3. Tertiary: Optional full legacy fallback (O(n^2))
         - When enabled via FULL_DOTNET_LEGACY_PROBE, performs the original
           Surfactant behavior using find_installed_software over all probedirs.

    Also supports:
    - Resolving unmanaged native libraries via dotnetImplMap
      (absolute-path fast path, legacy filename variants, directory-based probing)
    - Honor .NET app.config probing and <codeBase> href paths
    - Filter matches using version and culture metadata when present

    Args:
        sbom (SBOM): The current SBOM graph.
        software (Software): The importing software.
        metadata (dict): Parsed metadata for .NET imports.

    Returns:
        Optional[List[Relationship]]: A list of 'Uses' relationships or None.
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

            # Absolute path fast path (restores legacy behavior, but fs_tree-aware)
            #
            # Legacy did:
            #   - If Name is an absolute Windows path, compare that absolute path
            #     directly against all Software.installPath entries.
            #   - If it matches, emit Uses and skip probing entirely.
            #
            # New behavior:
            #   - Normalize the absolute path to POSIX style.
            #   - Use sbom.get_software_by_path(norm) so we benefit from fs_tree,
            #     directory symlinks, and hash-equivalence edges.
            #   - Skip self (dependent_uuid) to avoid self-loops.
            if is_absolute_path(ref):
                norm = normalize_path(ref)
                match = sbom.get_software_by_path(norm)
                if match and match.UUID != dependent_uuid:
                    logger.debug(f"[.NET][unmanaged][abs] {ref} (norm={norm}) → UUID={match.UUID}")
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                else:
                    logger.debug(f"[.NET][unmanaged][abs] {ref} (norm={norm}) → no match")
                # When an absolute path is used, legacy did *not* attempt any
                # probing or name variants. Preserve that behavior and continue.
                continue

            # Build candidate filenames for unmanaged imports (legacy behavior)
            # Construct a list of combinations specified in (2)
            # Refer to Issue #80 - Need to verify that this conforms with cross-platform behavior
            logger.debug(f"[.NET][unmanaged] resolving import: {ref}")
            combinations = [ref]
            if not (ref.endswith(".dll") or ref.endswith(".exe")):
                combinations.append(f"{ref}.dll")
            combinations.extend(
                [
                    f"{ref}.so",
                    f"lib{ref}.so",
                    f"{ref}.dylib",
                    f"lib{ref}.dylib",
                    f"lib{ref}",
                ]
            )
            logger.debug(f"[.NET][unmanaged] candidates for {ref}: {combinations}")

            # Probe directories from this software's installPath
            probedirs = []
            if isinstance(software.installPath, Iterable):
                for ip in software.installPath or []:
                    probedirs.append(pathlib.PureWindowsPath(ip).parent.as_posix())
            logger.debug(f"[.NET][unmanaged] probedirs for {ref}: {probedirs}")

            found = False
            for match in find_installed_software(sbom, probedirs, combinations):
                if match and match.UUID != dependent_uuid:
                    logger.debug(f"[.NET][unmanaged] {ref} → UUID={match.UUID}")
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                    found = True

            if not found:
                logger.debug(f"[.NET][unmanaged] {ref} → no match")

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
    logger.debug(f"[.NET][import] {software.UUID} importing {len(imports)} assemblies")

    for asmRef in imports:
        refName = asmRef.get("Name")
        refVersion = asmRef.get("Version")
        refCulture = asmRef.get("Culture")
        if not refName:
            continue

        logger.debug(
            f"[.NET][import] resolving {refName} (version={refVersion}, culture={refCulture})"
        )
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
                        logger.debug(f"[.NET][codeBase] {href} → UUID={match.UUID}")
                        relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                    elif not match:
                        logger.debug(f"[.NET][codeBase] {href} → no match")

        # --- Build probing dirs (legacy patterns + fs_tree) ---
        # Prefer the legacy helper if available; it encodes:
        #   - base dir
        #   - base/refName
        #   - culture subdirs
        #   - privatePath combinations
        # This reproduces legacy layout coverage, but we will still resolve
        # through the fs_tree via sbom.get_software_by_path().
        probedirs: list[str] = []
        if get_dotnet_probedirs is not None:
            probedirs = get_dotnet_probedirs(
                software=software,
                refCulture=refCulture,
                refName=refName,
                dnProbingPaths=probing_paths or None,
            )
        else:
            # Fallback: simpler base + privatePath behavior if the legacy helper
            # is not available in this build.
            if isinstance(software.installPath, Iterable):
                for ip in software.installPath or []:
                    base = pathlib.PurePath(ip).parent
                    probedirs.append(base.as_posix())
                    probedirs.extend([normalize_path(base, p) for p in probing_paths])

        logger.debug(f"[.NET][import] probing dirs for {refName}: {probedirs}")

        matched_uuids = set()
        used_method = {}

        def is_valid_match(sw: Software, refVersion=refVersion, refCulture=refCulture) -> bool:
            """
            Apply identity-based filters to ensure that a candidate assembly
            truly corresponds to the referenced assembly.

            A match is rejected when:
              • The candidate is the dependent software itself (avoid self-loops).
              • Version metadata exists on both sides and the versions differ.
              • Culture metadata exists on both sides and the cultures differ.

            Only explicit mismatches are filtered out; if metadata is absent on
            either side, the function allows the match to proceed so that other
            phases may evaluate it.
            """
            # Do not match the importing software to itself
            if sw.UUID == dependent_uuid:
                return False
            
            # Check version and culture metadata when present
            for md in sw.metadata or []:
                asm = md.get("dotnetAssembly")
                if asm:
                    sw_version = asm.get("Version")
                    sw_culture = asm.get("Culture")

                    # Version mismatch
                    if refVersion and sw_version and sw_version != refVersion:
                        logger.debug(
                            f"[.NET][filter] skipping {sw.UUID}: version {sw_version} ≠ {refVersion}"
                        )
                        return False
                    
                    # Culture mismatch
                    if refCulture and sw_culture and sw_culture != refCulture:
                        logger.debug(
                            f"[.NET][filter] skipping {sw.UUID}: culture {sw_culture} ≠ {refCulture}"
                        )
                        return False
            return True

        # Phase 1: fs_tree lookup
        #
        # Construct fully qualified candidate paths by combining each probing
        # directory with each allowed filename variant. Each constructed path
        # is resolved through sbom.get_software_by_path(), which uses the
        # filesystem graph (fs_tree) to account for symlinks, directory links,
        # and hash-equivalent nodes.
        #
        # A match is accepted only when:
        #   • A software entry exists at the resolved path, and
        #   • It satisfies version and culture filters (is_valid_match).
        #
        # This phase provides the most precise form of resolution because it
        # operates on concrete filesystem paths derived from .NET probing rules.
        for probe_dir in sorted(set(probedirs)):
            for fname in fname_variants:
                path = normalize_path(probe_dir, fname)
                match = sbom.get_software_by_path(path)
                ok = bool(match and is_valid_match(match))
                logger.debug(
                    f"[.NET][fs_tree] {path} → {'UUID=' + match.UUID if ok else 'no match'}"
                )
                if ok:
                    matched_uuids.add(match.UUID)
                    used_method[match.UUID] = "fs_tree"

        # Phase 2: installPath + fileName match
        #
        # This phase identifies assemblies by:
        #
        #   1. Checking whether the candidate software entry’s fileName list
        #      includes one of the expected filename variants (e.g., "Foo",
        #      "Foo.dll").
        #
        #   2. Requiring that at least one installPath ends with one of those
        #      variants. This enforces a strict basename match and prevents
        #      false positives from files whose names merely contain the
        #      reference as a substring.
        #
        # The combination of filename and installPath checks ensures that only
        # assemblies with an exact matching basename are selected.
        #
        # Phase 2: Legacy installPath + fileName (only reached if Phase 1 found nothing)
        if not matched_uuids:
            for sw in sbom.software:
                # Skip entries that fail version/culture filtering or that match self
                if not is_valid_match(sw):
                    continue

                # The software must advertise at least one matching fileName
                has_ref_name = isinstance(sw.fileName, Iterable) and any(
                    fn in (sw.fileName or []) for fn in fname_variants
                )
                if not has_ref_name or not isinstance(sw.installPath, Iterable):
                    continue

                # Require an exact filename match via the installPath basename
                for ip in sw.installPath:
                    if any(ip.endswith(fn) for fn in fname_variants):
                        logger.debug(f"[.NET][legacy] {refName} in {ip} → UUID={sw.UUID}")
                        matched_uuids.add(sw.UUID)
                        used_method[sw.UUID] = "legacy_installPath"

        # Phase 3: Optional full legacy probe (O(n^2), feature-flagged)
        if (
            not matched_uuids
            and FULL_DOTNET_LEGACY_PROBE
            and get_dotnet_probedirs is not None
        ):
            legacy_probedirs = get_dotnet_probedirs(
                software=software,
                refCulture=refCulture,
                refName=refName,
                dnProbingPaths=probing_paths or None,
            )
            if legacy_probedirs:
                logger.debug(
                    f"[.NET][legacy_fallback] probing {len(legacy_probedirs)} dirs for {refName}"
                )
                legacy_matches = find_installed_software(
                    sbom=sbom,
                    probedirs=legacy_probedirs,
                    filename=fname_variants,
                )
                for sw in legacy_matches:
                    if not is_valid_match(sw):
                        continue
                    logger.debug(
                        f"[.NET][legacy_fallback] {refName} → {sw.UUID} "
                        f"(installPath match via find_installed_software)"
                    )
                    matched_uuids.add(sw.UUID)
                    used_method[sw.UUID] = "legacy_full_scan"

        # Phase 4: Finalize relationships
        for uuid in matched_uuids:
            rel = Relationship(dependent_uuid, uuid, "Uses")
            if rel not in relationships:
                method = used_method.get(uuid, "unknown")
                logger.debug(
                    f"[.NET][final] {dependent_uuid} Uses {refName} → UUID={uuid} [{method}]"
                )
                relationships.append(rel)

        if not matched_uuids:
            logger.debug(f"[.NET][final] {dependent_uuid} Uses {refName} → no match")

    return relationships
