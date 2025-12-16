# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

from ._internal.posix_utils import posix_normpath


def has_required_fields(metadata) -> bool:
    """
    Checks if the metadata contains the required `elfDependencies` field.

    This function determines whether the `elfDependencies` field exists in the provided
    metadata. This field indicates the necessary
    dependency information to establish relationships.

    Args:
        metadata: The metadata provided to determine the presence of elfDependencies.

    Returns:
        bool: True if the `elfDependencies` field exists in the metadata, False otherwise.

    Raises:
        None
    """
    # no elfDependencies info, can't establish relationships
    return "elfDependencies" in metadata


# Information on loading dynamic libraries from ld.so man page:
# 1. if dependency string contains a slash, it is interpreted as a (relative or absolute) pathname and shared object is loaded using that
# 2. if no slash, search in the following order:
# - use dirs in DT_RPATH if present and DT_RUNPATH doesn't exist (deprecated)
# - use LD_LIBRARY_PATH unless being run in secure-execution mode (in which case ignored)
# - use dirs in DT_RUNPATH if present; only searched to find objects required by DT_NEEDED (direct dependencies) and don't apply to objects' children which must have their own DT_RUNPATH entries (this differs from DT_RPATH, which applies to searches for all children in the dependency tree)
# - from /etc/ld.so.cache, unless binary linked with -z nodeflib linker option then shared objects in the default paths are skipped (shared objects in hardware capability dirs are preferred over other shared objects)
# - in default path /lib, and then /usr/lib (/lib64 and /usr/lib64 maybe for 64-bit libraries); skipped if binary was linked with -z nodeflib linker option
# some strings are expanded; $ORIGIN, $LIB, $PLATFORM
# /etc/ld.so.conf can be used to configure the dynamic loader to search for other directories (such as /usr/local/lib or /opt/lib) as well; format is separate lines naming additional directories, and include <path> statement that can use wildcards to include paths from additional files, such as /etc/ld.so.conf.d/*.conf
# secure execution mode if AT_SECURE entry in auxiliary vector has nonzero value (process real & effective user IDs differ, or real & effectived group IDs differ; process with non-root user ID executed a binary that conferred capabilities to the process; nonzero value set by a Linux Security Module)
# hardware capability directories can be cascaded
# ----- hardware capabilities, recognized names -----
# Alpha: ev4, ev5, ev56, ev6, ev67
# MIPS: loongson2e, loongson2f, octeon, octeon2
# PowerPC: 4xxmac, altivec, arch_2_05, arch_2_06, booke, cellbe, dfp, efpdouble, efpsingle, fpu, ic_snoop, mmu, notb, pa6t, power4, power5, power5+, power6x, ppc32, ppc601, ppc64, smt, spe, ucache, vsx
# SPARC: flush, muldiv, stbar, swap, ultra3, v9, v9v, v9v2
# s390: dfp, eimm, esan3, etf3enh, g5, highgprs, hpage, ldisp, msa, stfle, z900, z990, z9-109, z10, zarch
# x86 (32-bit only): acpi, apic, clflush, cmov, cx8, dts, fxsr, ht, i386, i486, i586, i686, mca, mmx, mtrr, pat, pbe, pge, pn, pse36, sep, ss, sse, sse2, tm


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    Establish relationships between a software item and its dependencies.

    This function processes metadata to identify software dependencies and their
    corresponding relationships. It examines `metadata` for ELF dependencies,
    determines possible file paths for the dependencies, and searches the SBOM
    (Software Bill of Materials) for entries that match these dependencies.

    Args:
        sbom (SBOM): The software bill of materials, containing data about the available software.
        software (Software): The software entity for which relationships are being established.
        metadata: Metadata providing details about the software dependencies. Must contain
            the "elfDependencies" field to describe ELF-based dependencies.

    Returns:
        Optional[List[Relationship]]: A list of `Relationship` objects representing dependencies
        between the specified software and other software items in the SBOM. If the required
        fields in `metadata` are missing, `None` is returned.

    Raises:
        None

    Notes:
        - The function uses `metadata["elfDependencies"]` to locate dependencies described
          as ELF paths or filenames.
        - Relative paths in metadata are normalized and matched against installation paths
          of the candidate software entries.
        - Dependency file paths are cross-referenced with `sbom.software` entries to establish
          their relationships.
        - Returned `Relationship` objects are unique: no duplicates are added to the result list.

    Example:
        relationships = establish_relationships(sbom, software, metadata)
        if relationships:
            for relationship in relationships:
                print(f"{relationship.dependent_uuid} uses {relationship.dependency_uuid}")
    """
    if not has_required_fields(metadata):
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    default_search_paths = generate_search_paths(software, metadata)
    for dep in metadata["elfDependencies"]:
        # if dependency has a slash, it is interpreted as a pathname to shared object to load
        # construct fname and full file path(s) to search for; paths must be a list if the dependency is given as a relative path
        if "/" in dep:
            # search SBOM entries for a library at a matching relative/absolute path
            dep = posix_normpath(
                dep
            )  # normpath takes care of redundancies such as `//`->`/` and `ab/../xy`->`xy`; NOTE may change meaning of path containing symlinks
            fname = dep.name
            if dep.is_absolute():
                # absolute path
                fpaths = [str(dep)]
            else:
                # relative path
                fpaths = []
                # iterate through install paths for sw to get the full path to the file as it would appear in installPaths for the software entry
                if isinstance(software.installPath, Iterable):
                    for ipath in software.installPath:
                        ipath_posix = posix_normpath(
                            ipath
                        )  # NOTE symlinks in install path may be affected by normpath
                        fpaths.append(
                            posix_normpath(str(ipath_posix.parent.joinpath(dep))).as_posix()
                        )  # paths to search are install path folders + relative path of dependency
        else:
            fname = dep
            # the paths for the dependency follow the default search path order for Linux/FreeBSD/etc
            fpaths = [
                p.joinpath(fname).as_posix() for p in default_search_paths
            ]  # append fname to the end of the paths to get the full file install paths of the dependency

        # Look for a software entry with a file name and install path that matches the dependency that would be loaded
        for item in sbom.software:
            # Check if the software entry has a name matching the dependency first as a quick check to rule out non-matches
            if isinstance(item.fileName, Iterable) and fname not in item.fileName:
                continue

            # check if the software entry is installed to one of the paths looked at for loading the dependency
            for fp in fpaths:
                if isinstance(item.installPath, Iterable) and fp in item.installPath:
                    # software matching requirements to be the loaded dependency was found
                    dependency_uuid = item.UUID
                    rel = Relationship(dependent_uuid, dependency_uuid, "Uses")
                    if rel not in relationships:
                        relationships.append(rel)
    return relationships


def generate_search_paths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    """
    Generates a list of search paths for locating runtime libraries.

    This function constructs a list of search paths leveraging the `generate_runpaths`
    function, which generates runtime paths for the given software using PurePosixPath formatting. If the
    metadata specifies the `DF_1_NODEFLIB` flag in `elfDynamicFlags1`, it skips
    default library paths (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`) to comply with
    the `-z nodeflib` linker option.

    Args:
        sw (Software): An object representing the software to generate search
            paths for.
        md: Metadata associated with the software, which may include dynamic
            flags (`elfDynamicFlags1`) to determine if default library paths should
            be excluded.

    Returns:
        List[pathlib.PurePosixPath]: A list of `PurePosixPath` objects representing
        the search paths for runtime library resolution. This includes paths from
        `generate_runpaths`, along with default library paths if `DF_1_NODEFLIB` is
        not set.

    Notes:
        - The `DT_RPATH` dynamic tag has been deprecated.
        - Default library paths are included only if the `-z nodeflib` linker option
          is not specified through the `DF_1_NODEFLIB` flag in `elfDynamicFlags1`.
    """
    # 1. Search using directories in DT_RPATH if present and no DT_RUNPATH exists (use of DT_RPATH is deprecated)
    # 2. Use LD_LIBRARY_PATH environment variable; ignore if suid/sgid binary (nothing to do, we don't have this information w/o running on a live system)
    # 3. Search using directories in DT_RUNPATH if present
    paths = generate_runpaths(sw, md)  # will return an empty list if none

    # 4. From /etc/ld.so.cache (/var/run/ld.so.hints on FreeBSD) list of compiled candidate libraries previously found in augmented library path; if binary was linked with -z nodeflib linker option, libraries in default library paths are skipped
    # /etc/ld.so.conf can be used to add additional directories to defaults (e.g. /usr/local/lib or /opt/lib), but we don't necessarily have a way to gather this info
    # Search in default path /lib, then /usr/lib; skip if binary was linked with -z nodeflib option
    nodeflib = False
    if "elfDynamicFlags1" in md:
        if "DF_1_NODEFLIB" in md["elfDynamicFlags1"]:
            nodeflib = md["elfDynamicFlags1"]["DF_1_NODEFLIB"]
    if not nodeflib:
        # add default search paths
        paths.extend(
            [pathlib.PurePosixPath(p) for p in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]]
        )

    return paths


def generate_runpaths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    """
    Generate a list of resolved runpaths based on the metadata from
    an ELF file and the provided software object.

    This function determines the appropriate runpath entries by analyzing
    DT_RPATH and DT_RUNPATH from ELF metadata (`md`) and substitutes
    dynamic string tokens (DSTs) to produce formatted paths.

    The logic follows these rules:
    1. If `elfRpath` is present in the metadata and `elfRunpath` is not,
       the function uses `elfRpath` as the source of runpaths. Note that
       the use of DT_RPATH is deprecated.
    2. If `elfRunpath` exists, it takes precedence and the function uses
       `elfRunpath` as the source of runpath.
    3. Paths are split using `:` as a separator, and empty path components
       are ignored.
    4. All paths perform DST substitution using the
       `substitute_all_dst()` function.

    Args:
        sw (Software): An object containing dependency and installation information, where
           the software path can be iterated on through all runpath entries.
        md: ELF metadata containing key-values such as `elfRpath`
            and `elfRunpath`.

    Returns:
        List[pathlib.PurePosixPath]: A list of finalized runpaths where
        all dynamic string tokens are resolved. Each path is represented
        as a `pathlib.PurePosixPath` object.

    Example:
        Suppose `md` contains ELF metadata with the following entries:
        ```
       >>>md = {
       >>>"elfRpath": ["/lib:/usr/lib"],
       >>>"elfRunpath": None,
        }
        [
            PurePosixPath('/lib'),
            PurePosixPath('/usr/lib')
        ]
        ```
        And `sw` enables substitution tokens such as `$LIB`.
        The function will return resolved paths by splitting `"/lib:/usr/lib"`
        and applying substitutions where `$LIB` is located.

    Notes:
        - If the ELF file specifies both `DT_RPATH` and `DT_RUNPATH`,
          `DT_RUNPATH` is given precedence.
    """

    # rpath and runpath are lists of strings (just in case an ELF file has several, though that is probably an invalid ELF file)
    rp_to_use = []
    rpath = None
    runpath = None
    if "elfRpath" in md and md["elfRpath"]:
        rpath = md["elfRpath"]
    if "elfRunpath" in md and md["elfRunpath"]:
        runpath = md["elfRunpath"]

    # 1. Search using directories in DT_RPATH if present and no DT_RUNPATH exists (use of DT_RPATH is deprecated)
    # 3. Search using directories in DT_RUNPATH if present
    if rpath and not runpath:
        rp_to_use = rpath
    elif runpath:
        rp_to_use = runpath

    # split up the paths first, then substitute DSTs
    return [
        sp  # append path with DSTs replaced to the list
        for rp in rp_to_use  # iterate through all possible runpath entries
        for p in rp.split(":")  # iterate through all components (paths) in each runpath entry
        if p != ""  # if the path entry is not empty
        for sp in substitute_all_dst(sw, md, p)  # substitute DSTs in the path
    ]


def replace_dst(origstr, dvar, newval) -> str:
    """
    Replaces placeholders in a string with a new value.

    This function replaces occurrences of `$dvar` and `${dvar}` in the input
    string `origstr` with the value specified by `newval`.

     Args:
         origstr (str): The original string.
         dvar (str): The variable name to look for in origstr.
         newval (str): The value to replace occurrences of dvar with.

     Returns:
         str: A new string with all occurrences of `$dvar` and `${dvar}` replaced
         by `newval`.

     Typical Usage Example:
         >>> origstr = "The variable $name and ${name} are placeholders."
         >>> replace_dst(origstr, "name", "Alice")
         'The variable Alice and Alice are placeholders.'

    Raises:
         None

    """
    return origstr.replace("$" + dvar, newval).replace("${" + dvar + "}", newval)


def substitute_all_dst(sw: Software, md, path) -> List[pathlib.PurePosixPath]:
    """
    Substitute dynamic string tokens in a file path with appropriate values.

    This function processes a given file path and substitutes dynamic string tokens
    (e.g., `$ORIGIN`, `$LIB`, `${ORIGIN}`, `${LIB}`) with corresponding values derived
    from the `Software` object `sw` and predefined substitutions (e.g., "lib", "lib64").
    The resulting normalized paths are returned as a list of `pathlib.PurePosixPath` objects.

    Args:
        sw (Software): An object containing dependency and installation information, where
           `sw.installPath` can be an iterable of installation paths.
        md: Metadata that may be used to process the path
        path: The file path containing dynamic linker placeholders.

    Returns:
        List[pathlib.PurePosixPath]: A list of normalized paths with substitutions applied.
        If `$PLATFORM` or `${PLATFORM}` placeholders are found in the input path, an empty list
        is returned, as no substitution is currently implemented for the `PLATFORM` placeholder.

    Raises:
        ValueError: May be raised internally if any errors occur during path manipulation
        (e.g., invalid path operations or substitutions).

    Notes:
        - If `$ORIGIN` or `${ORIGIN}` placeholders are present, the substitution uses the
          parent directory of each path in `sw.installPath`.
        - If `$LIB` or `${LIB}` placeholders are present, the substitution uses "lib" and "lib64".
          This results in branching paths when combined with `$ORIGIN`.
        - `$PLATFORM` or `${PLATFORM}` placeholders are currently unhandled, and thus result in an empty
          returned list.
        - The resulting paths undergo normalization via `posix_normpath`.

    Example:
        >>> sw = Software(installPath=["/usr/bin/app", "/opt/tools"])
        >>> path = "/usr/lib/$ORIGIN/lib/$LIB"
        >>> substitute_all_dst(sw, md, path)
        [
            PurePosixPath('/usr/lib/usr/bin/lib/lib'),
                PurePosixPath('/usr/lib/usr/bin/lib64'),
            PurePosixPath('/usr/lib/opt/lib/lib'),
            PurePosixPath('/usr/lib/opt/lib/lib64'),
        ]
    """
    # substitute any dynamic string tokens found; may result in multiple strings if different variants are possible
    # replace $ORIGIN, ${ORIGIN}, $LIB, ${LIB}, $PLATFORM, ${PLATFORM} tokens
    # places the dynamic linker does this expansion are:
    # - environment vars: LD_LIBRARY_PATH, LD_PRELOAD, and LD_AUDIT
    # - dynamic section tags: DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_AUDIT, and DT_DEPAUDIT
    # - arguments to ld.so: --audit, --library-path, and --preload
    # - the filename arguments to dlopen and dlmopen
    # more details in the `Dynamic string tokens` section of https://man7.org/linux/man-pages/man8/ld.so.8.html
    pathlist: List[pathlib.PurePosixPath] = []
    # ORIGIN: replace with absolute directory containing the program or shared object (with symlinks resolved and no ../ or ./ subfolders)
    # for SUID/SGID binaries, after expansion the normalized path must be in a trusted directory (https://github.com/bminor/glibc/blob/0d41182/elf/dl-load.c#L356-L357, https://github.com/bminor/glibc/blob/0d41182/elf/dl-load.c#L297-L316)
    if (path.find("$ORIGIN") != -1) or (path.find("${ORIGIN}") != -1):
        if isinstance(sw.installPath, Iterable):
            for ipath in sw.installPath:
                origin = pathlib.PurePosixPath(ipath).parent.as_posix()
                pathlist.append(pathlib.PurePosixPath(replace_dst(path, "ORIGIN", origin)))

    # LIB: expands to `lib` or `lib64` depending on arch (x86-64 to lib64, x86-32 to lib)
    if (path.find("$LIB") != -1) or (path.find("${LIB}") != -1):
        if not pathlist:
            # nothing in the original pathlist, use the original path passed in
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "LIB", "lib")))
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "LIB", "lib64")))
        else:
            # perform substitutions with every current entry in pathlist
            pathlist = [
                newp
                for p in pathlist
                for newp in (
                    pathlib.PurePosixPath(replace_dst(p, "LIB", "lib")),
                    pathlib.PurePosixPath(replace_dst(p, "LIB", "lib64")),
                )
            ]

    # PLATFORM: expands to string corresponding to CPU type of the host system (e.g. "x86_64")
    # some archs the string comes from AT_PLATFORM value in auxiliary vector (getauxval)
    if (path.find("$PLATFORM") != -1) or (path.find("${PLATFORM}") != -1):
        # NOTE consider using what is known about the target CPU of the ELF binary, and get all possible PLATFORM values based on that from glibc/muslc source code?
        #      this would take some significant amount of searching (inconsistent in how different platforms set the value), and could result in a large increase in
        #      the number of search paths for a feature that is rarely used (similar to hwcaps subfolder searching)
        # For now, discard paths given that no valid substitution was found
        return []

    # normalize paths after expanding tokens to avoid portions of the path involving  ../, ./, and // occurrences
    pathlist = [posix_normpath(p.as_posix()) for p in pathlist]
    return pathlist
