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
    return origstr.replace("$" + dvar, newval).replace("${" + dvar + "}", newval)


def substitute_all_dst(sw: Software, md, path) -> List[pathlib.PurePosixPath]:
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
                pathlist.append(replace_dst(path, "ORIGIN", origin))

    # LIB: expands to `lib` or `lib64` depending on arch (x86-64 to lib64, x86-32 to lib)
    if (path.find("$LIB") != -1) or (path.find("${LIB}") != -1):
        if not pathlist:
            # nothing in the original pathlist, use the original path passed in
            pathlist.append(replace_dst(path, "LIB", "lib"))
            pathlist.append(replace_dst(path, "LIB", "lib64"))
        else:
            # perform substitutions with every current entry in pathlist
            pathlist = [
                newp
                for p in pathlist
                for newp in (
                    replace_dst(p, "LIB", "lib"),
                    replace_dst(p, "LIB", "lib64"),
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
    pathlist = [posix_normpath(p) for p in pathlist]
    return pathlist
