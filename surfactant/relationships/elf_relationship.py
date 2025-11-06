# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

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
    """
    Establishes 'Uses' relationships between a given software entity and its dynamically
    linked ELF dependencies, based on resolved filesystem paths and SBOM entries.

    This function emulates the dynamic linker’s behavior:
    - If a dependency path contains '/', treat it as an absolute or relative path.
    - Otherwise, resolve it using a search path (RPATH, RUNPATH, and system defaults).
    - Uses SBOM's fs_tree (preferred), legacy installPath-based fallback,
      and heuristic matching for symlink-style relationships.

    Parameters:
        sbom (SBOM): The complete software bill of materials.
        software (Software): The software object whose dependencies are being resolved.
        metadata (dict): ELF metadata containing dependency information (e.g. 'elfDependencies').

    Returns:
        Optional[List[Relationship]]: A list of Relationship objects indicating usage,
                                      or None if metadata is incomplete.
    """
    if not has_required_fields(metadata):
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    default_search_paths = generate_search_paths(software, metadata)
    logger.debug(f"[ELF][search] default paths: {[p.as_posix() for p in default_search_paths]}")

    for dep in metadata["elfDependencies"]:
        fpaths = []
        dep_path = posix_normpath(dep)
        fname = dep_path.name  # e.g., 'libfoo.so'

        # Case 1: Dependency has slash — treat as direct path
        if "/" in dep:
            if dep_path.is_absolute():
                fpaths = [dep_path.as_posix()]
            else:
                if isinstance(software.installPath, Iterable):
                    for ipath in software.installPath:
                        ipath_posix = posix_normpath(ipath)
                        combined = ipath_posix.parent.joinpath(dep_path)
                        fpaths.append(combined.as_posix())

        # Case 2: Bare filename — use runpaths and fallback paths
        else:
            fpaths = [p.joinpath(fname).as_posix() for p in default_search_paths]

        # Phase 1: fs_tree lookup
        matched_uuids = set()
        used_method = {}

        for path in fpaths:
            match = sbom.get_software_by_path(path)
            ok = bool(match and match.UUID != software.UUID)
            logger.debug(f"[ELF][fs_tree] {path} → {'UUID=' + match.UUID if ok else 'no match'}")
            if ok:
                matched_uuids.add(match.UUID)
                used_method[match.UUID] = "fs_tree"

        # Phase 2: Legacy installPath fallback
        if not matched_uuids:
            for item in sbom.software:
                has_name = isinstance(item.fileName, Iterable) and fname in (item.fileName or [])
                if not has_name:
                    continue
                for fp in fpaths:
                    if isinstance(item.installPath, Iterable) and fp in (item.installPath or []):
                        if item.UUID != software.UUID:
                            logger.debug(f"[ELF][legacy] {fname} in {fp} → UUID={item.UUID}")
                            matched_uuids.add(item.UUID)
                            used_method[item.UUID] = "legacy_installPath"

        # Phase 3: Symlink-aware heuristic
        # If path-based and legacy matching failed, fall back to checking:
        # - Same fileName as dependency
        # - Located in the same directory as any search path
        if not matched_uuids and fname:
            for item in sbom.software:
                has_name = isinstance(item.fileName, Iterable) and fname in (item.fileName or [])
                if not has_name or not isinstance(item.installPath, Iterable):
                    continue
                for ipath in item.installPath or []:
                    ip_dir = pathlib.PurePosixPath(ipath).parent
                    for fp in fpaths:
                        if pathlib.PurePosixPath(fp).parent == ip_dir:
                            if item.UUID != software.UUID:
                                logger.debug(
                                    f"[ELF][heuristic] {fname} via {ipath} ~ {fp} → UUID={item.UUID}"
                                )
                                matched_uuids.add(item.UUID)
                                used_method[item.UUID] = "heuristic"

        # Emit final relationships
        if matched_uuids:
            for dependency_uuid in matched_uuids:
                if dependency_uuid == software.UUID:
                    continue
                rel = Relationship(dependent_uuid, dependency_uuid, "Uses")
                if rel not in relationships:
                    relationships.append(rel)
                    method = used_method.get(dependency_uuid, "unknown")
                    logger.debug(
                        f"[ELF][final] {dependent_uuid} Uses {fname} → UUID={dependency_uuid} [{method}]"
                    )
        else:
            logger.debug(f"[ELF][final] {dependent_uuid} Uses {fname} → no match")

    logger.debug(f"[ELF][final] emitted {len(relationships)} relationships")
    return relationships


def generate_search_paths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    """
    Combines resolved RPATH/RUNPATH paths with system default paths unless
    DF_1_NODEFLIB is set. This reflects ELF loader behavior for dependency resolution.
    """
    # Start with RPATH or RUNPATH entries, if any.
    # 1. Search using directories in DT_RPATH if present and no DT_RUNPATH exists (use of DT_RPATH is deprecated)
    # 2. Use LD_LIBRARY_PATH environment variable; ignore if suid/sgid binary (nothing to do, we don't have this information w/o running on a live system)
    # 3. Search using directories in DT_RUNPATH if present
    paths = generate_runpaths(sw, md)  # May include $ORIGIN etc., already substituted

    # Check for the DF_1_NODEFLIB dynamic flag: disables default library search
    # 4. From /etc/ld.so.cache (/var/run/ld.so.hints on FreeBSD) list of compiled candidate libraries previously found in augmented library path; if binary was linked with -z nodeflib linker option, libraries in default library paths are skipped
    # /etc/ld.so.conf can be used to add additional directories to defaults (e.g. /usr/local/lib or /opt/lib), but we don't necessarily have a way to gather this info
    # Search in default path /lib, then /usr/lib; skip if binary was linked with -z nodeflib option
    nodeflib = False
    if "elfDynamicFlags1" in md and "DF_1_NODEFLIB" in md["elfDynamicFlags1"]:
        nodeflib = md["elfDynamicFlags1"]["DF_1_NODEFLIB"]

    # If DF_1_NODEFLIB is not set, include default system paths
    if not nodeflib:
        defaults = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        logger.debug(f"[ELF][runpath] DF_1_NODEFLIB not set; adding defaults: {defaults}")
        paths.extend([pathlib.PurePosixPath(p) for p in defaults])

    # Ensure all entries are PurePosixPath objects (in case runpaths included strings)
    return [p if isinstance(p, pathlib.PurePosixPath) else pathlib.PurePosixPath(p) for p in paths]


def generate_runpaths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    """
    Resolves ELF runpaths from metadata using $ORIGIN and other DST substitutions.

    According to the ELF specification:
    - If DT_RUNPATH is present, it takes precedence—even if empty.
    - If DT_RUNPATH is missing or empty (no usable entries), fall back to DT_RPATH.
    - Each entry may contain DST tokens ($ORIGIN, $LIB, etc.) that must be expanded.
    """
    runpaths = []

    rpath = md.get("elfRpath") or []
    runpath = md.get("elfRunpath") if "elfRunpath" in md else None

    # According to ELF spec, presence of DT_RUNPATH disables DT_RPATH
    if runpath is not None:
        # RUNPATH exists: use it only if it contains usable entries
        if any(p.strip() for p in runpath):
            runpaths = runpath
        else:
            runpaths = []  # DT_RUNPATH exists but is empty: skip RPATH
    else:
        runpaths = rpath  # DT_RUNPATH missing entirely, fallback to RPATH

    results = []
    for rp in runpaths:
        for p in rp.split(":"):
            if p.strip():
                results.extend(substitute_all_dst(sw, md, p))

    logger.debug(f"[ELF][runpath] expanded: {results}")
    return [pathlib.PurePosixPath(r) for r in results]


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
    Expands dynamic string tokens (DSTs) in ELF search paths like $ORIGIN, $LIB, $PLATFORM.

    Background and References:
    --------------------------
    The dynamic linker (`ld.so`) performs these substitutions for several contexts:
        - Environment variables: LD_LIBRARY_PATH, LD_PRELOAD, and LD_AUDIT
        - Dynamic section tags: DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_AUDIT, and DT_DEPAUDIT
        - Arguments to ld.so: --audit, --library-path, and --preload
        - Filename arguments to dlopen() and dlmopen()

    More details:
        See the “Dynamic string tokens” section of:
        https://man7.org/linux/man-pages/man8/ld.so.8.html

    Token behavior summary:
        $ORIGIN / ${ORIGIN}:
            Replaced with the absolute directory containing the program or shared object
            (with symlinks resolved and no ../ or ./ components).
            For SUID/SGID binaries, the resolved path must lie in a trusted directory.
            References:
              - glibc: elf/dl-load.c#L356-L357
              - glibc: elf/dl-load.c#L297-L316

        $LIB / ${LIB}:
            Expands to either "lib" or "lib64" depending on architecture
            (e.g. x86-64 → lib64, x86-32 → lib).

        $PLATFORM / ${PLATFORM}:
            Expands to the CPU type string (e.g. "x86_64").
            On some architectures this comes from AT_PLATFORM in the auxiliary vector.
            Implementing full substitution would require target-specific enumeration
            of possible platform values (from glibc or musl sources), which is nontrivial
            and rarely used — similar to hardware capability (hwcaps) subfolder searching.
            For now, such paths are discarded if unresolved.

    If no DSTs are present, the original path is returned unchanged.
    """
    pathlist: List[pathlib.PurePosixPath] = []

    has_origin = "$ORIGIN" in path or "${ORIGIN}" in path
    has_lib = "$LIB" in path or "${LIB}" in path
    has_platform = "$PLATFORM" in path or "${PLATFORM}" in path

    # ----------------------
    # ORIGIN token expansion
    # ----------------------
    if has_origin and isinstance(sw.installPath, Iterable):
        for ipath in sw.installPath:
            origin = pathlib.PurePosixPath(ipath).parent.as_posix()
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "ORIGIN", origin)))

    # ------------------
    # LIB token expansion
    # ------------------
    if has_lib:
        if not pathlist:
            # No ORIGIN was expanded; use original path
            pathlist.append(pathlib.PurePosixPath(path))
        pathlist = [
            newp
            for p in pathlist
            for newp in (
                pathlib.PurePosixPath(replace_dst(p, "LIB", "lib")),
                pathlib.PurePosixPath(replace_dst(p, "LIB", "lib64")),
            )
        ]

    # ----------------------
    # PLATFORM not supported
    # ----------------------
    if has_platform:
        # No way to resolve this reliably (varies by CPU/platform).
        # Returning empty disables unresolved PLATFORM paths.
        return []

    # -------------------------
    # No DSTs? Use original path
    # -------------------------
    if not (has_origin or has_lib or has_platform) and not pathlist:
        pathlist.append(pathlib.PurePosixPath(path))

    # -------------------------
    # Normalize all paths
    # -------------------------
    return [posix_normpath(p.as_posix()) for p in pathlist]
