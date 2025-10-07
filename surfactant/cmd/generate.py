# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib
import queue
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import click
from loguru import logger

from surfactant import ContextEntry
from surfactant.cmd.internal.generate_utils import SpecimenContextParamType
from surfactant.configmanager import ConfigManager
from surfactant.fileinfo import sha256sum
from surfactant.plugin.manager import call_init_hooks, find_io_plugin, get_plugin_manager
from surfactant.relationships import parse_relationships
from surfactant.sbomtypes import SBOM, Software


# Converts from a true path to an install path
def real_path_to_install_path(root_path: str, install_path: str, filepath: str) -> str:
    # appending a "/" to root_path can cause problems if it is "" or already ends with "/"
    if root_path != "" and not root_path.endswith("/"):
        return re.sub("^" + root_path + "/", install_path, filepath)
    return re.sub("^" + root_path, install_path, filepath)


def get_software_entry(
    context_queue,
    current_context,
    pluginmanager,
    parent_sbom: SBOM,
    filepath,
    *,  # arguments past this point are keyword-only
    filetype=None,
    container_uuid=None,
    root_path=None,
    install_path=None,
    user_institution_name="",
    omit_unrecognized_types=False,
    skip_extraction=False,
    container_prefix=None,
) -> Tuple[Software, List[Software]]:
    sw_entry = Software.create_software_from_file(filepath)
    if root_path is not None and install_path is not None:
        sw_entry.installPath = [real_path_to_install_path(root_path, install_path, filepath)]
    if root_path is not None and container_uuid is not None:
        # make sure there is a "/" separating container uuid and the filepath
        if root_path != "" and not root_path.endswith("/"):
            sw_entry.containerPath = [
                re.sub("^" + root_path, container_uuid + container_prefix, filepath)
            ]
        else:
            sw_entry.containerPath = [
                re.sub("^" + root_path, container_uuid + container_prefix + "/", filepath)
            ]
    sw_entry.recordedInstitution = user_institution_name
    sw_children: List[Software] = []
    sw_field_hints: List[Tuple[str, Any, int]] = []

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    extracted_info_results: List[object] = (
        pluginmanager.hook.extract_file_info(
            sbom=parent_sbom,
            software=sw_entry,
            filename=filepath,
            filetype=filetype,
            context_queue=context_queue,
            current_context=current_context,
            children=sw_children,
            software_field_hints=sw_field_hints,
            omit_unrecognized_types=omit_unrecognized_types,
        )
        if not skip_extraction
        else []
    )
    # add metadata extracted from the file
    for file_details in extracted_info_results:
        # None as details doesn't add any useful info...
        if file_details is None:
            continue

        # ensure metadata exists for the software entry
        if sw_entry.metadata is None:
            sw_entry.metadata = []
        sw_entry.metadata.append(file_details)

    # set SBOM fields based on sw_field_hints
    field_confidence: Dict[str, Tuple[Any, int]] = {}
    for field, value, confidence in sw_field_hints:
        # special case since vendor can list multiple values
        if field == "vendor":
            if field not in field_confidence:
                field_confidence[field] = ([], 0)
            field_confidence[field][0].append(value)
        # otherwise, find the value for each field with the highest confidence
        elif field not in field_confidence or confidence > field_confidence[field][1]:
            field_confidence[field] = (value, confidence)

    # set any fields that haven't been set yet (user/previously set fields take precedence)
    for field, (value, _) in field_confidence.items():
        if field == "name" and not sw_entry.name:
            sw_entry.name = value
        elif field == "version" and not sw_entry.version:
            sw_entry.version = value
        elif field == "vendor":
            # make sure the vendor field is initialized
            if sw_entry.vendor is None:
                sw_entry.vendor = []
            # add any new vendors detected to the list
            for vendor in value:
                if vendor not in sw_entry.vendor:
                    sw_entry.vendor.append(vendor)
        elif field == "description" and not sw_entry.description:
            sw_entry.description = value
        elif field == "comments" and not sw_entry.comments:
            sw_entry.comments = value
    return (sw_entry, sw_children)


def print_output_formats(ctx, _, value):
    if not value or ctx.resilient_parsing:
        return
    pm = get_plugin_manager()
    for plugin in pm.get_plugins():
        if hasattr(plugin, "write_sbom"):
            if hasattr(plugin, "short_name"):
                print(plugin.short_name())
            else:
                print(pm.get_canonical_name(plugin))
    ctx.exit()


def print_input_formats(ctx, _, value):
    if not value or ctx.resilient_parsing:
        return
    pm = get_plugin_manager()
    for plugin in pm.get_plugins():
        if hasattr(plugin, "read_sbom"):
            if hasattr(plugin, "short_name"):
                print(plugin.short_name())
            else:
                print(pm.get_canonical_name(plugin))
    ctx.exit()


def determine_install_prefix(
    entry: Optional[ContextEntry] = None,
    extract_path: Optional[Union[str, pathlib.Path]] = None,
    skip_extract_path: bool = False,
) -> Optional[str]:
    """Determine the install prefix based on what is provided in the context entry, and the extract path for the file.

    Args:
        entry (Optional[ContextEntry]): The context entry to check for an install prefix.
        extract_path (Optional[str|pathlib.Path]): The extract path for the file to use as a potential fallback.
        skip_extract_path (bool): Whether the extract_path should be skipped if the entry does not specify an installPrefix.

    Returns:
            Optional[str]: The install prefix to use, or 'NoneType' if an install path shouldn't be listed.
    """
    install_prefix = None
    if entry and (entry.installPrefix or entry.installPrefix == ""):
        install_prefix = entry.installPrefix
    elif not skip_extract_path and extract_path is not None:
        # pathlib doesn't include the trailing slash
        epath = pathlib.Path(extract_path)
        if epath.is_file():
            install_prefix = epath.parent.as_posix() if len(epath.parts) > 1 else ""
        else:
            install_prefix = epath.as_posix()
        # add a trailing slash after last directory name
        if install_prefix != "" and not install_prefix.endswith("/"):
            install_prefix += "/"
    return install_prefix


def get_default_from_config(option: str, fallback: Optional[Any] = None) -> Any:
    """Retrive a core config option for use as default argument value.

    Args:
        option (str): The core config option to get.
        fallback (Optional[Any]): The fallback value if the option is not found.

    Returns:
            Any: The configuration value or 'NoneType' if the key doesn't exist.
    """
    config_manager = ConfigManager()
    return config_manager.get("core", option, fallback=fallback)


@click.command("generate")
@click.argument(
    "specimen_context",
    envvar="SPECIMEN_CONTEXT",
    type=SpecimenContextParamType(),
    required=True,
)
@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sbom", type=click.File("r"), required=False)
@click.option(
    "--skip_gather",
    is_flag=True,
    default=False,
    required=False,
    help="Skip gathering information on files and adding software entries",
)
@click.option(
    "--skip_relationships",
    is_flag=True,
    default=False,
    required=False,
    help="Skip adding relationships based on Linux/Windows/etc metadata",
)
@click.option(
    "--skip_install_path",
    is_flag=True,
    default=False,
    required=False,
    help="Skip including install path information if not given by configuration",
)
@click.option(
    "--recorded_institution",
    is_flag=False,
    default=get_default_from_config("recorded_institution"),
    help="Name of user's institution",
)
@click.option(
    "--output_format",
    is_flag=False,
    default=get_default_from_config("output_format", fallback="surfactant.output.cytrics_writer"),
    help="SBOM output format, see --list-output-formats for list of options; default is CyTRICS",
)
@click.option(
    "--list_output_formats",
    is_flag=True,
    callback=print_output_formats,
    expose_value=False,
    is_eager=True,
    help="List supported output formats",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="Input SBOM format, see --list-input-formats for list of options; default is CyTRICS",
)
@click.option(
    "--list_input_formats",
    is_flag=True,
    callback=print_input_formats,
    expose_value=False,
    is_eager=True,
    help="List supported input formats",
)
@click.option(
    "--omit_unrecognized_types",
    is_flag=True,
    default=get_default_from_config("omit_unrecognized_types", fallback=False),
    required=False,
    help="Omit files with unrecognized types from the generated SBOM.",
)
# Disable positional argument linter check -- could make keyword-only, but then defaults need to be set
# pylint: disable-next=too-many-positional-arguments
def sbom(
    specimen_context: list,
    sbom_outfile: click.File,
    input_sbom: click.File,
    skip_gather: bool,
    skip_relationships: bool,
    skip_install_path: bool,
    recorded_institution: str,
    output_format: str,
    input_format: str,
    omit_unrecognized_types: bool,
):
    """Generate a sbom based on SPECIMEN_CONTEXT and output to SBOM_OUTPUT.

    An optional INPUT_SBOM can be supplied to use as a base for subsequent operations.
    """

    pm = get_plugin_manager()
    call_init_hooks(
        pm, hook_filter=["identify_file_type", "extract_file_info"], command_name="generate"
    )
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    contextQ: queue.Queue[ContextEntry] = queue.Queue()

    for cfg_entry in specimen_context:
        contextQ.put(ContextEntry(**cfg_entry))

    # define the new_sbom variable type
    new_sbom: SBOM
    # Click has Sentinel.UNSET type that doesn't have READ attribute, which may appear when running regression test script
    if not input_sbom or not hasattr(input_sbom, "read"):
        new_sbom = SBOM()
    else:
        new_sbom = input_reader.read_sbom(input_sbom)

    # gather metadata for files and add/augment software entries in the sbom
    if not skip_gather:
        # List of directory symlinks; 2-sized tuples with (source, dest)
        dir_symlinks: List[Tuple[str, str]] = []
        # List of file install path symlinks; keys are SHA256 hashes, values are source paths
        file_symlinks: Dict[str, List[str]] = {}
        # List of filename symlinks; keys are SHA256 hashes, values are file names
        filename_symlinks: Dict[str, List[str]] = {}
        while not contextQ.empty():
            entry: ContextEntry = contextQ.get()
            if entry.archive:
                logger.info("Processing parent container " + str(entry.archive))
                # TODO: if the parent archive has an info extractor that does unpacking interally, should the children be added to the SBOM?
                # current thoughts are (Syft) doesn't provide hash information for a proper SBOM software entry, so exclude these
                # extractor plugins meant to unpack files could be okay when used on an "archive", but then extractPaths should be empty
                parent_entry, _ = get_software_entry(
                    contextQ,
                    entry,
                    pm,
                    new_sbom,
                    entry.archive,
                    filetype=pm.hook.identify_file_type(filepath=entry.archive, context=entry)
                    or [],
                    user_institution_name=recorded_institution,
                    skip_extraction=entry.skipProcessingArchive,
                    container_prefix=entry.containerPrefix,
                )
                archive_entry = new_sbom.find_software(parent_entry.sha256)
                if (
                    archive_entry
                    and parent_entry
                    and Software.check_for_hash_collision(archive_entry, parent_entry)
                ):
                    logger.warning(
                        f"Hash collision between {archive_entry.name} and {parent_entry.name}; unexpected results may occur"
                    )
                if archive_entry:
                    parent_entry = archive_entry
                else:
                    new_sbom.add_software(parent_entry)
                parent_uuid = parent_entry.UUID
            else:
                parent_entry = None
                parent_uuid = None

            # If an installPrefix was given, clean it up some
            if entry.installPrefix:
                if not entry.installPrefix.endswith(("/", "\\")):
                    # Make sure the installPrefix given ends with a "/" (or Windows backslash path, but users should avoid those)
                    logger.warning(
                        "Fixing installPrefix in config file entry (include the trailing /)"
                    )
                    entry.installPrefix += "/"
                if "\\" in entry.installPrefix:
                    # Using an install prefix with backslashes can result in a gradual reduction of the number of backslashes... and weirdness
                    # Ideally even on a Windows "/" should be preferred instead in file paths, but "\" can be a valid character in Linux folder names
                    logger.warning(
                        "Fixing installPrefix with Windows-style backslash path separator in config file (ideally use / as path separator instead of \\, even for Windows"
                    )
                    entry.installPrefix = entry.installPrefix.replace("\\", "\\\\")

            # Clean up the container prefix if needed
            entry.containerPrefix = (
                entry.containerPrefix.strip("/") if entry.containerPrefix is not None else ""
            )
            if entry.containerPrefix != "":
                entry.containerPrefix = "/" + entry.containerPrefix

            for epath_str in entry.extractPaths:
                # convert to pathlib.Path, ensures trailing "/" won't be present and some more consistent path formatting
                epath = pathlib.Path(epath_str)
                install_prefix = determine_install_prefix(
                    entry, epath, skip_extract_path=skip_install_path
                )
                logger.trace("Extracted Path: " + epath.as_posix())

                # variable used to track software entries to add to the SBOM
                entries: List[Software]

                # handle individual file case, since os.walk doesn't
                if epath.is_file():
                    entries = []
                    filepath = epath.as_posix()
                    try:
                        sw_parent, sw_children = get_software_entry(
                            contextQ,
                            entry,
                            pm,
                            new_sbom,
                            filepath,
                            filetype=pm.hook.identify_file_type(filepath=filepath, context=entry)
                            or [],
                            root_path=epath.parent.as_posix() if len(epath.parts) > 1 else "",
                            container_uuid=parent_uuid,
                            install_path=install_prefix,
                            user_institution_name=recorded_institution,
                            container_prefix=entry.containerPrefix,
                        )
                    except Exception as e:
                        raise RuntimeError(f"Unable to process: {filepath}") from e
                    entries.append(sw_parent)
                    entries.extend(sw_children if sw_children else [])
                    new_sbom.add_software_entries(entries, parent_entry=parent_entry)
                    # epath was a file, no need to walk the directory tree
                    continue

                # epath is a directory, walk it
                for cdir, dirs, files in os.walk(epath):
                    logger.info("Processing " + str(cdir))

                    if entry.installPrefix:
                        for dir_ in dirs:
                            full_path = os.path.join(cdir, dir_)
                            if os.path.islink(full_path):
                                dest = resolve_link(
                                    full_path, cdir, epath.as_posix(), entry.installPrefix
                                )
                                if dest is not None:
                                    install_source = real_path_to_install_path(
                                        epath.as_posix(), entry.installPrefix, full_path
                                    )
                                    install_dest = real_path_to_install_path(
                                        epath.as_posix(), entry.installPrefix, dest
                                    )
                                    dir_symlinks.append((install_source, install_dest))

                    entries = []
                    for file in files:
                        # os.path.join will insert an OS specific separator between cdir and f
                        # need to make sure that separator is a / and not a \ on windows
                        filepath = pathlib.Path(cdir, file).as_posix()
                        # TODO: add CI tests for generating SBOMs in scenarios with symlinks... (and just generally more CI tests overall...)
                        # Record symlink details but don't run info extractors on them
                        if os.path.islink(filepath):
                            # NOTE: resolve_link function could print warning if symlink goes outside of extract path dir
                            true_filepath = resolve_link(
                                filepath, cdir, epath.as_posix(), entry.installPrefix
                            )
                            # Dead/infinite links will error so skip them
                            if true_filepath is None:
                                continue
                            # Compute sha256 hash of the file; skip if the file pointed by the symlink can't be opened
                            try:
                                true_file_sha256 = sha256sum(true_filepath)
                            except FileNotFoundError:
                                logger.warning(
                                    f"Unable to open symlink {filepath} pointing to {true_filepath}"
                                )
                                continue
                            # Record the symlink name to be added as a file name
                            # Dead links would appear as a file, so need to check the true path to see
                            # if the thing pointed to is a file or a directory
                            if os.path.isfile(true_filepath):
                                if true_file_sha256 and true_file_sha256 not in filename_symlinks:
                                    filename_symlinks[true_file_sha256] = []
                                symlink_base_name = pathlib.PurePath(filepath).name
                                if symlink_base_name not in filename_symlinks[true_file_sha256]:
                                    filename_symlinks[true_file_sha256].append(symlink_base_name)
                            # Record symlink install path if an install prefix is given
                            if entry.installPrefix:
                                install_filepath = real_path_to_install_path(
                                    epath.as_posix(), entry.installPrefix, filepath
                                )
                                install_dest = real_path_to_install_path(
                                    epath.as_posix(), entry.installPrefix, true_filepath
                                )
                                # A dead link shows as a file so need to test if it's a
                                # file or a directory once rebased
                                if os.path.isfile(true_filepath):
                                    if true_file_sha256 and true_file_sha256 not in file_symlinks:
                                        file_symlinks[true_file_sha256] = []
                                    file_symlinks[true_file_sha256].append(install_filepath)
                                else:
                                    dir_symlinks.append((install_filepath, install_dest))
                            # NOTE Two cases that don't get recorded (but maybe should?) are:
                            # 1. If the file pointed to is outside the extract paths, it won't
                            # appear in the SBOM at all -- is that desirable? If it were included,
                            # should the true path also be included as an install path?
                            # 2. Does a symlink "exist" inside an archive/installer, or only after
                            # unpacking/installation?
                            continue

                        if os.path.isfile(filepath):
                            if not entry.includeFileExts:
                                entry.includeFileExts = []
                            if not entry.excludeFileExts:
                                entry.excludeFileExts = []
                            if (
                                (
                                    ftype := pm.hook.identify_file_type(
                                        filepath=filepath, context=entry
                                    )
                                )
                                or (not (omit_unrecognized_types or entry.omitUnrecognizedTypes))
                                or (
                                    os.path.splitext(filepath)[1].lower()
                                    in [ext.lower() for ext in entry.includeFileExts]
                                )
                            ) and os.path.splitext(filepath)[1].lower() not in [
                                ext.lower() for ext in entry.excludeFileExts
                            ]:
                                try:
                                    sw_parent, sw_children = get_software_entry(
                                        contextQ,
                                        entry,
                                        pm,
                                        new_sbom,
                                        filepath,
                                        filetype=ftype or [],
                                        root_path=epath.as_posix(),
                                        container_uuid=parent_uuid,
                                        install_path=install_prefix,
                                        user_institution_name=recorded_institution,
                                        omit_unrecognized_types=omit_unrecognized_types
                                        or entry.omitUnrecognizedTypes,
                                        container_prefix=entry.containerPrefix,
                                    )
                                except Exception as e:
                                    raise RuntimeError(f"Unable to process: {filepath}") from e

                                entries.append(sw_parent)
                                entries.extend(sw_children if sw_children else [])
                    new_sbom.add_software_entries(entries, parent_entry=parent_entry)

        # Add symlinks to install paths and file names
        for software in new_sbom.software:
            # ensure fileName, installPath, and metadata lists for the software entry have been created
            # for a user supplied input SBOM, there are no guarantees
            if software.fileName is None:
                software.fileName = []
            if software.installPath is None:
                software.installPath = []
            if software.metadata is None:
                software.metadata = []
            if software.sha256 in filename_symlinks:
                filename_symlinks_added = []
                for filename in filename_symlinks[software.sha256]:
                    if filename not in software.fileName:
                        software.fileName.append(filename)
                        filename_symlinks_added.append(filename)
                if filename_symlinks_added:
                    # Store information on which file names are symlinks
                    software.metadata.append({"fileNameSymlinks": filename_symlinks_added})
            if software.sha256 in file_symlinks:
                symlinks_added = []
                for full_path in file_symlinks[software.sha256]:
                    if full_path not in software.installPath:
                        software.installPath.append(full_path)
                        symlinks_added.append(full_path)
                if symlinks_added:
                    # Store information on which install paths are symlinks
                    software.metadata.append({"installPathSymlinks": symlinks_added})

        # Add directory symlink destinations to extract/install paths
        for software in new_sbom.software:
            # NOTE: this probably doesn't actually add any containerPath symlinks
            for paths in (software.containerPath, software.installPath):
                if paths is None:
                    continue
                paths_to_add = []
                for path in paths:
                    for link_source, link_dest in dir_symlinks:
                        if path.startswith(link_dest):
                            # Replace the matching start with the symlink instead
                            # We can't use os.path.join here because we end up with absolute paths after
                            # removing the common start.
                            paths_to_add.append(path.replace(link_dest, link_source, 1))
                if paths_to_add:
                    found_md_installpathsymlinks = False
                    # make sure software.metadata list has been initialized
                    if software.metadata is None:
                        software.metadata = []
                    if isinstance(software.metadata, Iterable):
                        for md in software.metadata:
                            if isinstance(md, Dict) and "installPathSymlinks" in md:
                                found_md_installpathsymlinks = True
                                md["installPathSymlinks"] += paths_to_add
                    if not found_md_installpathsymlinks:
                        software.metadata.append({"installPathSymlinks": paths_to_add})
                    paths += paths_to_add
    else:
        logger.info("Skipping gathering file metadata and adding software entries")

    # add "Uses" relationships based on gathered metadata for software entries
    if not skip_relationships:
        parse_relationships(pm, new_sbom)
    else:
        logger.info("Skipping relationships based on imports metadata")

    # TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
    output_writer.write_sbom(new_sbom, sbom_outfile)


def resolve_link(
    path: str,
    cur_dir: str,
    extract_dir: str,
    install_prefix: Optional[str] = None,
) -> Union[str, None]:
    """
    Safely resolve a symbolic link (`symlink`) to its ultimate target while maintaining
    awareness of the extraction environment, install prefix, and relocation boundaries.

    This function expands both relative and absolute symlinks in a reproducible and
    relocatable way suitable for software supply chain analysis. It handles circular
    references, missing targets, and various absolute-path cases gracefully.

    ---
    Parameters
    ----------
    path : str
        The absolute or relative path to the symlink being resolved.
        Example: "/usr/bin/dirA/runme"
    cur_dir : str
        The directory containing the symlink. Used as the reference base for resolving
        relative paths.
        Example: "/usr/bin/dirA"
    extract_dir : str
        The root of the extracted or analyzed filesystem tree. All rebased links are
        rooted under this directory. Any link resolving outside this boundary is
        considered out-of-scope and excluded.
        Example: "/usr/bin"
    install_prefix : Optional[str]
        The original installation prefix for the analyzed software (e.g., "/usr/bin",
        "/opt/app"). Used to determine whether an absolute link should be rebased,
        preserved, or excluded. If None, "/" is assumed as the logical installation root.

    ---
    Returns
    -------
    str | None
        - The fully resolved, normalized absolute path (as a string) if the target is valid
          and remains within the extraction directory.
        - None if resolution fails due to:
            * Infinite symlink cycle
            * Nonexistent or broken target
            * I/O or permission errors while reading symlinks
            * Final target path lying outside the extraction directory (excluded from SBOM)

    ---
    Resolution Policy
    -----------------
    1. **Relative Symlinks**
       Resolved relative to the directory containing the symlink.
       Example:
           cur_dir = "/usr/bin/dirE"
           link = "link_to_F" → "../dirF"
           result = "/usr/bin/dirF"

    2. **Absolute Symlinks**
       Handled in the following priority order:

       (a) **Within install_prefix**
           If the target starts with `install_prefix`, it is preserved verbatim
           (no rebasing or exclusion).
           Example:
               install_prefix="/usr/bin"
               link="/usr/bin/ls" → preserved as "/usr/bin/ls"

       (b) **Existing system path (outside extract_dir)**
           If the target exists on the host filesystem but lies outside `extract_dir`
           (e.g., "/bin/ls", "/lib/x86_64-linux-gnu/libc.so.6"), it is excluded
           from SBOM generation.

       (c) **Relocatable absolute path (no existing match)**
           If the absolute target does not exist locally and does not match
           `install_prefix`, it is rebased under `extract_dir`.
           Example:
               extract_dir="/opt/pkgroot"
               link="/usr/local/lib/foo.so"
               → "/opt/pkgroot/usr/local/lib/foo.so"

    3. **Normalization**
       The resulting path is normalized using `Path.resolve(strict=False)` to collapse
       redundant `.` and `..` segments without requiring the target to exist. This
       ensures canonical paths for incomplete or partially extracted trees.

    4. **Cycle Detection**
       If the same symlink is encountered more than once during traversal, an infinite
       loop is assumed and resolution stops immediately, returning None.

    5. **Exclusion Rule**
       After normalization, any path not contained within `extract_dir` is considered
       external and excluded from the SBOM (returns None).

    6. **Logging Behavior**
       - DEBUG: for each resolution step and path rebase
       - INFO: when links are skipped because they resolve outside the extraction tree
       - WARNING: for missing targets, broken links, or detected cycles

    ---
    Example
    -------
    Given:
        extract_dir = "/usr/bin"
        install_prefix = "/usr/bin"

    Case 1:
        /usr/bin/dirA/runme → /bin/ls
        → Skipped (outside extraction directory)

    Case 2:
        /usr/bin/dirF/runme → /usr/bin/ls
        → Final resolved path: /usr/bin/ls
    """
    path = pathlib.Path(path)
    cur_dir = pathlib.Path(cur_dir)
    extract_dir = pathlib.Path(extract_dir).resolve(strict=False)

    # Safety check: ensure we are operating inside the extraction tree
    assert str(cur_dir).startswith(str(extract_dir)), (
        f"cur_dir={cur_dir} must be inside extract_dir={extract_dir}"
    )

    seen_paths: set[pathlib.Path] = set()
    current_path = path

    logger.debug(f"Starting resolution for {path} (cur_dir={cur_dir})")

    # Follow symlinks recursively until a non-symlink is reached
    while current_path.is_symlink():
        if current_path in seen_paths:
            logger.warning(f"Infinite loop detected at {current_path}")
            return None
        seen_paths.add(current_path)

        dest = current_path.readlink()
        dest_str = str(dest)
        logger.debug(
            f"{current_path} → {dest} ({'absolute' if dest.is_absolute() else 'relative'})"
        )

        if dest.is_absolute():
            # Case 1: target already under install_prefix (e.g., /usr/bin/echo)
            if install_prefix and dest_str.startswith(install_prefix):
                new_path = pathlib.Path(dest_str)
                logger.debug(
                    f"Absolute symlink {dest} already under install_prefix {install_prefix} → {new_path}"
                )

            # Case 2: absolute path exists on host system (outside extract_dir)
            elif pathlib.Path(dest_str).exists():
                new_path = pathlib.Path(dest_str)
                logger.warning(
                    f"Skipping symlink {path}: resolved target {new_path} lies outside extraction directory {extract_dir}"
                )
                return None  # Exclude from SBOM

            # Case 3: relocatable absolute path (no existing match)
            else:
                try:
                    new_path = extract_dir / dest.relative_to("/")
                except ValueError:
                    # Handle non-Unix paths (e.g., Windows drive letters)
                    rel_dest = dest_str.lstrip("/")
                    new_path = extract_dir / rel_dest
                logger.debug(
                    f"Rebased absolute symlink {dest} under extract_dir {extract_dir} → {new_path}"
                )

        else:
            # Relative symlink: resolve relative to current directory
            new_path = cur_dir / dest
            logger.debug(f"Resolved relative symlink {dest} → {new_path}")

        # Normalize the computed path without requiring its existence
        try:
            new_path = pathlib.Path(new_path).resolve(strict=False)
        except (OSError, RuntimeError) as e:
            logger.warning(f"Symlink resolution failed for {current_path}: {e}")
            return None

        # Ensure target is within extraction directory
        try:
            rel = new_path.relative_to(extract_dir)
        except ValueError:
            logger.info(
                f"Skipping symlink {path}: resolved path {new_path} is outside extraction directory {extract_dir}"
            )
            return None  # Exclude from SBOM

        # Rebase the path under extract_dir for the next iteration
        new_path = extract_dir / rel
        logger.debug(f"Rebasing under extract_dir → {new_path}")

        # Step into the next path in the chain
        current_path = new_path
        cur_dir = current_path.parent
        logger.debug(f"Stepping into {current_path}")

    # Final resolved path validation
    if not current_path.exists():
        logger.warning(f"{path} → {current_path}, but target does not exist")
    else:
        try:
            current_path.relative_to(extract_dir)
        except ValueError:
            logger.info(
                f"Skipping final resolved path for {path}: {current_path} is outside extraction directory {extract_dir}"
            )
        else:
            logger.debug(f"Final resolved path for {path} → {current_path}")
            return str(current_path)

    return None
