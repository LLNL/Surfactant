# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
import pathlib
import queue
import re
from typing import Dict, List, Optional, Tuple, Union

import click
from loguru import logger

from surfactant import ContextEntry
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.relationships import parse_relationships
from surfactant.sbomtypes import SBOM, Software


# Converts from a true path to an install path
def real_path_to_install_path(root_path: str, install_path: str, filepath: str) -> str:
    return re.sub("^" + root_path + "/", install_path, filepath)


def get_software_entry(
    context,
    pluginmanager,
    parent_sbom: SBOM,
    filepath,
    filetype=None,
    container_uuid=None,
    root_path=None,
    install_path=None,
    user_institution_name="",
) -> Tuple[Software, List[Software]]:
    sw_entry = Software.create_software_from_file(filepath)
    if root_path and install_path:
        sw_entry.installPath = [real_path_to_install_path(root_path, install_path, filepath)]
    if root_path and container_uuid:
        sw_entry.containerPath = [re.sub("^" + root_path, container_uuid, filepath)]
    sw_entry.recordedInstitution = user_institution_name
    sw_children = []

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    extracted_info_results = pluginmanager.hook.extract_file_info(
        sbom=parent_sbom,
        software=sw_entry,
        filename=filepath,
        filetype=filetype,
        context=context,
        children=sw_children,
    )
    # add metadata extracted from the file, and set SBOM fields if metadata has relevant info
    for file_details in extracted_info_results:
        sw_entry.metadata.append(file_details)

        # common case is Windows PE file has these details under FileInfo, otherwise fallback default value is fine
        if "FileInfo" in file_details:
            fi = file_details["FileInfo"]
            if "ProductName" in fi:
                sw_entry.name = fi["ProductName"]
            if "FileVersion" in fi:
                sw_entry.version = fi["FileVersion"]
            if "CompanyName" in fi:
                sw_entry.vendor = [fi["CompanyName"]]
            if "FileDescription" in fi:
                sw_entry.description = fi["FileDescription"]
            if "Comments" in fi:
                sw_entry.comments = fi["Comments"]

        # less common: OLE file metadata that might be relevant
        if filetype == "OLE":
            logger.trace("-----------OLE--------------")
            if "subject" in file_details["ole"]:
                sw_entry.name = file_details["ole"]["subject"]
            if "revision_number" in file_details["ole"]:
                sw_entry.version = file_details["ole"]["revision_number"]
            if "author" in file_details["ole"]:
                sw_entry.vendor.append(file_details["ole"]["author"])
            if "comments" in file_details["ole"]:
                sw_entry.comments = file_details["ole"]["comments"]
    return (sw_entry, sw_children)


def validate_config(config):
    for line in config:
        extract_path = line["extractPaths"]
        for pth in extract_path:
            extract_path_convert = pathlib.Path(pth)
            if not extract_path_convert.exists():
                logger.error("invalid path: " + str(pth))
                return False
    return True


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


def warn_if_hash_collision(soft1: Optional[Software], soft2: Optional[Software]):
    if not soft1 or not soft2:
        return
    # A hash collision occurs if one or more but less than all hashes match or
    # any hash matches but the filesize is different
    collision = False
    if soft1.sha256 == soft2.sha256 or soft1.sha1 == soft2.sha1 or soft1.md5 == soft2.md5:
        # Hashes can be None; make sure they aren't before checking for inequality
        if soft1.sha256 and soft2.sha256 and soft1.sha256 != soft2.sha256:
            collision = True
        elif soft1.sha1 and soft2.sha1 and soft1.sha1 != soft2.sha1:
            collision = True
        elif soft1.md5 and soft2.md5 and soft1.md5 != soft2.md5:
            collision = True
        elif soft1.size != soft2.size:
            collision = True
    if collision:
        logger.warning(
            f"Hash collision between {soft1.name} and {soft2.name}; unexpected results may occur"
        )


@click.command("generate")
@click.argument(
    "config_file",
    envvar="CONFIG_FILE",
    type=click.Path(exists=True),
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
    default="LLNL",
    help="Name of user's institution",
)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, see --list-output-formats for list of options; default is CyTRICS",
)
@click.option(
    "--list-output-formats",
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
    "--list-input-formats",
    is_flag=True,
    callback=print_input_formats,
    expose_value=False,
    is_eager=True,
    help="List supported input formats",
)
def sbom(
    config_file,
    sbom_outfile,
    input_sbom,
    skip_gather,
    skip_relationships,
    skip_install_path,
    recorded_institution,
    output_format,
    input_format,
):
    """Generate a sbom configured in CONFIG_FILE and output to SBOM_OUTPUT.

    An optional INPUT_SBOM can be supplied to use as a base for subsequent operations
    """

    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    if pathlib.Path(config_file).is_file():
        with click.open_file(config_file) as f:
            config = json.load(f)
            # TODO: what if it isn't a JSON config file, but a single file to generate an SBOM for? perhaps file == "archive"?
    else:
        # Emulate a configuration file with the path
        config = []
        config.append({})
        config[0]["extractPaths"] = [config_file]
        config[0]["installPrefix"] = config_file

    # quit if invalid path found
    if not validate_config(config):
        return

    context = queue.Queue()

    for entry in config:
        context.put(ContextEntry(**entry))

    if not input_sbom:
        new_sbom = SBOM()
    else:
        new_sbom = input_reader.read_sbom(input_sbom)

    # gather metadata for files and add/augment software entries in the sbom
    if not skip_gather:
        # List of directory symlinks; 2-sized tuples with (source, dest)
        dir_symlinks: List[Tuple[str, str]] = []
        # List of file symlinks; keys are SHA256 hashes, values are source paths
        file_symlinks: Dict[str, List[str]] = {}
        while not context.empty():
            entry: ContextEntry = context.get()
            if entry.archive:
                logger.info("Processing parent container " + str(entry.archive))
                # TODO: if the parent archive has an info extractor that does unpacking interally, should the children be added to the SBOM?
                # current thoughts are (Syft) doesn't provide hash information for a proper SBOM software entry, so exclude these
                # extractor plugins meant to unpack files could be okay when used on an "archive", but then extractPaths should be empty
                parent_entry, _ = get_software_entry(
                    context,
                    pm,
                    new_sbom,
                    entry.archive,
                    user_institution_name=recorded_institution,
                )
                archive_entry = new_sbom.find_software(parent_entry.sha256)
                warn_if_hash_collision(archive_entry, parent_entry)
                if archive_entry:
                    parent_entry = archive_entry
                else:
                    new_sbom.add_software(parent_entry)
                parent_uuid = parent_entry.UUID
            else:
                parent_entry = None
                parent_uuid = None

            if entry.installPrefix and not entry.installPrefix.endswith(("/", "\\")):
                # Make sure the installPrefix given ends with a "/" (or Windows backslash path, but users should avoid those)
                logger.warning("Fixing install path")
                entry.installPrefix += "/"

            for epath in entry.extractPaths:
                # extractPath should not end with "/" (Windows-style backslash paths shouldn't be used at all)
                if epath.endswith("/"):
                    epath = epath[:-1]
                logger.trace("Extracted Path: " + str(epath))
                for cdir, dirs, files in os.walk(epath):
                    logger.info("Processing " + str(cdir))

                    if entry.installPrefix:
                        for dir_ in dirs:
                            full_path = os.path.join(cdir, dir_)
                            if os.path.islink(full_path):
                                dest = resolve_link(full_path, cdir, epath, entry.installPrefix)
                                if dest is not None:
                                    install_source = real_path_to_install_path(
                                        epath, entry.installPrefix, full_path
                                    )
                                    install_dest = real_path_to_install_path(
                                        epath, entry.installPrefix, dest
                                    )
                                    dir_symlinks.append((install_source, install_dest))

                    entries: List[Software] = []
                    for f in files:
                        # os.path.join will insert an OS specific separator between cdir and f
                        # need to make sure that separator is a / and not a \ on windows
                        filepath = pathlib.Path(cdir, f).as_posix()
                        file_is_symlink = False
                        # TODO: add CI tests for generating SBOMs in scenarios with symlinks... (and just generally more CI tests overall...)
                        if os.path.islink(filepath):
                            true_filepath = resolve_link(filepath, cdir, epath, entry.installPrefix)
                            # Dead/infinite links will error so skip them
                            if true_filepath is None:
                                continue
                            # Otherwise add them and skip adding the entry
                            if entry.installPrefix:
                                install_filepath = real_path_to_install_path(
                                    epath, entry.installPrefix, filepath
                                )
                                install_dest = real_path_to_install_path(
                                    epath, entry.installPrefix, true_filepath
                                )
                                # A dead link shows as a file so need to test if it's a
                                # file or a directory once rebased
                                if os.path.isfile(true_filepath):
                                    # file_symlinks.append((install_filepath, install_dest))
                                    file_is_symlink = True
                                else:
                                    dir_symlinks.append((install_filepath, install_dest))
                                    continue
                            # We need get_software_entry to look at the true filepath
                            filepath = true_filepath

                        if entry.installPrefix or entry.installPrefix == "":
                            install_path = entry.installPrefix
                        elif not skip_install_path:
                            # epath is guaranteed to not have an ending slash due to formatting above
                            install_path = epath + "/"
                        else:
                            install_path = None

                        if ftype := pm.hook.identify_file_type(filepath=filepath):
                            try:
                                sw_parent, sw_children = get_software_entry(
                                    context,
                                    pm,
                                    new_sbom,
                                    filepath,
                                    filetype=ftype,
                                    root_path=epath,
                                    container_uuid=parent_uuid,
                                    install_path=install_path,
                                    user_institution_name=recorded_institution,
                                )
                            except Exception as e:
                                raise RuntimeError(f"Unable to process: {filepath}") from e

                            if file_is_symlink and entry.installPrefix:
                                # Track the symlink, but don't add to list of entries
                                # as it'll be processed later anyways
                                if sw_parent.sha256 not in file_symlinks:
                                    file_symlinks[sw_parent.sha256] = []
                                file_symlinks[sw_parent.sha256].append(install_filepath)
                            else:
                                entries.append(sw_parent)
                                for sw in sw_children:
                                    entries.append(sw)

                    if entries:
                        # if a software entry already exists with a matching file hash, augment the info in the existing entry
                        for e in entries:
                            existing_sw = new_sbom.find_software(e.sha256)
                            warn_if_hash_collision(existing_sw, e)
                            if not existing_sw:
                                new_sbom.add_software(e)
                                # if the config file specified a parent/container for the file, add the new entry as a "Contains" relationship
                                if parent_entry:
                                    parent_uuid = parent_entry.UUID
                                    child_uuid = e.UUID
                                    new_sbom.create_relationship(
                                        parent_uuid, child_uuid, "Contains"
                                    )
                            else:
                                existing_uuid, entry_uuid = existing_sw.merge(e)
                                # go through relationships and see if any need existing entries updated for the replaced uuid (e.g. merging SBOMs)
                                for rel in new_sbom.relationships:
                                    if rel.xUUID == entry_uuid:
                                        rel.xUUID = existing_uuid
                                    if rel.yUUID == entry_uuid:
                                        rel.yUUID = existing_uuid
                                # add a new contains relationship if the duplicate file is from a different container/archive than previous times seeing the file
                                if parent_entry:
                                    parent_uuid = parent_entry.UUID
                                    child_uuid = existing_uuid
                                    # avoid duplicate entries
                                    if not new_sbom.find_relationship(
                                        parent_uuid, child_uuid, "Contains"
                                    ):
                                        new_sbom.create_relationship(
                                            parent_uuid, child_uuid, "Contains"
                                        )
                                # TODO a pass later on to check for and remove duplicate relationships should be added just in case

        # Add file symlinks to install paths
        for software in new_sbom.software:
            if software.sha256 in file_symlinks:
                symlinks_added = []
                for full_path in file_symlinks[software.sha256]:
                    if full_path not in software.installPath:
                        software.installPath.append(full_path)
                        symlinks_added.append(full_path)
                    base_name = pathlib.PurePath(full_path).name
                    if base_name not in software.fileName:
                        software.fileName.append(base_name)
                if symlinks_added:
                    # Store information on which install paths are symlinks
                    software.metadata.append({"installPathSymlinks": symlinks_added})

        # Add directory symlink destinations to extract/install paths
        for software in new_sbom.software:
            # NOTE: this probably doesn't actually add any containerPath symlinks
            for paths in (software.containerPath, software.installPath):
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
                    for md in software.metadata:
                        if "installPathSymlinks" in md:
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
    path: str, cur_dir: str, extract_dir: str, install_prefix: str = None
) -> Union[str, None]:
    assert cur_dir.startswith(extract_dir)
    # Links seen before
    seen_paths = set()
    # os.readlink() resolves one step of a symlink
    current_path = path
    steps = 0
    while os.path.islink(current_path):
        # If we've already seen this then we're in an infinite loop
        if current_path in seen_paths:
            logger.warning(f"Resolving symlink {path} encountered infinite loop at {current_path}")
            return None
        seen_paths.add(current_path)
        dest = os.readlink(current_path)
        # Convert relative paths to absolute local paths
        if not pathlib.Path(dest).is_absolute():
            common_path = os.path.commonpath([cur_dir, extract_dir])
            local_path = os.path.join("/", cur_dir[len(common_path) :])
            dest = os.path.join(local_path, dest)
        # Convert to a canonical form to eliminate .. to prevent reading above extract_dir
        # NOTE: should consider detecting reading above extract_dir and warn the user about incomplete file system structure issues
        dest = os.path.normpath(dest)
        if install_prefix and dest.startswith(install_prefix):
            dest = dest[len(install_prefix) :]
        # We need to get a non-absolute path so os.path.join works as we want
        if pathlib.Path(dest).is_absolute():
            # TODO: Windows support, but how???
            dest = dest[1:]
        # Rebase to get the true location
        current_path = os.path.join(extract_dir, dest)
        cur_dir = os.path.dirname(current_path)
    if not os.path.exists(current_path):
        logger.warning(f"Resolved symlink {path} to a path that doesn't exist {current_path}")
        return None
    return os.path.normpath(current_path)
