import json
import os
import pathlib
import re
import pathlib
from typing import List, Union

import click

from surfactant.plugin.manager import get_plugin_manager
from surfactant.relationships import parse_relationships
from surfactant.sbomtypes import SBOM, Software


def get_software_entry(
    pluginmanager,
    parent_sbom: SBOM,
    filepath,
    filetype=None,
    container_uuid=None,
    root_path=None,
    install_path=None,
    user_institution_name="",
) -> Software:
    sw_entry = Software.create_software_from_file(filepath)
    if root_path and install_path:
        sw_entry.installPath = [re.sub("^" + root_path + "/", install_path, filepath)]
    if root_path and container_uuid:
        sw_entry.containerPath = [re.sub("^" + root_path, container_uuid, filepath)]
    sw_entry.recordedInstitution = user_institution_name

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    extracted_info_results = pluginmanager.hook.extract_file_info(
        sbom=parent_sbom, software=sw_entry, filename=filepath, filetype=filetype
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
            print("-----------OLE--------------")
            if "subject" in file_details["ole"]:
                sw_entry.name = file_details["ole"]["subject"]
            if "revision_number" in file_details["ole"]:
                sw_entry.version = file_details["ole"]["revision_number"]
            if "author" in file_details["ole"]:
                sw_entry.vendor.append(file_details["ole"]["author"])
            if "comments" in file_details["ole"]:
                sw_entry.comments = file_details["ole"]["comments"]

    return sw_entry


def validate_config(config):
    for line in config:
        extract_path = line["extractPaths"]
        for pth in extract_path:
            extract_path_convert = pathlib.Path(pth)
            if not extract_path_convert.exists():
                print("invalid path: " + str(pth))
                return False
    return True


@click.command("generate")
@click.argument("config_file", envvar="CONFIG_FILE", type=click.File("r"), required=True)
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
    "--recorded_institution", is_flag=False, default="LLNL", help="Name of user's institution"
)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=surfactant.output.[cytrics|csv|spdx]_writer",
)
def sbom(
    config_file,
    sbom_outfile,
    input_sbom,
    skip_gather,
    skip_relationships,
    recorded_institution,
    output_format,
):
    pm = get_plugin_manager()
    output_writer = pm.get_plugin(output_format)

    config = json.load(config_file)

    # quit if invalid path found
    if not validate_config(config):
        return

    if not input_sbom:
        new_sbom = SBOM()
    else:
        new_sbom = SBOM.from_json(input_sbom.read())

    # gather metadata for files and add/augment software entries in the sbom
    if not skip_gather:
        # List of symlinks; 2-sized tuples with (source, dest)
        symlinks = []
        for entry in config:
            if "archive" in entry:
                print("Processing parent container " + str(entry["archive"]))
                parent_entry = get_software_entry(
                    pm, new_sbom, entry["archive"], user_institution_name=recorded_institution
                )
                archive_entry = new_sbom.find_software(parent_entry.sha256)
                if archive_entry:
                    parent_entry = archive_entry
                else:
                    new_sbom.add_software(parent_entry)
                parent_uuid = parent_entry.UUID
            else:
                parent_entry = None
                parent_uuid = None

            if "installPrefix" in entry:
                install_prefix = entry["installPrefix"]
                # Make sure the installPrefix given ends with a "/" (or Windows backslash path, but users should avoid those)
                if install_prefix and not install_prefix.endswith(("/", "\\")):
                    print("Fixing install path")
                    install_prefix += "/"
            else:
                install_prefix = None

            for epath in entry["extractPaths"]:
                # extractPath should not end with "/" (Windows-style backslash paths shouldn't be used at all)
                if epath.endswith("/"):
                    epath = epath[:-1]
                print("Extracted Path: " + str(epath))
                for cdir, dirs, files in os.walk(epath):
                    print("Processing " + str(cdir))

                    for dir_ in dirs:
                        full_path = os.path.join(cdir, dir_)
                        if os.path.islink(full_path):
                            dest = resolve_link(full_path, cdir, epath)
                            if dest is not None:
                                symlinks.append((dir_, dest))

                    entries: List[Software] = []
                    for f in files:
                        filepath = os.path.join(cdir, f)
                        if os.path.islink(filepath):
                            filepath = resolve_link(filepath, cdir, epath)
                            # Dead/infinite links will error so skip them
                            if filepath is None:
                                continue
                        if ftype := pm.hook.identify_file_type(filepath=filepath):
                            entries.append(
                                get_software_entry(
                                    pm,
                                    new_sbom,
                                    filepath,
                                    filetype=ftype,
                                    root_path=epath,
                                    container_uuid=parent_uuid,
                                    install_path=install_prefix,
                                    user_institution_name=recorded_institution,
                                )
                            )
                    if entries:
                        # if a software entry already exists with a matching file hash, augment the info in the existing entry
                        for e in entries:
                            existing_sw = new_sbom.find_software(e.sha256)
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

        # Add symlink destinations to extract/install paths
        for software in new_sbom.software:
            for paths in (software.containerPath, software.installPath):
                paths_to_add = []
                for path in paths:
                    for link_source, link_dest in symlinks:
                        if path.startswith(link_dest):
                            # Replace the matching start with the symlink instead
                            paths_to_add.append(os.path.join(link_source, path[len(link_dest):]))
                paths += paths_to_add
    else:
        print("Skipping gathering file metadata and adding software entries")

    # add "Uses" relationships based on gathered metadata for software entries
    if not skip_relationships:
        parse_relationships(pm, new_sbom)
    else:
        print("Skipping relationships based on imports metadata")

    # TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
    output_writer.write_sbom(new_sbom, sbom_outfile)


def resolve_link(path: str, cur_dir: str, extract_dir: str) -> Union[str, None]:
    assert cur_dir.startswith(extract_dir)
    # Maximum number of indirections allowed before failing to resolve the link
    MAX_STEPS = 128
    # os.readlink() resolves one step of a symlink
    current_path = path
    steps = 0
    while steps < MAX_STEPS and os.path.islink(current_path):
        steps += 1
        dest = os.readlink(current_path)
        # Convert relative paths to absolute local paths
        if not pathlib.Path(dest).is_absolute():
            common_path = os.path.commonpath([cur_dir, extract_dir])
            local_path = os.path.join('/', cur_dir[len(common_path):])
            dest = os.path.join(local_path, dest)
        # Convert to a canonical form to eliminate .. to prevent reading above extract_dir
        dest = os.path.normpath(dest)
        # We need to get a non-absolute path so os.path.join works as we want
        if pathlib.Path(dest).is_absolute():
            # TODO: Windows support, but how???
            dest = dest[1:]
        # Rebase to get the true location
        current_path = os.path.join(extract_dir, dest)
        cur_dir = os.path.dirname(current_path)
    # If the path is still a symlink we've hit the iteration limit
    if os.path.islink(current_path):
        return None
    if not os.path.exists(current_path):
        return None
    return os.path.normpath(current_path)
