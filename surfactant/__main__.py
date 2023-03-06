# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import argparse
import json
import os
import pathlib
import platform
import re
import sys
import time
import uuid

import surfactant.pluginsystem  # handles loading the various plugins included with surfactant, for gathering information/relationships/output
from surfactant.fileinfo import calc_file_hashes, get_file_info
from surfactant.filetypeid import check_exe_type, check_hex_type, hex_file_extensions
from surfactant.relationships import (
    add_relationship,
    find_relationship,
    parse_relationships,
)
from surfactant.sbom_utils import entry_search, update_entry


def get_software_entry(
    filename, container_uuid=None, root_path=None, install_path=None, user_institution_name=""
):
    file_type = check_exe_type(filename)

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    file_details = []

    for p in surfactant.pluginsystem.InfoPlugin.get_plugins():
        if p.supports_file(filename, file_type):
            file_details = p.extract_info(filename)
            # only one file type should match; should consider the case of polyglot files eventually
            break

    # add basic file info, and information on what collected the information listed for the file to aid later processing
    stat_file_info = get_file_info(filename)
    collection_info = {
        "collectedBy": "Surfactant",
        "collectionPlatform": platform.platform(),
        "fileInfo": {"mode": stat_file_info["filemode"], "hidden": stat_file_info["filehidden"]},
    }

    metadata = []
    metadata.append(collection_info)
    if file_details:
        metadata.append(file_details)

    # common case is Windows PE file has these details under FileInfo, otherwise fallback default value is fine
    fi = file_details["FileInfo"] if "FileInfo" in file_details else {}
    name = fi["ProductName"] if "ProductName" in fi else ""
    version = fi["FileVersion"] if "FileVersion" in fi else ""
    vendor = [fi["CompanyName"]] if "CompanyName" in fi else []
    description = fi["FileDescription"] if "FileDescription" in fi else ""
    comments = fi["Comments"] if "Comments" in fi else ""

    # less common: OLE file metadata that might be relevant
    if file_type == "OLE":
        print("-----------OLE--------------")
        if "subject" in file_details["ole"]:
            name = file_details["ole"]["subject"]
        if "revision_number" in file_details["ole"]:
            version = file_details["ole"]["revision_number"]
        if "author" in file_details["ole"]:
            vendor.append(file_details["ole"]["author"])
        if "comments" in file_details["ole"]:
            comments = file_details["ole"]["comments"]

    return {
        "UUID": str(uuid.uuid4()),
        **calc_file_hashes(filename),
        "name": name,
        "fileName": [pathlib.Path(filename).name],
        "installPath": [re.sub("^" + root_path + "/", install_path, filename)]
        if root_path and install_path
        else None,
        "containerPath": [re.sub("^" + root_path, container_uuid, filename)]
        if root_path and container_uuid
        else None,
        "size": stat_file_info["size"],
        "captureTime": int(time.time()),
        "version": version,
        "vendor": vendor,
        "description": description,
        "relationshipAssertion": "Unknown",
        "comments": comments,
        "metadata": metadata,
        "supplementaryFiles": [],
        "provenance": None,
        "recordedInstitution": user_institution_name,
        "components": [],  # or null
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "config_file",
        metavar="CONFIG_FILE",
        nargs="?",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help="Config file (JSON); make sure keys with paths do not have a trailing /",
    )
    parser.add_argument(
        "sbom_outfile",
        metavar="SBOM_OUTPUT",
        nargs="?",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="Output SBOM file",
    )
    parser.add_argument(
        "-i",
        "--input_sbom",
        type=argparse.FileType("r"),
        help="Input SBOM to use as a base for subsequent operations",
    )
    parser.add_argument(
        "--skip_gather",
        action="store_true",
        help="Skip gathering information on files and adding software entries",
    )
    parser.add_argument(
        "--skip_relationships",
        action="store_true",
        help="Skip adding relationships based on Linux/Windows/etc metadata",
    )
    parser.add_argument("--recordedinstitution", help="name of user institution", default="LLNL")
    args = parser.parse_args()

    config = json.load(args.config_file)

    if not args.input_sbom:
        sbom = {"software": [], "relationships": []}
    else:
        sbom = json.load(args.input_sbom)

    # gather metadata for files and add/augment software entries in the sbom
    if not args.skip_gather:
        for entry in config:
            if "archive" in entry:
                print("Processing parent container " + str(entry["archive"]))
                parent_entry = get_software_entry(
                    entry["archive"], user_institution_name=args.recordedinstitution
                )
                archive_found, archive_index = entry_search(sbom, parent_entry["sha256"])
                if not archive_found:
                    sbom["software"].append(parent_entry)
                else:
                    parent_entry = sbom["software"][archive_index]
                parent_uuid = parent_entry["UUID"]
            else:
                parent_entry = None
                parent_uuid = None

            if "installPrefix" in entry:
                # TODO in docs mention that installPrefix should use posix style directory separators e.g. C:/Test/example.exe
                install_prefix = entry["installPrefix"]
            else:
                install_prefix = None

            # TODO in docs mention that extractPaths should use posix style directory separators e.g. C:/Test/example.exe
            for epath in entry["extractPaths"]:
                print("Extracted Path: " + str(epath))
                for cdir, _, files in os.walk(epath):
                    print("Processing " + str(cdir))

                    entries = []
                    for f in files:
                        filepath = os.path.join(cdir, f)
                        file_suffix = pathlib.Path(filepath).suffix.lower()
                        if check_exe_type(filepath):
                            entries.append(
                                get_software_entry(
                                    filepath,
                                    root_path=epath,
                                    container_uuid=parent_uuid,
                                    install_path=install_prefix,
                                    user_institution_name=args.recordedinstitution,
                                )
                            )
                        elif (file_suffix in hex_file_extensions) and check_hex_type(filepath):
                            entries.append(
                                get_software_entry(
                                    filepath,
                                    root_path=epath,
                                    container_uuid=parent_uuid,
                                    install_path=install_prefix,
                                    user_institution_name=args.recordedinstitution,
                                )
                            )
                    # entries = [get_software_entry(os.path.join(cdir, f), root_path=epath, container_uuid=parent_uuid, install_path=install_prefix, user_institution_name=args.recordedinstitution) for f in files if check_exe_type(os.path.join(cdir, f))]
                    if entries:
                        # if a software entry already exists with a matching file hash, augment the info in the existing entry
                        for e in entries:
                            found, index = entry_search(sbom, e["sha256"])
                            if not found:
                                sbom["software"].append(e)
                                # if the config file specified a parent/container for the file, add the new entry as a "Contains" relationship
                                if parent_entry:
                                    parent_uuid = parent_entry["UUID"]
                                    child_uuid = e["UUID"]
                                    add_relationship(sbom, parent_uuid, child_uuid, "Contains")
                            else:
                                existing_uuid, entry_uuid, updated_entry = update_entry(
                                    sbom, e, index
                                )
                                # use existing uuid and entry uuid to update parts of the software entry (containerPath) that may be out of date
                                if (
                                    "containerPath" in updated_entry
                                    and updated_entry["containerPath"] is not None
                                ):
                                    for index, value in enumerate(updated_entry["containerPath"]):
                                        if value.startswith(entry_uuid):
                                            updated_entry["containerPath"][index] = value.replace(
                                                entry_uuid, existing_uuid
                                            )
                                # go through relationships and see if any need existing entries updated for the replaced uuid (e.g. merging SBOMs)
                                for index, value in enumerate(sbom["relationships"]):
                                    if value["xUUID"] == entry_uuid:
                                        sbom["relationships"][index]["xUUID"] = existing_uuid
                                    if value["yUUID"] == entry_uuid:
                                        sbom["relationships"][index]["yUUID"] = existing_uuid
                                # add a new contains relationship if the duplicate file is from a different container/archive than previous times seeing the file
                                if parent_entry:
                                    parent_uuid = parent_entry["UUID"]
                                    child_uuid = existing_uuid
                                    # avoid duplicate entries
                                    if not find_relationship(
                                        sbom, parent_uuid, child_uuid, "Contains"
                                    ):
                                        add_relationship(sbom, parent_uuid, child_uuid, "Contains")
                                # TODO a pass later on to check for and remove duplicate relationships should be added just in case
    else:
        print("Skipping gathering file metadata and adding software entries")

    # add "Uses" relationships based on gathered metadata for software entries
    if not args.skip_relationships:
        parse_relationships(sbom)
    else:
        print("Skipping relationships based on imports metadata")

    # TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
    surfactant.pluginsystem.OutputPlugin.get_plugin("CYTRICS").write(sbom, args.sbom_outfile)


if __name__ == "__main__":
    main()
