import hashlib
import pathlib
import random
import string
import sys
import uuid
from collections.abc import Iterable
from typing import Dict, List, Optional, Tuple

import spdx.utils
import spdx.writers.json as jsonwriter
import spdx.writers.tagvalue as tvwriter
from spdx.checksum import Checksum, ChecksumAlgorithm
from spdx.creationinfo import Organization, Tool
from spdx.document import Document
from spdx.file import File, FileType
from spdx.license import License
from spdx.package import Package
from spdx.relationship import Relationship, RelationshipType
from spdx.utils import NoAssert
from spdx.version import Version
from spdx.parsers.loggers import ErrorMessages

import surfactant.plugin
from surfactant import __version__ as surfactant_version
from surfactant.sbomtypes import SBOM, Software, System


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    # NOTE eventually outformat and many fields in SPDX document should be user settable (namespace, name)
    outformat = "json"

    spdx_doc = create_spdx_doc()

    # NOTE CyTRICS SBOM format lumps all file names/container paths together into a single list; preserving
    # a semblance of a file tree with nested filesystem/archive information would help some for establishing
    # SPDX Relationships -- though in general SBOM format conversion isn't straightforward or lossless

    # Create a map of UUIDs to SPDX IDs, for defining SPDX Relationships later
    uuid_to_spdxid: Dict[str, List[str]] = {}

    # Add SPDX packages for systems
    for system in sbom.systems:
        system_uuid, pkg = convert_system_to_spdx_packages(system)
        spdx_doc.add_package(pkg)
        if system_uuid not in uuid_to_spdxid:
            uuid_to_spdxid[system_uuid] = []
        uuid_to_spdxid[system_uuid].append(pkg.spdx_id)

    # Create a map of SPDX IDs for Files that map directly to a known container UUID
    # this gets used to avoid creating excessive relationships if a file is present
    # due to being found within multiple different containers
    container_path_relationships: Dict[Tuple[str, str]] = {}

    for software in sbom.software:
        # Add software entries that contain others as SPDX Packages
        # anything containing other files can be a SPDX Package (directory, container, tarball, zip, etc)
        # some could also be represented as a SPDX File
        if sbom.has_relationship(xUUID=software.UUID, relationship="Contains"):
            software_uuid, pkgs = convert_software_to_spdx_packages(software)
            for pkg in pkgs:
                spdx_doc.add_package(pkg)
                if software_uuid not in uuid_to_spdxid:
                    uuid_to_spdxid[software_uuid] = []
                uuid_to_spdxid[software_uuid].append(pkg.spdx_id)
        # Add all other software entries as SPDX Files
        else:
            for parent_uuid, software_uuid, file in convert_software_to_spdx_files(software):
                spdx_doc.add_file(file)
                if parent_uuid:
                    container_path_relationships[file.spdx_id] = parent_uuid
                if software_uuid:
                    if software_uuid not in uuid_to_spdxid:
                        uuid_to_spdxid[software_uuid] = []
                    uuid_to_spdxid[software_uuid].append(file.spdx_id)

    # Convert relationships into SPDX Relationships
    for rel in sbom.relationships:
        if (rel.xUUID in uuid_to_spdxid) and (rel.yUUID in uuid_to_spdxid):
            # UUID to SPDX ID is (potentially) one-to-many mapping
            for x_spdxid in uuid_to_spdxid[rel.xUUID]:
                for y_spdxid in uuid_to_spdxid[rel.yUUID]:
                    rel_type = rel.relationship.upper()  # Contains will map to SPDX "CONTAINS"

                    # Minimize duplicate contains relationships for files with multiple container paths
                    if (
                        (rel_type == "CONTAINS")
                        and (y_spdxid in container_path_relationships)
                        and (rel.xUUID != container_path_relationships[y_spdxid])
                    ):
                        continue

                    rel_comment = None  # Default value is None
                    try:
                        # Check if rel_type is defined by SPDX; otherwise throws KeyError
                        RelationshipType[rel_type]
                    except KeyError:
                        # Use type "OTHER" and a comment if SPDX doesn't define the relationship type
                        rel_comment = f"Type: {rel_type}"
                        rel_type = "OTHER"
                    spdx_rel = Relationship(f"{x_spdxid} {rel_type} {y_spdxid}", rel_comment)
                    spdx_doc.add_relationship(spdx_rel)

    # Add package verification codes
    for pkg in spdx_doc.packages:
        files = spdx.utils.get_files_in_package(pkg, spdx_doc.files, spdx_doc.relationships)
        pkg.verif_code = spdx.utils.calc_verif_code(files)

    if outformat == "json":
        try:
            jsonwriter.write_document(spdx_doc, outfile)
        except jsonwriter.InvalidDocumentError as e:
            sys.stderr.write(e)
    elif outformat == "tagvalue":
        try:
            tvwriter.write_document(spdx_doc, outfile)
        except tvwriter.InvalidDocumentError as e:
            sys.stderr.write(e)


def convert_system_to_spdx_packages(system: System) -> Tuple[str, Package]:
    # Pick the best name for the package
    name = system.officialName
    if not name and system.name:
        name = system.name

    # Pick a vendor to use as the supplier
    supplier = None
    if system.vendor:
        # assume Organization, not enough info to distinguish People
        supplier = Organization(system.vendor[0])

    return (system.UUID, create_spdx_package(name, system.description, supplier))


def convert_software_to_spdx_packages(software: Software) -> Tuple[str, List[Package]]:
    packages: List[Package] = []
    for fname in software.fileName:
        name = software.name
        if not name:
            # No name, fall-back to the file name
            name = fname
        # Pick a vendor to use as the supplier
        supplier = None
        if software.vendor:
            # assume Organization, not enough info to distinguish People
            supplier = Organization(software.vendor[0])
        packages.append(
            create_spdx_package(
                name,
                software.description,
                supplier,
                file_name=fname,
                version=software.version,
                sha1=software.sha1,
                sha256=software.sha256,
                md5=software.md5,
            )
        )
    return software.UUID, packages


def convert_software_to_spdx_files(software: Software) -> List[Tuple[str, str, File]]:
    files: List[Tuple[str, str, File]] = []
    for cpathstr in software.containerPath:
        cpath = pathlib.PurePath(cpathstr)
        # Less than 2 parts would just be the container path uuid, or a file name
        if len(cpath.parts) > 1:
            # First entry in container path is the parent container UUID
            parent_uuid = cpath.parts[0]
            # Full path to file, relative to package root (starting with "./")
            file_path = "./" + "/".join(cpath.parts[1:])

            idstring = generate_file_idstring(software, cpath.parts[-1])
            file = create_spdx_file(idstring, file_path, software)
            files.append((parent_uuid, software.UUID, file))
    # Alternative if no container paths exist for a software entry
    if not software.containerPath:
        for fname in software.fileName:
            idstring = generate_file_idstring(software, fname)
            file = create_spdx_file(idstring, "./" + fname, software)
            files.append((None, software.UUID, file))
    return files


def create_spdx_doc() -> Document:
    spdx_doc = Document()
    # Document fields set here are mandatory
    spdx_doc.version = Version(2, 2)
    spdx_doc.data_license = License.from_identifier(
        "CC0-1.0"
    )  # SPDX spec requires this to be CC0-1.0
    spdx_doc.spdx_id = "SPDXRef-DOCUMENT"
    spdx_doc.name = "SBOM - DRAFT"  # document name, as designated by the creator

    # NOTE: The URI does not have to be accessible. It is only intended to provide a unique ID.
    # Format is: https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]
    # spdx.org/spdxdocs can be used if the creator does not own their own website.
    spdx_doc.namespace = f"https://spdx.org/spdxdocs/{spdx_doc.name}-{str(uuid.uuid4())}"

    # For including refs to external SPDX Documents: spdx_doc.add_ext_document_reference()

    # Organization or Person can also be added as creators (may use "anonymous")
    spdx_doc.creation_info.add_creator(Tool(f"Surfactant-{surfactant_version}"))
    spdx_doc.creation_info.set_created_now()

    # Optional Document fields
    spdx_doc.comment = "DRAFT SBOM - INCOMPLETE"
    return spdx_doc


def create_spdx_file(idstring: str, file_path: str, software: Software) -> File:
    file = File(file_path)

    # Required File fields
    file.spdx_id = f"SPDXRef-{idstring}"
    file.set_checksum(
        Checksum("SHA1", software.sha1.lower())
    )  # SHA1 required, should probably error if doesn't exist
    if software.sha256:
        file.set_checksum(Checksum("SHA256", software.sha256.lower()))
    if software.md5:
        file.set_checksum(Checksum("MD5", software.md5.lower()))
    file.conc_lics = (
        NoAssert()
    )  # SPDXNone if no license available for file, NoAssert if can't determine
    file.add_lics(
        NoAssert()
    )  # info in actual file (e.g. header, not external such as COPYING.txt); None for nothing, NoAssert for did not look
    if cr_text := get_fileinfo_metadata(software, "LegalCopyright"):
        file.copyright = cr_text  # free-form text field extracted from actual file identifying copyright holder and any dates present
    else:
        file.copyright = (
            NoAssert()
        )  # SPDXNone for nothing present, NoAssert for no attempt to determine

    # Optional File fields
    # One or more of: SOURCE | BINARY | ARCHIVE | APPLICATION | AUDIO | IMAGE | TEXT | VIDEO | DOCUMENTATION | SPDX | OTHER
    file.file_types.append(FileType.BINARY)

    return file


def create_spdx_package(
    name: str,
    summary,
    supplier,
    file_name: Optional[str] = None,
    version: Optional[str] = None,
    sha1: Optional[str] = None,
    sha256: Optional[str] = None,
    md5: Optional[str] = None,
) -> Package:
    pkg = Package()
    # Required Package fields
    pkg.name = name
    idstring = generate_package_idstring(name, version, file_name)
    pkg.spdx_id = f"SPDXRef-{idstring}"
    pkg.download_location = (
        NoAssert()
    )  # SPDXNone if there is no location whatsoever, not just that we "failed" or didn't try to locate one
    pkg.conc_lics = (
        NoAssert()
    )  # if different from declared license, must explain in comments why; NoAssert prefer to have comment
    # pkg.license_comment # any relevant info on analysis that led to concluded license
    pkg.add_lics_from_file(
        NoAssert()
    )  # SPDXNone if no license info detected, NoAssert if didn't try to determine
    pkg.license_declared = (
        NoAssert()
    )  # licenses declared by authors of package, not 3rd party repo; NoAssert since didn't attempt to determine
    pkg.cr_text = (
        NoAssert()
    )  # SPDXNone if no copyright info, NoAssert if didn't try to determine; use any Cr text even if incomplete

    # Optional Package fields
    if version:
        pkg.version = version
    if file_name:
        pkg.file_name = file_name  # actual file name, or path to directory treated as package (subdirectory is denoted with ./)
    # NOTE spdx does not be able to handle packages with multiple vendors listed
    pkg.supplier = supplier if supplier else NoAssert()  # NoAssertion if can't determine
    pkg.originator = (
        NoAssert()
    )  # 3rd party who distributed package is different than the supplier/vendor
    if sha1:
        pkg.set_checksum(Checksum("SHA1", sha1.lower()))
    if sha256:
        pkg.set_checksum(Checksum("SHA256", sha256.lower()))
    if md5:
        pkg.set_checksum(Checksum("MD5", md5.lower()))
    if summary:
        pkg.summary = summary  # concise info on the function or use of package, without having to parse source code
    pkg.homepage = NoAssert()  # SPDXNone if none exists, NoAssert if didn't try to find a homepage
    # pkg.primary_package_purpose can be: APPLICATION | FRAMEWORK | LIBRARY | CONTAINER | OPERATING - SYSTEM |
    # DEVICE | FIRMWARE | SOURCE | ARCHIVE | FILE | INSTALL | OTHER

    return pkg


def generate_random_idstring(num_chars=5) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=num_chars))


def generate_file_idstring(software: Software, filename: str) -> str:
    # Create an SPDXRef unique ID string (valid chars: alphanumeric, ".", and "-")
    # Filename
    idfilename = "".join(ch for ch in filename if (ch.isalnum() or ch in ".-"))
    # Product name
    idproductname = ""
    if software.name:
        idproductname = "".join(ch for ch in software.name if (ch.isalnum() or ch in ".-"))
    # Version
    idversion = ""
    if software.version:
        idversion = "".join(ch for ch in software.version if (ch.isalnum() or ch in ".-"))
    # Return id string with generated unique id appended to ensure no duplicate SPDXRefs for files
    # leaving out "fields" that are empty strings
    return "-".join(
        x for x in [idfilename, idversion, idproductname, generate_random_idstring()] if x
    )


def generate_package_idstring(name: str, version: str, file_name: str) -> str:
    # Create an SPDXRef unique ID string (valid chars: alphanumeric, ".", and "-")
    # Package Name
    idname = ""
    if idname:
        idname = "".join(ch for ch in name if (ch.isalnum() or ch in ".-"))
    # File Name
    idfilename = ""
    if file_name:
        idfilename = "".join(ch for ch in file_name if (ch.isalnum() or ch in ".-"))
    # Package Version
    idversion = ""
    if version:
        idversion = "".join(ch for ch in version if (ch.isalnum() or ch in ".-"))
    # Return id string with generated unique id appended to ensure no duplicate SPDXRefs for files
    # leaving out "fields" that are empty strings
    return "-".join(x for x in [idname, idversion, idfilename, generate_random_idstring()] if x)


def get_fileinfo_metadata(software: Software, field: str) -> Optional[str]:
    if software.metadata and isinstance(software.metadata, Iterable):
        retval = []
        for entry in software.metadata:
            if "FileInfo" in entry and field in entry["FileInfo"]:
                return entry["FileInfo"][field]
    return None


def get_software_field(software: Software, field):
    if hasattr(software, field):
        return getattr(software, field)
    # Copyright field currently only gets populated from Windows PE file metadata
    if field == "Copyright":
        if software.metadata and isinstance(software.metadata, Iterable):
            retval = []
            for entry in software.metadata:
                if "FileInfo" in entry and "LegalCopyright" in entry["FileInfo"]:
                    return entry["FileInfo"]["LegalCopyright"]
    return None


# Verification Code generation used by spdx tools written in Java (not what is defined in SPDX spec)
# based on: https://github.com/spdx/tools/blob/bc35e25/TestFiles/spdx-parser-source/org/spdx/rdfparser/VerificationCodeGenerator.java
# sha1 checksums are lowercase with no leading 0x: https://github.com/spdx/tools/blob/bc35e25d/src/org/spdx/rdfparser/JavaSha1ChecksumGenerator.java
def java_generate_package_verification_code(software: List[Software]):
    skippedFileNames: List[str] = []
    fileNameAndChecksums: List[str] = collect_file_data(software)
    fileNameAndChecksums.sort()
    m = hashlib.sha1()
    for entry in fileNameAndChecksums:
        m.update(bytes(entry, "utf-8"))
    return m.hexdigest, skippedFileNames


def collect_file_data(software: List[Software]) -> List[str]:
    file_data: List[str] = []
    for sw in software:
        # lower case sha1 hash without a leading 0x prefix
        checksum = sw.sha1.lower()
        for fpath in sw.install_path:
            # GitHub spdx/tools uses this format for checksumming file data: checksumValue+"||"+filePath+END_OF_LINE_CHAR
            file_data.append(checksum + "||" + normalize_file_path(fpath) + "\n")
    return file_data


# normalize file path per the Java SPDX utility... not part of the SPDX spec
# NOTE I think GitHub spdx/tools uses a "./" replacement method that is too
# liberal and will mess up directory names ending in a "."; also ".." should
# remove the previously added part of the path
def normalize_file_path(nonNormalizedFilePath: str) -> str:
    # replace backslashes with forward slash
    filePath = nonNormalizedFilePath.replace("\\", "/").strip()
    # this splits the filepath, and removes instances of "./"
    filePathParts = pathlib.Path(filePath).parts
    # move up to higher directories
    if ".." in filePathParts:
        normalizedFilePathParts = []
        for _, part in enumerate(filePathParts):
            if part == "..":
                # go up a directory by removing the last entry from filePathParts
                # going above the last directory could be considered an error
                if len(normalizedFilePathParts) > 0:
                    normalizedFilePathParts.pop()
            else:
                normalizedFilePathParts.append(part)
        filePath = "/".join(normalizedFilePathParts)
    filePath = "./" + filePath
    return filePath
