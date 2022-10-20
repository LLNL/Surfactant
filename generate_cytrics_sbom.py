# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats
# https://github.com/erocarrera/pefile/blob/master/pefile.py#L2914
# pefile only handles MZ magic bytes, but ZM might be valid as well
# there could also be some other supported Windows EXE formats such as NE, LE, LX, TX, and COM (generally no header, except CP/M 3 format COM has RET instruction)

import os
import re
import time
from hashlib import sha256, sha1, md5
import uuid
import json

import dnfile
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import olefile
import pathlib
from enum import Enum, auto
import sys
import argparse
from deepdiff import DeepDiff

class ExeType(Enum):
    ELF = auto()
    PE = auto()
    OLE = auto()
    JAVA_MACHOFAT = auto()
    MACHO32 = auto()
    MACHO64 = auto()

def check_exe_type(filename):
    try:
        with open(filename, 'rb') as f:
            magic_bytes = f.read(8)
            if magic_bytes[:4] == b"\x7fELF":
                return 'ELF'
            elif magic_bytes[:2] == b"MZ":
                return 'PE'
            elif magic_bytes == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                return 'OLE'
            # elif magic_bytes[:4] == b"\xca\xfe\xba\xbe":
            #    # magic bytes can either be for Java class file or Mach-O Fat Binary
            #    return 'JAVA_MACHOFAT'
            #elif magic_bytes[:4] == b"\xfe\xed\xfa\xce":
            #    return 'MACHO32'
            #elif magic_bytes[:4] == b"\xfe\xed\xfa\xcf":
            #    return 'MACHO64'
            else:
                return None
    except FileNotFoundError:
        return None

def get_file_info(filename):
    try:
        fstats = os.stat(filename)
    except FileNotFoundError:
        return None
    else:
        return {"size": fstats.st_size, "accesstime": fstats.st_atime, "modifytime": fstats.st_mtime, "createtime": fstats.st_ctime}
    

def calc_file_hashes(filename):
    sha256_hash = sha256()
    sha1_hash = sha1()
    md5_hash = md5()
    b = bytearray(4096)
    mv = memoryview(b)
    try:
        with open(filename, "rb", buffering=0) as f:
            while n := f.readinto(mv):
                sha256_hash.update(mv[:n])
                sha1_hash.update(mv[:n])
                md5_hash.update(mv[:n])
    except FileNotFoundError:
        return None
    return {"sha256": sha256_hash.hexdigest(), "sha1": sha1_hash.hexdigest(), "md5": md5_hash.hexdigest()}

def extract_elf_info(filename):
    try:
        f = open(filename, 'rb')
        elf = ELFFile(f)
    except:
        return {}, {}

    file_hdr_details = {}
    file_hdr_details["elfDependencies"] = []
    file_hdr_details["elfRpath"] = []
    file_hdr_details["elfRunpath"] = []
    file_hdr_details["elfSoname"] = []
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                # Shared libraries
                file_hdr_details["elfDependencies"].append(tag.needed)
            elif tag.entry.d_tag == 'DT_RPATH':
                # Library rpath
                file_hdr_details["elfRpath"].append(tag.rpath)
            elif tag.entry.d_tag == 'DT_RUNPATH':
                # Library runpath
                file_hdr_details["elfRunpath"].append(tag.runpath)
            elif tag.entry.d_tag == 'DT_SONAME':
                # Library soname (for linking)
                file_hdr_details["elfSoname"].append(tag.soname)

    if import_dir := getattr(elf, "e_ident", None):
        file_hdr_details["e_ident"] = []
        for entry in import_dir:
            file_hdr_details["e_ident"].append({entry : import_dir[entry]})
    
    file_details = {"OS": "Linux"}

    if elf["e_type"] == 'ET_EXEC':
        file_hdr_details["elfIsExe"] = True
    else:
        file_hdr_details["elfIsExe"] = False

    if elf["e_type"] == 'ET_DYN':
        file_hdr_details["elfIsLib"] = True
    else:
        file_hdr_details['elfIsLib'] = False

    if elf["e_type"] == 'ET_REL':
        file_hdr_details['elfIsRel'] = True
    else:
        file_hdr_details['elfIsRel'] = False

    return file_hdr_details, file_details

def extract_pe_info(filename):
    dnfile.fast_load = False
    try:
        pe = dnfile.dnPE(filename, fast_load=False)
    except:
        return {}, {}

    file_hdr_details = {}

    if import_dir := getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
        #print("---Imported Symbols---")
        file_hdr_details["peImport"] = []
        for entry in import_dir:
             file_hdr_details["peImport"].append(entry.dll.decode())
             #for imp in entry.imports:
             #    print("\t" + hex(imp.address) + " " + str(imp.name))

    if bound_import_dir := getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", None):
        #print("---Bound Imported Symbols---")
        file_hdr_details["peBoundImport"] = []
        for entry in bound_import_dir:
            file_hdr_details["peBoundImport"].append(entry.dll.decode())
            #for imp in entry.imports:
            #    print("\t" + hex(imp.address) + " " + str(imp.name))

    if delay_import_dir := getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None):
        #print("---Delay Imported Symbols---")
        file_hdr_details["peDelayImport"] = []
        for entry in delay_import_dir:
            file_hdr_details["peDelayImport"].append(entry.dll.decode())
            #for imp in entry.imports:
            #    print("\t" + hex(imp.address) + " " + str(imp.name))
    
    file_hdr_details["peIsExe"] = pe.is_exe()
    file_hdr_details["peIsDll"] = pe.is_dll()
    if opt_hdr := getattr(pe, "OPTIONAL_HEADER", None):
        if opt_hdr_data_dir := getattr(opt_hdr, "DATA_DIRECTORY", None):
            #print("---COM Descriptor---")
            com_desc_dir_num = dnfile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            com_desc_dir = opt_hdr_data_dir[com_desc_dir_num]
            file_hdr_details["peIsClr"] = (com_desc_dir.VirtualAddress > 0) and (com_desc_dir.Size > 0)

    file_details = {"OS": "Windows"}
    if pe_fi := getattr(pe, "FileInfo", None):
        if len(pe_fi) > 0:
            for fi_entry in pe_fi[0]:
                if fi_entry.name == "StringFileInfo":
                    for st in fi_entry.StringTable:
                        for st_entry in st.entries.items():
                            file_details[st_entry[0].decode()] = st_entry[1].decode()

    # If this is a .NET assembly, extract information about it from the headers
    if dnet := getattr(pe, "net", None):
        if dnet_flags := getattr(dnet, "Flags", None):
            file_hdr_details["dotnetFlags"] = {
                        "ILONLY": dnet_flags.CLR_ILONLY,
                        "32BITREQUIRED": dnet_flags.CLR_32BITREQUIRED,
                        "IL_LIBRARY": dnet_flags.CLR_IL_LIBRARY,
                        "STRONGNAMESIGNED": dnet_flags.CLR_STRONGNAMESIGNED,
                        "NATIVE_ENTRYPOINT": dnet_flags.CLR_NATIVE_ENTRYPOINT,
                        "TRACKDEBUGDATA": dnet_flags.CLR_TRACKDEBUGDATA,
                        "32BITPREFERRED": dnet_flags.CLR_PREFER_32BIT
                    }
        if dnet_mdtables := getattr(dnet, "mdtables", None):
            if assembly_info := getattr(dnet_mdtables, "Assembly", None):
                assemblies = []
                for a_info in assembly_info:
                    asm = {}
                    asm["Name"] = a_info.Name
                    asm["Culture"] = a_info.Culture
                    asm["Version"] = f"{a_info.MajorVersion}.{a_info.MinorVersion}.{a_info.BuildNumber}.{a_info.RevisionNumber}"
                    asm["PublicKey"] = a_info.PublicKey.decode('unicode_escape')
                    asm["HashAlgId"] = a_info.HashAlgId
                    print("Processing:"+a_info.Name)
                    # Info on flags
                    # Processor Architecture fields/values: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture?view=net-6.0
                    # PA enum values in dnfile: https://github.com/malwarefrank/dnfile/blob/7441fe326e0cc254ed2944a18773d8b4fe99c4c6/src/dnfile/enums.py#L663-L671
                    # .NET runtime corhdr.h PA enum: https://github.com/dotnet/runtime/blob/9d6396deb02161f5ee47af72ccac52c2e1bae458/src/coreclr/inc/corhdr.h#L747-L754
                    # Assembly flags: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assemblyflags?view=net-6.0
                    if a_flags := getattr(a_info, "Flags", None):
                        asm["Flags"] = {
                                    "DisableJitCompileOptimizer": a_flags.afDisableJITcompileOptimizer, # JIT compiler optimization disabled for assembly
                                    "EnableJitCompileTracking": a_flags.afEnableJITcompileTracking, # JIT compiler tracking enabled for assembly
                                    "PublicKey": a_flags.afPublicKey, # assembly ref has the full (unhashed) public key
                                    "Retargetable": a_flags.afRetargetable, # impl of referenced assembly used at runtime may not match version seen at compile time
                                    "PA_Specified": a_flags.afPA_Specified, # propagate processor architecture flags to AssemblyRef record
                                    "PA_None": a_flags.afPA_None,
                                    "PA_MSIL": a_flags.afPA_MSIL,
                                    "PA_x86": a_flags.afPA_x86,
                                    "PA_IA64": a_flags.afPA_IA64,
                                    "PA_AMD64": a_flags.afPA_AMD64,
                                    "PA_ARM": a_flags.afPA_Unknown1, # based on enumeration values in docs, clr runtime corhdr.h, and dnfile
                                    "PA_ARM64": a_flags.afPA_Unknown2,
                                    "PA_NoPlatform": a_flags.afPA_Unknown3 # applies to any platform but cannot run on any (e.g. reference assembly), "specified" should not be set
                                }
                    assemblies.append(asm)
                file_hdr_details["dotnetAssembly"] = assemblies
            if assemblyref_info := getattr(dnet_mdtables, "AssemblyRef", None):
                assembly_refs = []
                for ar_info in assemblyref_info:
                    asmref = {}
                    asmref["Name"] = ar_info.Name
                    asmref["Culture"] = ar_info.Culture
                    asmref["Version"] = f"{ar_info.MajorVersion}.{ar_info.MinorVersion}.{ar_info.BuildNumber}.{ar_info.RevisionNumber}"
                    asmref["PublicKey"] = ar_info.PublicKey.decode('unicode_escape')
                    asmref["HashValue"] = ar_info.HashValue.decode('unicode_escape')
                    print("Processing:"+ar_info.Name)
                    # Info on flags
                    # Processor Architecture fields/values: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture?view=net-6.0
                    # PA enum values in dnfile: https://github.com/malwarefrank/dnfile/blob/7441fe326e0cc254ed2944a18773d8b4fe99c4c6/src/dnfile/enums.py#L663-L671
                    # .NET runtime corhdr.h PA enum: https://github.com/dotnet/runtime/blob/9d6396deb02161f5ee47af72ccac52c2e1bae458/src/coreclr/inc/corhdr.h#L747-L754
                    # Assembly flags: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assemblyflags?view=net-6.0
                    if ar_flags := getattr(ar_info, "Flags", None):
                        asmref["Flags"] = {
                                    "DisableJitCompileOptimizer": ar_flags.afDisableJITcompileOptimizer, # JIT compiler optimization disabled for assembly
                                    "EnableJitCompileTracking": ar_flags.afEnableJITcompileTracking, # JIT compiler tracking enabled for assembly
                                    "PublicKey": ar_flags.afPublicKey, # assembly ref has the full (unhashed) public key
                                    "Retargetable": ar_flags.afRetargetable, # impl of referenced assembly used at runtime may not match version seen at compile time
                                    "PA_Specified": ar_flags.afPA_Specified, # propagate processor architecture flags to AssemblyRef record
                                    "PA_None": ar_flags.afPA_None,
                                    "PA_MSIL": ar_flags.afPA_MSIL,
                                    "PA_x86": ar_flags.afPA_x86,
                                    "PA_IA64": ar_flags.afPA_IA64,
                                    "PA_AMD64": ar_flags.afPA_AMD64,
                                    "PA_ARM": ar_flags.afPA_Unknown1, # based on enumeration values in docs, clr runtime corhdr.h, and dnfile
                                    "PA_ARM64": ar_flags.afPA_Unknown2,
                                    "PA_NoPlatform": ar_flags.afPA_Unknown3 # applies to any platform but cannot run on any (e.g. reference assembly), "specified" should not be set
                                }
                    assembly_refs.append(asmref)
                file_hdr_details["dotnetAssemblyRef"] = assembly_refs

    return file_hdr_details, file_details

def extract_ole_info(filename):
    file_hdr_details = {}
    file_details = {}

    ole = olefile.OleFileIO(filename)
    md = ole.get_metadata()
    file_hdr_details["ole"] = {}
    for prop in md.SUMMARY_ATTRIBS:
        if value := getattr(md, prop, None):
            if type(value) is bytes:
                file_hdr_details["ole"][prop] = value.decode("unicode_escape")
            else:
                file_hdr_details["ole"][prop] = str(value)
    ole.close()
    return file_hdr_details, file_details

def get_software_entry(filename, container_uuid=None, root_path=None, install_path=None):
    file_type = check_exe_type(filename)
    if file_type == 'ELF':
        file_hdr_details, file_info_details = extract_elf_info(filename)
    elif file_type == 'PE':
        file_hdr_details, file_info_details = extract_pe_info(filename)
    elif file_type == 'OLE':
        file_hdr_details, file_info_details = extract_ole_info(filename)
    else:
        # details are just empty; this is the case for archive files (e.g. zip, tar, iso)
        file_hdr_details = []
        file_info_details = []

    metadata = []
    if file_hdr_details:
        metadata.append(file_hdr_details)
    if file_info_details:
        metadata.append(file_info_details)

    # common case is Windows PE file has these details, fallback default value is okay for any other file type
    name = file_info_details["ProductName"] if "ProductName" in file_info_details else ""
    version = file_info_details["FileVersion"] if "FileVersion" in file_info_details else ""
    vendor = [file_info_details["CompanyName"]] if "CompanyName" in file_info_details else []
    description = file_info_details["FileDescription"] if "FileDescription" in file_info_details else ""
    comments = file_info_details["Comments"] if "Comments" in file_info_details else ""

    # less common: OLE file metadata that might be relevant
    if file_type == 'OLE':
        print("-----------OLE--------------")
        if "subject" in file_hdr_details["ole"]:
            name = file_hdr_details["ole"]["subject"]
        if "revision_number" in file_hdr_details["ole"]:
            version = file_hdr_details["ole"]["revision_number"]
        if "author" in file_hdr_details["ole"]:
            vendor.append(file_hdr_details["ole"]["author"])
        if "comments" in file_hdr_details["ole"]:
            comments = file_hdr_details["ole"]["comments"]

    return {
       "UUID": str(uuid.uuid4()),
       **calc_file_hashes(filename),
       "name": name,
       "fileName": [
           pathlib.Path(filename).name
       ],
       "installPath": [re.sub("^"+root_path + "/", install_path, filename)] if root_path and install_path else None,
       "containerPath": [re.sub("^"+root_path, container_uuid, filename)] if root_path and container_uuid else None,
       "size": get_file_info(filename)["size"],
       "captureTime": int(time.time()),
       "version": version,
       "vendor": vendor,
       "description": description,
       "relationshipAssertion": "Unknown",
       "comments": comments,
       "metadata": metadata,
       "supplementaryFiles": [],
       "provenance": None,
       "recordedInstitution": "LLNL",
       "components": [] # or null
    }

def add_relationship(xUUID, yUUID, relationship):
    sbom['relationships'].append({"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship})

# TODO add support for emulating the search paths for dependencies that the OS would follow
def parse_relationships(sbom):
    for sw in sbom['software']:
        dependent_uuid = sw.get('UUID')
        # check each object within the metadata for an 'elfDependencies' key
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
                        add_relationship(dependent_uuid, dependency_uuid[0], "Uses")
                    else:
                        print(f" Dependency {fname} not found for sbom['software'] entry={sw}")

            # handle PE imports
            if 'peImport' in md:
                for fname in md['peImport']:
                    # TODO add a check for the dependency being in the same install folder as the exectutable (depends on being able to get accurate install locations from msi/exe installers)
                    if dependency_uuid := [item.get('UUID') for item in sbom['software'] if item.get('fileName')[0] == fname]:
                        # shouldn't find multiple entries with the same UUID
                        # if we did, there may be files outside of the correct search path that were considered in the previous step
                        add_relationship(dependent_uuid, dependency_uuid[0], "Uses")
                    else:
                        print(f" Dependency {fname} not found for sbom['software'] entry={sw}\n")
            # TODO handle .NET imports
            if 'peBoundImport' in md:
                pass
            if 'peDelayImport' in md:
                pass

def entry_search(sbom, hsh):
    if len(sbom['software']) == 0:
        return False, None
    for index, item in enumerate(sbom['software']):
        if hsh in item['sha256']:
            return True, index
        
    return False, None

def update_entry(sbom, entry, index):
    if index != None:
        # duplicate entry, check other fields to see if data differs. 
        existing_entry = sbom['software'][index]
        if existing_entry != entry:
            # go through each key-value pair between the entries to find the differences and update accordingly.
            existing_uuid = existing_entry['UUID']
            entry_uuid = entry['UUID']
            diff = DeepDiff(existing_entry, entry)['values_changed']
            for key in diff:
                value = diff[key]['new_value']
                location = key.replace("root", "")[2:-2]
                if location not in ['UUID', 'captureTime']:
                    # if new value to replace is an empty string or None - just leave as is
                    if value not in ['', " ", None]:
                        # if value is an array, append the new values; only add if not a duplicate
                        # ex: containerPath (array), fileName, installPath, vendor, metadata, supplementaryFiles, components
                        if isinstance(sbom['software'][index][location], list):
                            for item in sbom['software'][index][location]:
                                entries = eval(value)
                                # case where value is a list cast as a string (because of the DeepDiff output) that needs to be converted back to a list 
                                if isinstance(value, str) and type(entries) == list:
                                    for e in entries:
                                        if e not in item:
                                            sbom['software'][index][location].append(e)
                                else:
                                    raise Exception("Trying to compare a string with a list, when two lists are being compared")
                        # if new value and old value don't match, print some sort of message showing discrepancy
                        if value != sbom['software'][index][location]:
                            raise Exception(f'New value and old value do not match.')
                        
                        # if value is a string, update the dictionary
                        # ex: name, provenance (may be an array?), comments, version, description, relationshipAssertion, recordedInstitution
                        sbom['software'][index].update({location : value})
                
                    # TODO: for intermediate file format, find/figure out way to resolve conflicts between surfactant sboms and those with manual additions
  
            # return UUID of existing entry, UUID of entry being discarded 
            return existing_uuid, entry_uuid
    


#### Main part of code ####

parser = argparse.ArgumentParser()
parser.add_argument('config_file', metavar='CONFIG_FILE', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='Config file (JSON); make sure keys with paths do not have a trailing /')
parser.add_argument('sbom_outfile', metavar='SBOM_OUTPUT', nargs='?', type=argparse.FileType('w'), default=sys.stdout, help='Output SBOM file')
parser.add_argument('-i', '--input_sbom', type=argparse.FileType('r'), help='Input SBOM to use as a base for subsequent operations')
parser.add_argument('--skip_gather', action='store_true', help='Skip gathering information on files and adding software entries')
parser.add_argument('--skip_relationships', action='store_true', help='Skip adding relationships based on Linux/Windows/etc metadata')
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
            parent_entry = get_software_entry(entry["archive"])
            parent_uuid = parent_entry["UUID"]
            sbom["software"].append(parent_entry)
        else:
            parent_entry = None
            parent_uuid = None

        if "installPrefix" in entry:
            install_prefix = entry["installPrefix"]
        else:
            install_prefix = None

        for epath in entry["extractPaths"]:
            print("Extracted Path: " + str(epath))
            for cdir, _, files in os.walk(epath):
                print("Processing " + str(cdir))
            
                entries = [get_software_entry(os.path.join(cdir, f), root_path=epath, container_uuid=parent_uuid, install_path=install_prefix) for f in files if check_exe_type(os.path.join(cdir, f))]
                if entries:
                    # TODO if a software entry already exists with a matching file hash, augment the info in the existing entry
                    # new file name (possibly) to the list of file names, new install path, container path
                    # parent uuid relationship may already exist, needs checking
                    for e in entries:
                        found, index = entry_search(sbom, e['sha256'])
                        if not found:
                            sbom["software"].append(e)
                        else:
                            existing_uuid, entry_uuid = update_entry(sbom, e, index)
                            # TODO use existing uuid and entry uuid to  update the sbom['relationships'] entries
                    # if the config file specified a parent/container for the files, add it as a "Contains" relationship
                    if parent_entry:
                        for e in entries:
                            xUUID = parent_entry["UUID"]
                            yUUID = e["UUID"]
                            sbom["relationships"].append({"xUUID": xUUID, "yUUID": yUUID, "relationship": "Contains"})
else:
    print("Skipping gathering file metadata and adding software entries")

# add "Uses" relationships based on gathered metadata for software entries
if not args.skip_relationships:
    parse_relationships(sbom)
else:
    print("Skipping relationships based on imports metadata")

# TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
json.dump(sbom, args.sbom_outfile, indent=4)




