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

import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import pathlib
import sys


def check_exe_type(filename):
    try:
        with open(filename, 'rb') as f:
            first_two_magic = f.read(2)
            if first_two_magic == b"\x7fE":
                return 'ELF'
            elif first_two_magic == b"MZ":
                return 'PE'
            else:
                return None
    except FileNotFoundError:
        return False

def check_is_exe_file(filename):
    try:
        with open(filename, 'rb') as f:
            first_two_magic = f.read(2)
            if first_two_magic == b"\x7fE" or first_two_magic == b"MZ" :
                return True
            else:
                return False
    except FileNotFoundError:
        return False

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
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                # Shared libraries
                file_hdr_details["elfDependencies"].append(tag.needed)

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
    pefile.fast_load = False
    try:
        pe = pefile.PE(filename, fast_load=False)
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
            com_desc_dir_num = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
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
    return file_hdr_details, file_details

def get_software_entry(filename, container_uuid=None, root_path=None, install_path=None):
    file_type = check_exe_type(filename)
    if file_type == 'ELF':
        file_hdr_details, file_info_details = extract_elf_info(filename)
    elif file_type == 'PE':
        file_hdr_details, file_info_details = extract_pe_info(filename)
    else:
        pass

    metadata = []
    if file_hdr_details:
        metadata.append(file_hdr_details)
    if file_info_details:
        metadata.append(file_info_details)

    return {
       "UUID": str(uuid.uuid4()),
       **calc_file_hashes(filename),
       "name": (file_info_details["ProductName"]) if "ProductName" in file_info_details else "",
       "fileName": [
           pathlib.Path(filename).name
       ],
       "installPath": [re.sub("^"+root_path + "/", install_path, filename)] if root_path and install_path else None,
       "containerPath": [re.sub("^"+root_path, container_uuid, filename)] if root_path and container_uuid else None,
       "size": get_file_info(filename)["size"],
       "captureTime": int(time.time()),
       "version": file_info_details["FileVersion"] if "FileVersion" in file_info_details else "",
       "vendor": [file_info_details["CompanyName"]] if "CompanyName" in file_info_details else [],
       "description": file_info_details["FileDescription"] if "FileDescription" in file_info_details else "",
       "relationshipAssertion": "Unknown",
       "comments": file_info_details["Comments"] if "Comments" in file_info_details else "",
       "metadata": metadata,
       "supplementaryFiles": [],
       "provenance": None,
       "recordedInstitution": "LLNL",
       "components": [] # or null
    }

def parse_relationships(sbom):
    for item in sbom['software']:
        try:
            for i in item['metadata'][0]['elfDependencies']:
                shared_lib = re.split(':', i)
                shared_lib_name = re.split('\[+(.*?)\]', shared_lib[1])
                depends_uuid = item.get('UUID')
                fname = shared_lib_name[1]
                sbom['relationships'].append ({"xUUID": depends_uuid, "yUUID": [item.get('UUID') for item in sbom['software'] if item.get('fileName')[0] == fname][0], "relationship": "Uses"})
        except:
            print(f" Has no dependencies -> sbom['software']= {item}")

#### Main part of code ####

# Make sure json file below doesn't have a trailing '/' at the end of the path.
with open("examples/linux_extracted_config.json", "r") as f:
    config = json.load(f)

sbom = {"software": [], "relationships": []}

for entry in config:
    if "archive" in entry:
        print("Processing parent container " + str(entry["archive"]))
        parent_entry = get_software_entry(entry["archive"])
        sbom["software"].append(parent_entry)
    else:
        parent_entry = None
    if "installPrefix" in entry:
        install_prefix = entry["installPrefix"]
    else:
        install_prefix = None 
    for epath in entry["extractPaths"]:
        print("Extracted Path: " + str(epath))
        for cdir, _, files in os.walk(epath):
            print("Processing " + str(cdir))
            
            if parent_entry:
                entries = [get_software_entry(os.path.join(cdir, f), root_path=epath, container_uuid=parent_entry["UUID"]) for f in files if check_is_exe_file(os.path.join(cdir, f))]
            else:
                entries = [get_software_entry(os.path.join(cdir, f), root_path=epath, install_path=install_prefix) for f in files if check_is_exe_file(os.path.join(cdir, f))]
            if entries:
                sbom["software"].extend(entries)
                if parent_entry:
                    for e in entries:
                        xUUID = parent_entry["UUID"]
                        yUUID = e["UUID"]
                        sbom["relationships"].append({"xUUID": xUUID, "yUUID": yUUID, "relationship": "Contains"})

parse_relationships(sbom)    
                
with open("sbom.json", "w") as f:
    json.dump(sbom, f, indent=4)




