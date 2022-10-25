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
import defusedxml.ElementTree
import pathlib
from enum import Enum, auto
import sys
import string
import argparse
from deepdiff import DeepDiff

class ExeType(Enum):
    ELF = auto()
    PE = auto()
    OLE = auto()
    JAVA_MACHOFAT = auto()
    MACHO32 = auto()
    MACHO64 = auto()

def check_motorola(current_line):
    current_line = current_line.strip()
    if len(current_line) < 1:
        return False
    if current_line[0] != 'S' and current_line[0] != 's':
        return False
    for x in range(1, len(current_line)):
        if current_line[x] not in string.hexdigits:
            return False
    return True

def check_intel(current_line):
    current_line = current_line.strip()
    if len(current_line) < 1:
        return False
    if current_line[0] != ':':
        return False
    for x in range(1, len(current_line)):
        if current_line[x] not in string.hexdigits:
            return False
    return True

# extensions from:
# https://en.wikipedia.org/wiki/Intel_HEX
# - not included: all p00 to pff extensions
# https://en.wikipedia.org/wiki/SREC_(file_format)
hex_file_extensions = [".hex", ".mcs", ".h86", ".hxl", ".hxh", ".obl", ".obh", ".ihex", ".ihe", ".ihx", ".a43", ".a90", ".s-record", ".srecord", ".s-rec", ".srec", ".s19", ".s28", ".s37", ".s", ".s1", ".s2", ".s3", ".sx", ".exo", ".mot", ".mxt"]

def check_hex_type(filename):
    try:
        with open(filename, 'r') as f:
            
            percent_intel = 0
            percent_motorola = 0
            for line in range(100):
                curr = f.readline()
                if not curr:
                    break
                if check_motorola(curr):
                    percent_motorola+=1
                elif check_intel(curr):
                    percent_intel+=1
            if percent_intel > percent_motorola:
                return "INTEL_HEX"
            elif percent_motorola > percent_intel:
                return "MOTOROLA_SREC"
            else:
                return None
            
    except FileNotFoundError:
        return False

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
            #elif magic_bytes[:4] == b"\xde\xc0\x17\x0b":
            #    return 'LLVM_BITCODE'
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
                    asm["PublicKey"] = a_info.PublicKey.hex()
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
                    asmref["PublicKey"] = ar_info.PublicKey.hex()
                    asmref["HashValue"] = ar_info.HashValue.hex()
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

    # TODO for a custom intermediate SBOM format, the information read from the manifest and app config files
    # should be tied to a specific "<install path>/<file name>", in case the same file appears in separate
    # directories/file systems with different manifest/config file settings for paths to search
    file_details["dllRedirectionLocal"] = check_windows_dll_redirection_local(filename)

    manifest_info = get_windows_manifest_info(filename)
    if manifest_info:
        file_details["manifestFile"] = manifest_info

    app_config_info = get_windows_application_config_info(filename)
    if app_config_info:
        file_details["appConfigFile"] = app_config_info

    return file_hdr_details, file_details

def get_xmlns_and_tag(uri):
    check_xmlns = re.match(r'\{.*\}', uri.tag)
    xmlns = check_xmlns.group(0) if check_xmlns else ''
    tag = uri.tag
    if tag.startswith(xmlns):
        tag = tag.replace(xmlns, "", 1)
    return xmlns, tag

# check for manifest file on Windows (note: could also be a resource contained within an exe/dll)
# return any info that could be useful for establishing "Uses" relationships later
def get_windows_manifest_info(filename):
    binary_filepath = pathlib.Path(filename)
    manifest_filepath = binary_filepath.with_suffix(binary_filepath.suffix + '.manifest')
    if manifest_filepath.exists():
        print("Found application manifest file for " + filename)
        et = defusedxml.ElementTree.parse(manifest_filepath)
        manifest_info = {}

        # root element is <assembly> which could contain:
        # <assemblyIdentity>
        # <file>
        # <dependency>, which contains the usual <dependentAssembly> element found in Windows app config files
        for asm_e in et.getroot():
            asm_xmlns, asm_tag = get_xmlns_and_tag(asm_e)
            if asm_tag == "assemblyIdentity":
                if "assemblyIdentity" in manifest_info:
                    print("[WARNING] duplicate assemblyIdentity element found in the manifest file: " + str(manifest_filepath))
                manifest_info["assemblyIdentity"] = asm_e.attrib
            if asm_tag == "file":
                if not "file" in manifest_info:
                    manifest_info["file"] = []
                manifest_info["file"].append(asm_e.attrib)
            if asm_tag == "dependency":
                if "dependency" in manifest_info:
                    print("[WARNING] duplicate dependency element found in the manifest file: " + str(manifest_filepath))
                dependency_info = {}
                for dependency in asm_e:
                    dependency_xmlns, dependency_tag = get_xmlns_and_tag(dependency)
                    if dependency_tag == "dependentAssembly":
                        if not "dependentAssembly" in dependency_info:
                            dependency_info["dependentAssembly"] = []
                        dependency_info["dependentAssembly"].append(get_dependentAssembly_info(dependency))
                manifest_info["dependency"] = dependency_info
        return manifest_info
    return None

# returns info on a dependentAssembly
def get_dependentAssembly_info(da_et):
    daet_xmlns, daet_tag = get_xmlns_and_tag(da_et)
    if daet_tag != "dependentAssembly":
        print("[WARNING] element tree given was not for a dependentAssembly element tag")
    da_info = {}
    for da_e in da_et:
        da_xmlns, da_tag = get_xmlns_and_tag(da_e)
        if da_tag == "assemblyIdentity":
            if "assemblyIdentity" in da_info:
                print("[WARNING] duplicate assemblyIdentity element found in the app config file: " + str(config_filepath))
            da_info["assemblyIdentity"] = da_e.attrib
        if da_tag == "codeBase":
            if "codeBase" in da_info:
                print("[WARNING] duplicate codeBase element found in the app config file: " + str(config_filepath))
            da_info["codeBase"] = da_e.attrib
        if da_tag == "bindingRedirect":
            if "bindingRedirect" in da_info:
                print("[WARNING] duplicate bindingRedirect element found in the app config file: " + str(config_filepath))
            da_info["bindingRedirect"] = da_e.attrib
    return da_info

# returns a map for the given assembly binding element tree based on content within the elemnt tree for an "assemblyBinding" tag
# the "assemblyBinding" tag can appear within either a <runtime> or <windows> element, or under the root <configuration> element
# <runtime>: could contain appliesTo attribute, probing, dependentAssembly, and qualifyAssembly elements
# <windows>: could contain probing, assemblyIdentity, and dependentAssembly elements
def get_assemblyBinding_info(ab_et):
    xmlns, tag = get_xmlns_and_tag(ab_et)
    if tag != "assemblyBinding":
        print("[WARNING] element tree given was not for an assemblyBinding tag")

    ab_info = {}

    # Specifies runtime version .NET assembly redirection applies to
    # uses .NET Framework version number; if not given, assemblyBinding
    # element applies to all versions of .NET Framework
    # ab_e.attrib["appliesTo"]
    if "appliesTo" in ab_et.attrib:
        ab_info["appliesTo"] = ab_et.attrib["appliesTo"]
    for ab_e in ab_et:
        ab_xmlns, ab_tag = get_xmlns_and_tag(ab_e)
        # <probing>
        # specifies subdirs of application's base dir to search for assemblies
        # privatePath: "bin;bin2\subbin;bin3"
        if ab_tag == "probing":
            if "probing" in ab_info:
                print("[WARNING] duplicate probing element found in the app config file: " + str(config_filepath))
            ab_info["probing"] = ab_e.attrib

        # <dependentAssembly> for .NET
        # binding policy and assembly location for dependent assemblies
        #   <assemblyIdentity>
        #   used to determine if this dependentAssembly config element should apply
        #   - name: name of the assembly
        #   - culture: (optional) specify language and country/region of assembly
        #   - publicKeyToken: (optional) specify assembly strong name
        #   - processorArchitecture: (optional) "x86", "amd64", "msil", or "ia64"
        #   <codeBase>
        #   specifies assembly to use; if not present, usual probing for assemblies
        #   - version: version of assembly the codebase applies to
        #   - href: URL where runtime can find specified version of assembly
        #   <bindingRedirect>
        #   redirect one assembly to another version
        #   - oldVersion: assembly version originally requested
        #   - newVersion: the assembly version to use instead
        if ab_tag == "dependentAssembly":
            if not "dependentAssembly" in ab_info:
                ab_info["dependentAssembly"] = []
            ab_info["dependentAssembly"].append(get_dependentAssembly_info(ab_e))

        # <qualifyAssembly>
        # replaces partial name in Assembly.Load with full name
        # - partialName: "math"
        # - fullName: "math,version=...,publicKeyToken=...,culture=neutral"
        if ab_tag == "qualifyAssembly":
            if "qualifyAssembly" in ab_info:
                print("[WARNING] duplicate qualifyAssembly element found in the app config file: " + str(config_filepath))
            ab_info["qualifyAssembly"] = ab_e.attrib
    return ab_info

# DLL redirection summary: redirection file with name_of_exe.local (contents are ignored) makes a check for mydll.dll happen in the application directory first,
# regardless of what the full path specified for LoadLibrary or LoadLibraryEx is (if no dll found in local directory, uses the typical search order)
def check_windows_dll_redirection_local(filename):
    binary_filepath = pathlib.Path(filename)
    config_filepath = binary_filepath.with_suffix(binary_filepath.suffix + '.local')
    return config_filepath.exists()

# check for an application configuration file and return (potentially) useful information
# https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies#application-configuration-file
# https://learn.microsoft.com/en-us/windows/win32/sbscs/application-configuration-files
def get_windows_application_config_info(filename):
    binary_filepath = pathlib.Path(filename)
    config_filepath = binary_filepath.with_suffix(binary_filepath.suffix + '.config')
    if config_filepath.exists():
        print("Found application configuration file for " + filename)
        et = defusedxml.ElementTree.parse(config_filepath)
        app_config_info = {}

        # requiredRuntime is used for v1.0 of .NET Framework, supportedRuntime is for v1.1+
        supportedRuntime = et.find('./startup/supportedRuntime')
        requiredRuntime = et.find('./startup/requiredRuntime')
        if (supportedRuntime != None) or (requiredRuntime != None):
            startup_info = {}
            if (supportedRuntime != None) and supportedRuntime.attrib:
                startup_info["supportedRuntime"] = supportedRuntime.attrib
            if (requiredRuntime != None) and requiredRuntime.attrib:
                startup_info["requiredRuntime"] = requiredRuntime.attrib
            app_config_info["startup"] = startup_info

        # <linkedConfiguration href="URL of linked XML file" />
        # - seems to appear within an assemblyBinding element right under the root configuration element
        # - only format for href is `file://` either local or UNC
        # - includes assembly config file contents here, similar to #include
        linkedConfiguration = et.find('./assemblyBinding/linkedConfiguration')
        if (linkedConfiguration != None) and linkedConfiguration.attrib:
            app_config_info["assemblyBinding"] = {"linkedConfiguration": linkedConfiguration.attrib}

        # The following appear within a <windows> element:
        # <probing privatePath="bin;..\bin2\subbin;bin3"/>
        # - valid starting on Windows Server 2008 R2 and Windows 7
        # - privatePath: (optional) specifies relative paths of subdirs of the app base dir that might contain assemblies
        # <assemblyBinding>
        # - first element must be an assemblyIdentity describing the assembly; followed by dependentAssembly elements (also below)
        #   <probing privatePath="bin;..\bin2\subbin;bin3"/>
        #   - valid starting on Windows Server 2008 R2 and Windows 7
        #   - privatePath: (optional) specifies relative paths of subdirs of the app base dir that might contain assemblies
        # <dependency> (based on the app config file schema, this
        # - contains one or more dependentAssembly elements (optional)
        #  <dependentAssembly>
        #  - contains assemblyIdentity that unique identifies an app
        #  - app config file redirects binding of application to side-by-side assemblies
        #    <assemblyIdentity processorArchitecture="X86" name="Microsoft.Windows.mysampleApp" type="win32" version="1.0.0.0"/>
        #    - describes side-by-side assembly the application depends on
        #    - type: must be "win32" lowercase
        #    - name: identifies app being affected by app config file or assembly being redirected
        #    - language: (optional) identifies the language by DHTML code or "*" if language neutral/worldwide use
        #    - processorArchitecture: the processor running the application
        #    - version: version of app or assembly
        #    - publicKeyToken: 16-char hex string w/ last 8 bytes of SHA-1 hash of public key the assembly is signed by
        #    <bindingRedirect oldVersion="1.0.0.0" newVersion="1.0.10.0"/>
        #    - oldVersion: assembly version being overriden or redirected
        #    - newVersion: replacement assembly version
        windows_et = et.find('./windows')
        if windows_et != None:
            windows_info = {}
            for win_child in windows_et:
                xmlns, tag = get_xmlns_and_tag(win_child)
                if tag == "probing":
                    if "probing" in windows_info:
                        print("[WARNING] duplicate windows/probing element was found in the app config file: " + str(config_filepath))
                    if "privatePath" in win_child.attrib:
                        windows_info["probing"] = {"privatePath": win_child.attrib['privatePath']}
                    else:
                        print("[WARNING] windows/probing element missing privatePath attribute in app config file: " + str(config_filepath))
                if tag == "assemblyBinding":
                    windows_info["assemblyBinding"] = get_assemblyBinding_info(win_child)
                if tag == "dependency":
                    dependency_info = {}
                    for dependency in win_child:
                        dependency_xmlns, dependency_tag = get_xmlns_and_tag(dependency)
                        if dependency_tag == "dependentAssembly":
                            if not "dependentAssembly" in dependency_info:
                                dependency_info["dependentAssembly"] = []
                            dependency_info["dependentAssembly"].append(get_dependentAssembly_info(dependency))
                    windows_info["dependency"] = dependency_info
            app_config_info["windows"] = windows_info

        # runtime element used for .NET related configuration info that can affect how the runtime locates assemblies to load
        runtime_et = et.find('./runtime')
        if runtime_et != None:
            runtime_info = {}
            for rt_child in runtime_et:
                # Docs say "urn:schemas-microsoft-com:asm.v1" is the namespace for assemblyBinding
                xmlns, tag = get_xmlns_and_tag(rt_child)
                if tag == "developmentMode":
                    # attribute is either 'true' or 'false' (string)
                    # Causes runtime to search directory given in DEVPATH env var for assemblies first (skips signature checks)
                    if "developmentMode" in runtime_info:
                        print("[WARNING] duplicate developmentMode element was found in the app config file: " + str(config_filepath))
                    if "developerInstallation" in rt_child.attrib:
                        runtime_info["developmentMode"] = {"developerInstallation": rt_child.attrib['developerInstallation']}
                    else:
                        print("[WARNING] developmentMode element missing developerInstallation attribute in app config file: " + str(config_filepath))
                if tag == "assemblyBinding":
                    runtime_info["assemblyBinding"] = get_assemblyBinding_info(rt_child)
            app_config_info["runtime"] = runtime_info

        # Info returned includes:
        # - runtime information related to .NET
        # - config options (codeBase, probing) that affect how .NET assemblies are located
        # - config options (probing) that affect how native Windows DLLs are found
        # - assembly identity info (processor targeted, etc)
        # - dependent assembly info (used to determine correct version of an assembly to use)
        return app_config_info
    return None

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
        # as well as intel hex or motorola s-rec files
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

def find_relationship(xUUID, yUUID, relationship):
    return {"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship} in sbom['relationships']

# TODO for an intermediate SBOM format, have ability to search more efficiently by hashes/filepath/filename
# currently, establishing relationships is something around O(n^2) due to searching entire sbom for matches

# return all matching dotnet assemblies
# TODO: an intermediate file format should keep files in different places but matching hashes separate until
# relationships are established; this would make so we can use .NET metadata about versions, strong names, etc
# and not accidentally mix and match cultures/app config info that could differ for different copies of the same
# file (due to app config files pointing to different assemblies despite DLL having same hash)
# culture information to find the right assembly from app config file is likely to vary (though almost always neutral/none)
def find_dotnet_assemblies(probedirs, filename):
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom['software']:
        # Skip if no install path (e.g. installer/temporary file)
        if e['installPath'] == None:
            continue
        for pdir in probedirs:
            # installPath contains full path+filename, so check for all combinations of probedirs+filename
            pfile = pathlib.PureWindowsPath(pdir, filename)
            for ifile in e['installPath']:
                # PureWindowsPath is case-insensitive for file/directory names
                if pfile == pathlib.PureWindowsPath(ifile):
                    # matching probe directory and filename, add software to list
                    possible_matches.append(e)
    return possible_matches

# return a list of all possible matching DLLs that could be loaded on Windows
def find_windows_dlls(probedirs, filename):
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom['software']:
        # Skip if no install path (e.g. installer/temporary file)
        if e['installPath'] == None:
            continue
        for pdir in probedirs:
            # installPath contains full path+filename, so check for all combinations of probedirs+filename
            pfile = pathlib.PureWindowsPath(pdir, filename)
            for ifile in e['installPath']:
                # PureWindowsPath is case-insensitive for file/directory names
                if pfile == pathlib.PureWindowsPath(ifile):
                    # matching probe directory and filename, add software to list
                    possible_matches.append(e)
    return possible_matches

def add_windows_pe_dependencies(sw, peImports):
    # No installPath is probably temporary files/installer
    # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
    if sw['installPath'] == None:
        return

    # https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
    # Desktop Applications (we can only check a subset of these without much more info gathering, disassembly + full filesystem + environment details)
    # 1. Specifying full path, using DLL redirection, or using a manifest
    # - https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
    # - DLL redirection summary: redirection file with name_of_exe.local (contents are ignored) makes a check for mydll.dll happen in the application directory first, regardless of what the full path specified for LoadLibrary or LoadLibraryEx is (if no dll found in local directory, uses the typical search order)
    # - manifest files cause any .local files to be ignored (also, enabling DLL redirection may require setting DevOverrideEnable registry key)
    # 2. If DLL with same module name is loaded in memory, no search will happen. If DLL is in KnownDLLs registry key, it uses the system copy of the DLL instead of searching.
    # 3. If LOAD_LIBRARY_SEARCH flags are set for LoadLibraryEx, it will search dir LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, paths explicitly added by AddDllDirectory (LOAD_LIBRARY_SEARCH_USER_DIRS) or the SetDllDirectory (multiple paths added have unspecified search order), then system directory (LOAD_LIBRARY_SEARCH_SYSTEM32)
    # 4. Look in dir the app was loaded from (or specified by absolute path lpFileName if LoadLibraryEx is called with LOAD_WITH_ALTERED_SEARCH_PATH)
    # 5. If SetDllDirectory function called with lpPathName: the directory specified
    # 6. If SafeDllSearchMode is disabled: the current directory
    # 7. Look in the system directory (GetSystemDirectory to get the path)
    # 8. The 16-bit system directory (no function to get this directory; %windir%\SYSTEM on 32-bit systems, not supported on 64-bit systems)
    # 9. Windows system directory (GetWindowsDirectory to get this path)
    # 10. If SafeDllSearchMode is enabled (default): the current directory
    # 11. Directories listed in PATH environment variable (per-application path in App Paths registry key is not used for searching)

    # In addition, Windows 10 + 11 add a feature called API sets: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
    # these use special dll names that aren't actually a physical file on disk

    # Of those steps, without gathering much more information that is likely not available or manual/dynamic analysis, we can do:
    # 4. Look for DLL in the directory the application was loaded from
    dependent_uuid = sw.get('UUID')
    for fname in peImports:
        probedirs = []
        for ipath in sw['installPath']:
            probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())
        # likely just one found, unless sw entry has the same file installed to multiple places
        for e in find_windows_dlls(probedirs, fname):
            dependency_uuid = e['UUID']
            if not find_relationship(dependent_uuid, dependency_uuid, "Uses"):
                add_relationship(dependent_uuid, dependency_uuid, "Uses")
        # logging DLLs not found would be nice, but is excessively noisy due being almost exclusively system DLLs
        #print(f" Dependency {fname} not found for sbom['software'] entry={sw}")

def parse_relationships(sbom):
    for sw in sbom['software']:
        # Skip for temporary files/installer that don't have any installPath to find dependencies with
        if sw['installPath'] == None:
            continue
        dependent_uuid = sw.get('UUID')
        windowsAppConfig = None
        windowsManifest = None
        # Find metadata for app config or manifest files with info to help establish dependencies on Windows
        for md in sw['metadata']:
            if 'appConfigFile' in md:
                windowsAppConfig = md['appConfigFile']
            if 'manifestFile' in md:
                windowsManifest = md['manifestFile']
        # Find metadata saying what dependencies are used by the software entry
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
                        pass
                        # this mostly just prints system libraries
                        #print(f" Dependency {fname} not found for sbom['software'] entry={sw}")

            # handle PE imports
            if 'peImport' in md:
                # NOTE: UWP apps have their own search order for libraries; they use a .appx or .msix file extension and appear to be zip files, so our SBOM probably doesn't even include them
                add_windows_pe_dependencies(sw, md['peImport'])
            if 'peBoundImport' in md:
                add_windows_pe_dependencies(sw, md['peBoundImport'])
            if 'peDelayImport' in md:
                add_windows_pe_dependencies(sw, md['peDelayImport'])
            if 'dotnetAssemblyRef' in md:
                dnName = None
                dnCulture = None
                dnVersion = None
                if 'dotnetAssembly' in md:
                    dnAssembly = md['dotnetAssembly']
                    if 'Name' in dnAssembly:
                        dnName = dnAssembly['Name']
                    if 'Culture' in dnAssembly:
                        dnCulture = dnAssembly['Culture']
                    if 'Version' in dnAssembly:
                        dnVersion = dnAssembly['Version']
                # get additional probing paths if they exist
                dnProbingPaths = None
                dnDependentAssemblies = None
                if windowsAppConfig:
                    if 'runtime' in windowsAppConfig:
                        wac_runtime = windowsAppConfig['runtime']
                        if 'assemblyBinding' in wac_runtime:
                            wac_asmbinding = wac_runtime['assemblyBinding']
                            if 'dependentAssembly' in wac_asmbinding:
                                dnDependentAssemblies = wac_asmbinding['dependentAssembly']
                            if 'probing' in wac_asmbinding:
                                wac_probing = wac_asmbinding['probing']
                                if 'privatePath' in wac_probing:
                                    wac_paths = wac_probing['privatePath']
                                    for path in wac_paths.split(';'):
                                        if dnProbingPaths == None:
                                            dnProbingPaths = []
                                        dnProbingPaths.append(pathlib.PureWindowsPath(path).as_posix())

                # https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
                # 1. Determine correct assembly version using configuration files (binding redirects, code location, etc)
                # 2. Check if assembly name bound before; if it is use previously loaded assembly
                # 3. Check global assembly cache (%windir%\Microsoft.NET\assembly in .NET framework 4, %windir%\assembly previously)
                # 4. Probe for assembly:
                # - a. Check for <codeBase> element in app config; check the given location and if assembly found great no probing; otherwise fail without probing
                # - b. If there is no <codeBase> element, begin probing using
                #    - application base + culture + assembly name directories
                #    - privatePath directories from a probing element, combined with culture/appbase/assemblyname (done before the standard probing directories)
                #    - the location of the calling assembly may be used as a hint for where to find the referenced assembly
                if 'dotnetAssemblyRef' in md:
                    for asmRef in md['dotnetAssemblyRef']:
                        refName = None
                        refVersion = None
                        refCulture = None
                        if 'Name' in asmRef:
                            refName = asmRef['Name']
                        else:
                            continue # no name means we have no assembly to search for
                        if 'Culture' in asmRef:
                            refCulture = asmRef['Culture']
                        if 'Version' in asmRef:
                            refVersion = asmRef['Version']

                        # check if codeBase element exists for this assembly in appconfig
                        if dnDependentAssemblies != None:
                            for depAsm in dnDependentAssemblies:
                                # dependent assembly object contains info on assembly id and binding redirects that with a better internal SBOM
                                # representation could be used to also verify the right assembly is being found
                                if 'codeBase' in depAsm:
                                    if 'href' in depAsm['codeBase']:
                                        codebase_href = depAsm['codeBase']['href']
                                        # strong named assembly can be anywhere on intranet or Internet
                                        if codebase_href.startswith('http://') or codebase_href.startswith('https://') or codebase_href.startswith('file://'):
                                            # codebase references a url; interesting for manual analysis/gathering additional files, but not supported by surfactant yet
                                            pass
                                        else:
                                            # most likely a private assembly, so path must be relative to application's directory
                                            for install_filepath in sw['installPath']:
                                                install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
                                                cb_filepath = pathlib.PureWindowsPath(install_basepath, codebase_href)
                                                cb_file = cb_filepath.name
                                                cb_path = cb_filepath.parent.as_posix()
                                                for e in find_dotnet_assemblies(cb_path, cb_file):
                                                    dependency_uuid = e['UUID']
                                                    if not find_relationship(dependent_uuid, dependency_uuid, "Uses"):
                                                        add_relationship(dependent_uuid, dependency_uuid, "Uses")

                        # continue on to probing even if codebase element was found, since we can't guarantee the assembly identity required by the codebase element
                        # create list of probing paths
                        probedirs = []
                        # probe for the referenced assemblies
                        for install_filepath in sw['installPath']:
                            install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
                            if refCulture == None or refCulture == '':
                                # [application base] / [assembly name].dll
                                # [application base] / [assembly name] / [assembly name].dll
                                probedirs.append(pathlib.PureWindowsPath(install_basepath).as_posix())
                                probedirs.append(pathlib.PureWindowsPath(install_basepath, refName).as_posix())
                                if dnProbingPaths != None:
                                    # add probing private paths
                                    for path in dnProbingPaths:
                                        # [application base] / [binpath] / [assembly name].dll
                                        # [application base] / [binpath] / [assembly name] / [assembly name].dll
                                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path).as_posix())
                                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refName).as_posix())
                            else:
                                # [application base] / [culture] / [assembly name].dll
                                # [application base] / [culture] / [assembly name] / [assembly name].dll
                                probedirs.append(pathlib.PureWindowsPath(install_basepath, refCulture).as_posix())
                                probedirs.append(pathlib.PureWindowsPath(install_basepath, refName, refCulture).as_posix())
                                if dnProbingPaths != None:
                                    # add probing private paths
                                    for path in dnProbingPaths:
                                        # [application base] / [binpath] / [culture] / [assembly name].dll
                                        # [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
                                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refCulture).as_posix())
                                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path, refName, refCulture).as_posix())
                        for e in find_dotnet_assemblies(probedirs, refName+".dll"):
                            dependency_uuid = e['UUID']
                            if not find_relationship(dependent_uuid, dependency_uuid, "Uses"):
                                add_relationship(dependent_uuid, dependency_uuid, "Uses")
                            # logging assemblies not found would be nice but is a lot of noise as it mostly just prints system/core .NET libraries
                            #print(f" Dependency {refName} not found for sbom['software'] entry={sw}")

def entry_search(sbom, hsh):
    if len(sbom['software']) == 0:
        return False, None
    for index, item in enumerate(sbom['software']):
        if hsh in item['sha256']:
            return True, index
        
    return False, None

# updates fields in an entry, with the assumption that the hashes match (e.g. most extracted values should match)
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
                # key will look something like root['fileName'][0], we only want the first location/key
                location = key.replace("root", "")
                location = location[2:location.index("']")]
                if location not in ['UUID', 'captureTime']:
                    # if new value to replace is an empty string or None - just leave as is
                    if value not in ['', " ", None]:
                        # if value is an array, append the new values; only add if not a duplicate
                        # ex: containerPath (array), fileName, installPath, vendor, provenance, metadata, supplementaryFiles, components
                        if isinstance(sbom['software'][index][location], list):
                            if location in ["containerPath", "fileName", "installPath", "vendor", "provenance", "metadata", "supplementaryFiles", "components"]:
                                if not value in sbom['software'][index][location]:
                                    sbom['software'][index][location].append(value)
                            #for item in sbom['software'][index][location]:
                            #    entries = eval(value)
                            #    # case where value is a list cast as a string (because of the DeepDiff output) that needs to be converted back to a list
                            #    if isinstance(value, str) and type(entries) == list:
                            #        for e in entries:
                            #            if e not in item:
                            #                sbom['software'][index][location].append(e)
                            #    else:
                            #        raise Exception("Trying to compare a string with a list, when two lists are being compared")
                        
                        # if value is a string, update the dictionary
                        # ex: name, comments, version, description, relationshipAssertion, recordedInstitution
                        if location in ["name", "comments", "version", "description", "relationshipAssertion", "recordedInstitution"]:
                            sbom['software'][index].update({location : value})
                
                    # TODO: for intermediate file format, find/figure out way to resolve conflicts between surfactant sboms and those with manual additions
  
            # return UUID of existing entry, UUID of entry being discarded, existing_entry object
            return existing_uuid, entry_uuid, existing_entry
    


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
            archive_found, archive_index = entry_search(sbom, parent_entry['sha256'])
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
                        entries.append(get_software_entry(filepath, root_path=epath, container_uuid=parent_uuid, install_path=install_prefix))
                    elif (file_suffix in hex_file_extensions) and check_hex_type(filepath):
                        entries.append(get_software_entry(filepath, root_path=epath, container_uuid=parent_uuid, install_path=install_prefix))
                #entries = [get_software_entry(os.path.join(cdir, f), root_path=epath, container_uuid=parent_uuid, install_path=install_prefix) for f in files if check_exe_type(os.path.join(cdir, f))]
                if entries:
                    # if a software entry already exists with a matching file hash, augment the info in the existing entry
                    for e in entries:
                        found, index = entry_search(sbom, e['sha256'])
                        if not found:
                            sbom["software"].append(e)
                        else:
                            existing_uuid, entry_uuid, updated_entry = update_entry(sbom, e, index)
                            # use existing uuid and entry uuid to update parts of the software entry (containerPath) that may be out of date
                            if 'containerPath' in updated_entry and updated_entry['containerPath'] != None:
                                for index, value in enumerate(updated_entry['containerPath']):
                                    if value.startswith(entry_uuid):
                                        updated_entry['containerPath'][index] = value.replace(entry_uuid, existing_uuid)
                            # go through relationships and see if any need existing entries existed for the replaced uuid (e.g. merging SBOMs)
                            for index, value in enumerate(sbom['relationships']):
                                if value['xUUID'] == entry_uuid:
                                    sbom['relationships'][index]['xUUID'] = existing_uuid
                                if value['yUUID'] == entry_uuid:
                                    sbom['relationships'][index]['yUUID'] = existing_uuid
                            # TODO a pass later on to remove duplicate relationships will be needed
                    # if the config file specified a parent/container for the files, add it as a "Contains" relationship
                    if parent_entry:
                        for e in entries:
                            xUUID = parent_entry["UUID"]
                            yUUID = e["UUID"]
                            # make sure an existing parent relationship doesn't already exist (due to a duplicate file hash returning an existing entry)
                            if not find_relationship(xUUID, yUUID, "Contains"):
                                add_relationship(xUUID, yUUID, "Contains")
else:
    print("Skipping gathering file metadata and adding software entries")

# add "Uses" relationships based on gathered metadata for software entries
if not args.skip_relationships:
    parse_relationships(sbom)
else:
    print("Skipping relationships based on imports metadata")

# TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
json.dump(sbom, args.sbom_outfile, indent=4)




