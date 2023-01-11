import string
from enum import Enum, auto


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
                # to check if an OLE is an MSI file, check the root storage object CLSID
                # {000c1084-0000-0000-c000-000000000046}	MSI
                # {000c1086-0000-0000-c000-000000000046}       Windows Installer Patch MSP
                # for olefile python library: ole.root.clsid (clsid without {} wrapper)"
                # extensions are typically .msi and .msp for files with these two clsid's
                # less common would be a .msm (merge) with the same clsid as MSI
                # as well as .mst (transform) with a clsid of 000c1082
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


