import pathlib
from enum import Enum, auto
from typing import Optional

import surfactant.plugin


class ExeType(Enum):
    ELF = auto()
    PE = auto()
    OLE = auto()
    JAVA_MACHOFAT = auto()
    MACHO32 = auto()
    MACHO64 = auto()


@surfactant.plugin.hookimpl(tryfirst=True)
def identify_file_type(filepath: str) -> Optional[str]:
    # pylint: disable=too-many-return-statements
    try:
        with open(filepath, "rb") as f:
            magic_bytes = f.read(265)
            if magic_bytes[:4] == b"\x7fELF":
                return "ELF"
            if magic_bytes[:2] == b"MZ":
                return "PE"
            if magic_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                # MSI (install), MSP (patch), MST (transform), and MSM (merge) files are all types of OLE files
                # the root storage object CLSID is used to identify what it is (+ file extension)
                return "OLE"
            if magic_bytes[:4] == b"MSCF":
                return "CAB"
            # For gzipped data, also filter by extension to avoid huge number of entries with limited info
            if magic_bytes[:2] == b"\x1f\x8b" and "".join(
                pathlib.Path(filepath).suffixes
            ).lower() in [
                ".tar.gz",
                ".cab.gz",
            ]:
                return "GZIP"
            if magic_bytes[257:265] == b"ustar\x0000" or magic_bytes[257:265] == b"ustar  \x00":
                return "TAR"
            # if magic_bytes[:4] == b"\xca\xfe\xba\xbe":
            #    # magic bytes can either be for Java class file or Mach-O Fat Binary
            #    return 'JAVA_MACHOFAT'
            # if magic_bytes[:4] == b"\xfe\xed\xfa\xce":
            #    return 'MACHO32'
            # if magic_bytes[:4] == b"\xfe\xed\xfa\xcf":
            #    return 'MACHO64'
            # if magic_bytes[:4] == b"\xde\xc0\x17\x0b":
            #    return 'LLVM_BITCODE'
            return None
    except FileNotFoundError:
        return None
