from typing import Union

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: str) -> bool:
    return filetype in ("A.OUT little", "A.OUT big")


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
    if not supports_file(filetype):
        return None
    return extract_a_out_info(filetype, filename)


_A_OUT_TARGET_NAME = {
    0x00: "Unknown",
    0x01: "M68010",
    0x02: "M68020",
    0x03: "SPARC",
    0x04: "R3000",
    0x40: "NS32032",
    0x45: "NS32532",
    0x64: "386",
    0x65: "AMD 29K",
    0x66: "386 DYNIX",
    0x67: "ARM",
    0x83: "Sparclet",
    0x86: "386 NetBSD",
    0x87: "M68K NetBSD",
    0x88: "M68K 4K pages NetBSD",
    0x89: "ns532k NetBSD",
    0x8A: "SPARC NetBSD",
    0x8B: "PMAX NetBSD",
    0x8C: "VAX NetBSD",
    0x8D: "Aplha NetBSD",
    0x8E: "MIPS",
    0x8F: "ARM6 NetBSD",
    0x91: "SH3",
    0x94: "PowerPC 64",
    0x95: "PowerPC NetBSD",
    0x96: "VAX 4K pages NetBSD",
    0x97: "MIPS R2000/R3000",
    0x98: "MIPS R4000/R6000",
    0x99: "m88k OpenBSD",
    0x9A: "HPPA OpenBSD",
    0x9B: "SuperH 64-bit",
    0x9C: "SPARC64 NetBSD",
    0x9D: "AMD64 NetBSD",
    0x9E: "SuperH 32-bit",
    0x9F: "Itanium",
    0xB7: "ARM AARCH64",
    0xB8: "OpenRISC 1000",
    0xB9: "RISC-V",
    0xFF: "Axis ETRAC CRIS",
}


def extract_a_out_info(filetype: str, filename: str) -> object:
    try:
        with open(filename, "rb") as f:
            magic_bytes = f.read(4)
            target = get_target_type(filetype, magic_bytes)
            if target is None:
                return None
            return {"aoutMachineType": target}
    except FileNotFoundError:
        return None


def get_target_type(filetype: str, magic_bytes: bytes) -> Union[str, None]:
    if filetype == "A.OUT big":
        big_endian_magic = (
            int.from_bytes(magic_bytes[:4], byteorder="big", signed=False) >> 16
        ) & 0xFF
        if big_endian_magic in _A_OUT_TARGET_NAME:
            return _A_OUT_TARGET_NAME[big_endian_magic]
    if filetype == "A.OUT little":
        little_endian_magic = (
            int.from_bytes(magic_bytes[:4], byteorder="little", signed=False) >> 16
        ) & 0xFF
        if little_endian_magic in _A_OUT_TARGET_NAME:
            return _A_OUT_TARGET_NAME[little_endian_magic]
    return None
