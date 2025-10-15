# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from typing import List, Optional, Tuple

import math

@dataclass
class WriteInfo:
    start_address: int
    data: bytearray

def read_srecord_info(file: str) -> Optional[List[WriteInfo]]:
    ret_info: List[WriteInfo] = []
    with open(file) as f:
        for line in f:
            line = line.strip()
            if len(line) == 0:
                continue
            if line[0] != 'S':
                return None
            srec_type = line[1]
            byte_count = int(line[2:4], base=16)
            bytes_sum = byte_count
            if srec_type == '1':
                addr = (int(line[4:6], base=16) << 8) | (int(line[6:8], base=16))
                next_byte = 8
                bytes_sum += int(line[4:6], base=16) + int(line[6:8], base=16)
                # Byte count is address + data + checksum, so exclude the data and address bytes
                bytes_to_read = byte_count - 2 - 1
            elif srec_type == '2':
                addr = (int(line[4:6], base=16) << 16) | (int(line[6:8], base=16) << 8) | (int(line[8:10], base=16))
                next_byte = 10
                bytes_sum += int(line[4:6], base=16) + int(line[6:8], base=16) + int(line[8:10], base=16)
                bytes_to_read = byte_count - 3 - 1
            elif srec_type == '3':
                addr = (int(line[4:6], base=16) << 24) | (int(line[6:8], base=16) << 16) | (int(line[8:10], base=16) << 8) | (int(line[10:12], base=16))
                next_byte = 12
                bytes_sum += int(line[4:6], base=16) + int(line[6:8], base=16) + int(line[8:10], base=16) + int(line[10:12], base=16)
                bytes_to_read = byte_count - 4 - 1
            else:
                continue
            temp_bytes: List[int] = []
            i = 0
            for byte_no in range(bytes_to_read):
                i += 1
                start_byte = next_byte + byte_no * 2
                temp_bytes.append(int(line[start_byte:start_byte + 2], base=16))
                bytes_sum += temp_bytes[-1]
            # verify checksum
            expected_checksum = int(line[-2:], base=16)
            checksum = 0xFF - (bytes_sum & 0xFF)
            if expected_checksum != checksum:
                return None
            ret_info.append(WriteInfo(addr, bytearray(temp_bytes)))
    return ret_info

def read_hex_info(file: str) -> Optional[List[WriteInfo]]:
    ret_info: List[WriteInfo] = []
    with open(file) as f:
        addr_top_bytes = 0
        for line in f:
            line = line.strip()
            if len(line) == 0:
                continue
            if line[0] != ':':
                return None
            byte_count = int(line[1:3], base=16)
            bytes_sum = byte_count
            addr = (int(line[3:5], base=16) << 8) | (int(line[5:7], base=16))
            bytes_sum += int(line[3:5], base=16) + int(line[5:7], base=16)
            data_type = int(line[7:9], base=16)
            bytes_sum += data_type
            data_bytes: List[int] = []
            for byte_no in range(byte_count):
                start_byte = 9 + byte_no * 2
                data_bytes.append(int(line[start_byte:start_byte + 2], base=16))
                bytes_sum += data_bytes[-1]
            if data_type == 0:
                addr = addr_top_bytes + addr
                ret_info.append(WriteInfo(addr, bytearray(data_bytes)))
            elif data_type == 2:
                addr_top_bytes = ((data_bytes[0] << 8) | data_bytes[1]) * 16
            elif data_type == 4:
                addr_top_bytes = ((data_bytes[0] << 8) | data_bytes[1]) << 16
            expected_checksum = int(line[-2:], base=16)
            # Do a second 0xFF in the case of the +1 going to 0x0100
            check_sum = ((~bytes_sum & 0xFF) + 1) & 0xFF
            if expected_checksum != check_sum:
                return None
    return ret_info

def get_first_and_last_address(data: List[WriteInfo]) -> Tuple[int, int]:
    # Arbitrarly large number so smaller addresses will always compare true
    first_address = 2 << 65
    last_address = 0
    for entry in data:
        if entry.start_address < first_address:
            first_address = entry.start_address
        entry_end = entry.start_address + len(entry.data)
        if entry_end > last_address:
            last_address = entry_end
    return first_address, last_address

# write_to is a file-like object
# returns true if the file was successfully written
def write_write_info_to_file(write_to, data: List[WriteInfo], *, trim_leading_zeros: bool) -> bool:
    first_address, _ = get_first_and_last_address(data)
    if not trim_leading_zeros and first_address > 0:
        write_to.write(b'0' * first_address)
    data = sorted(data, key=lambda x: x.start_address)
    write_address = 0
    for entry in data:
        if write_address > entry.start_address:
            # Error: Overlapping data, skip writting the file?
            return False
        elif write_address < entry.start_address:
            write_to.write(b'0' * (entry.start_address - write_address))
            write_address = entry.start_address
        write_to.write(entry.data)
        write_address += len(entry.data)
    return True
