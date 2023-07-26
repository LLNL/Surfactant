# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib

from surfactant.filetypeid.id_magic import identify_file_type

# Files are relative to tests/data/
_file_to_file_type = {
    "a_out_files/big_m68020.aout": "A.OUT big",
    "a_out_files/big_netbsd_i386.aout": "A.OUT big",
    "a_out_files/big_netbsd_sparc.aout": "A.OUT big",
    "a_out_files/little_386.aout": "A.OUT little",
    "a_out_files/little_unknown.aout": "A.OUT little",
    "coff_files/intel_80386_coff": "COFF",
    "ELF_shared_obj_test_no1/bin/hello_world": "ELF",
    "ELF_shared_obj_test_no1/lib/libtestlib.so": "ELF",
    "java_class_no1/HelloWorld.class": "JAVACLASS",
    "mach_o_dylib_test_no1/bin/hello_world": "MACHO64",
    "mach_o_dylib_test_no1/lib/libtestlib.dylib": "MACHO64",
    "msitest_no1/test.msi": "OLE",
    "NET_app_config_test_no1/ConsoleApp2.exe": "PE",
    "NET_app_config_test_no1/bin/Debug/net6.0/hello.dll": "PE",
    "Windows_dll_test_no1/hello_world.exe": "PE",
    "Windows_dll_test_no1/testlib.dll": "PE",
}


def test_magic_id():
    base_path = pathlib.Path(__file__).parent.absolute()
    data_dir = os.path.join(base_path, "..", "data")
    for file_name, file_type in _file_to_file_type.items():
        assert identify_file_type(os.path.join(data_dir, file_name)) == file_type
