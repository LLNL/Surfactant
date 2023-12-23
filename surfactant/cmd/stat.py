import click

from surfactant.sbomtypes import SBOM


@click.command("stat")
@click.argument("input_sbom", type=click.File("r"), required=True)
def stat(input_sbom):
    data = SBOM.from_json(input_sbom.read())
    elfIsLib = 0
    elfIsExe = 0
    peIsExe = 0
    peIsdll = 0
    clrExe = 0
    clrDll = 0
    for sw in data.software:
        if not sw.metadata:
            continue
        for md in sw.metadata:
            if "elfIsLib" in md:
                if md["elfIsLib"]:
                    elfIsLib += 1
            if "elfIsExe" in md:
                if md["elfIsExe"]:
                    elfIsExe += 1
            if "peIsExe" in md:
                if md["peIsExe"]:
                    peIsExe += 1
            if "peIsDll" in md:
                if md["peIsDll"]:
                    peIsdll += 1
            if "peIsClr" in md:
                if md["peIsClr"]:
                    if md["peIsExe"]:
                        clrExe += 1
                    else:
                        clrDll += 1
    num_pe_exe_str = f"Number of PE Executables: {peIsExe} with {clrExe} using .NET/CLR"
    num_dll_str = f"Number of DLLs: {peIsdll} with {clrDll} using .NET/CLR"
    num_elf_bin_str = f"Number of ELF Binaries: {elfIsExe}"
    num_elf_shared_lib_str = f"Number of ELF shared libraries: {elfIsLib}"
    print(num_pe_exe_str)
    print(num_dll_str)
    print(num_elf_bin_str)
    print(num_elf_shared_lib_str)
