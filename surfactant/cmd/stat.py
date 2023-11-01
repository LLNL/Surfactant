import click

from surfactant.sbomtypes import SBOM


@click.command("stat")
@click.argument("input_sbom", type=click.File("r"), required=True)
def stat(input_sbom):
    click.echo("Running stat command")
    data = SBOM.from_json(input_sbom.read())
    elfIsLib = 0
    elfIsExe = 0
    peIsExe = 0
    peIsdll = 0
    clrExe = 0
    clrDll = 0
    for sw in data.software:
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
                if md["peisClr"]:
                    if md["peIsExe"]:
                        clrExe += 1
                    else:
                        clrDll += 1
    num_pe_exe_str = "Number of PE Executables: {} with {} using .NET/CLR".format(
        str(peIsExe), str(clrExe)
    )
    num_dll_str = "Number of DLLs: {} with {} using .NET/CLR".format(str(peIsdll), str(clrDll))
    num_elf_bin_str = "Number of ELF Binaries: {}".format(str(elfIsExe))
    num_elf_shared_lib_str = "Number of ELF shared libraries: {}".format(str(elfIsLib))
    print(num_pe_exe_str)
    print(num_dll_str)
    print(num_elf_bin_str)
    print(num_elf_shared_lib_str)
