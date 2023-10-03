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
    sw = data.software
    for i in range(len(sw)):
        md = sw[i].metadata
        for n in range(len(md)):
            if "elfIsLib" in md[n]:
                if md[n]["elfIsLib"]:
                    elfIsLib += 1
            if "elfIsExe" in md[n]:
                if md[n]["elfIsExe"]:
                    elfIsExe += 1
            if "peIsExe" in md[n]:
                if md[n]["peIsExe"]:
                    peIsExe += 1
            if "peIsDll" in md[n]:
                if md[n]["peIsDll"]:
                    peIsdll += 1
            if "peIsClr" in md[n]:
                if md[n]["peisClr"]:
                    if md[n]["peIsExe"]:
                        clrExe += 1
                    else:
                        clrDll += 1 
    num_pe_exe_str = (
        "Number of PE Executables: " + str(peIsExe) + " with " + str(clrExe) + " using .NET/CLR"
    )
    num_dll_str = "Number of DLLs: " + str(peIsdll) + " with " + str(clrDll) + " using .NET/CLR"
    num_elf_bin_str = "Number of ELF Binaries: " + str(elfIsExe)
    num_elf_shared_lib_str = "Number of ELF shared libraries: " + str(elfIsLib)
    print(num_pe_exe_str)
    print(num_dll_str)
    print(num_elf_bin_str)
    print(num_elf_shared_lib_str)
    return
