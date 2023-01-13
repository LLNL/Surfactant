from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import struct
import surfactant.pluginsystem as pluginsystem


class ELF(pluginsystem.InfoPlugin):
    PLUGIN_NAME = "ELF"

    @classmethod
    def supports_type(cls, filetype):
        return filetype == "ELF"

    @classmethod
    def extract_info(cls, filename):
        return extract_elf_info(filename)


def extract_elf_info(filename):
    try:
        f = open(filename, 'rb')
        elf = ELFFile(f)
    except:
        return {}

    file_details = {"OS": "Linux"}
    file_details["elfDependencies"] = []
    file_details["elfRpath"] = []
    file_details["elfRunpath"] = []
    file_details["elfSoname"] = []
    file_details["elfHumanArch"] = ""
    file_details["elfArchNumber"] = -1
    file_details["elfArchitecture"] = ""
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                # Shared libraries
                file_details["elfDependencies"].append(tag.needed)
            elif tag.entry.d_tag == 'DT_RPATH':
                # Library rpath
                file_details["elfRpath"].append(tag.rpath)
            elif tag.entry.d_tag == 'DT_RUNPATH':
                # Library runpath
                file_details["elfRunpath"].append(tag.runpath)
            elif tag.entry.d_tag == 'DT_SONAME':
                # Library soname (for linking)
                file_details["elfSoname"].append(tag.soname)

    if import_dir := getattr(elf, "e_ident", None):
        file_details["e_ident"] = []
        for entry in import_dir:
            file_details["e_ident"].append({entry : import_dir[entry]})

    if elf["e_type"] == 'ET_EXEC':
        file_details["elfIsExe"] = True
    else:
        file_details["elfIsExe"] = False

    if elf["e_type"] == 'ET_DYN':
        file_details["elfIsLib"] = True
    else:
        file_details['elfIsLib'] = False

    if elf["e_type"] == 'ET_REL':
        file_details['elfIsRel'] = True
    else:
        file_details['elfIsRel'] = False
    file_details["elfHumanArch"] = elf.get_machine_arch()
    f.seek(18)
    isa_data = f.read(2)
    if elf.little_endian:
        file_details["elfArchNumber"] = struct.unpack("<H", isa_data)[0]
    else:
        file_details["elfArchNumber"] = struct.unpack(">H", isa_data)[0]
    file_details["elfArchitecture"] = elf["e_machine"]
    
    return file_details