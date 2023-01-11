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
        return {}, {}

    file_hdr_details = {}
    file_hdr_details["elfDependencies"] = []
    file_hdr_details["elfRpath"] = []
    file_hdr_details["elfRunpath"] = []
    file_hdr_details["elfSoname"] = []
    file_hdr_details["elfHumanArch"] = ""
    file_hdr_details["elfArchNumber"] = -1
    file_hdr_details["elfArchitecture"] = ""
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
    file_hdr_details["elfHumanArch"] = elf.get_machine_arch()
    f.seek(18)
    isa_data = f.read(2)
    if elf.little_endian:
        file_hdr_details["elfArchNumber"] = struct.unpack("<H", isa_data)[0]
    else:
        file_hdr_details["elfArchNumber"] = struct.unpack(">H", isa_data)[0]
    file_hdr_details["elfArchitecture"] = elf["e_machine"]


    return file_hdr_details, file_details


