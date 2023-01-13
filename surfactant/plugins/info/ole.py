import olefile
import surfactant.pluginsystem as pluginsystem


class OLE(pluginsystem.InfoPlugin):
    PLUGIN_NAME = "OLE"
    
    @classmethod
    def supports_type(cls, filetype):
        return filetype == "OLE"

    @classmethod
    def extract_info(cls, filename):
        return extract_ole_info(filename)


def extract_ole_info(filename):
    file_details = {}

    ole = olefile.OleFileIO(filename)
    md = ole.get_metadata()
    file_details["ole"] = {}

    # to check if an OLE is an MSI file, check the root storage object CLSID
    # {000c1084-0000-0000-c000-000000000046}	MSI
    # {000c1086-0000-0000-c000-000000000046}    Windows Installer Patch MSP
    # extensions are typically .msi and .msp for files with these two clsid's
    # less common would be a .msm (merge) with the same clsid as MSI
    # as well as .mst (transform) with a clsid of 000c1082
    if ole.root and hasattr(ole.root, 'clsid'):
        file_details["ole"]["clsid"] = str(ole.root.clsid).lower()
        if file_details["ole"]["clsid"] == "000c1082-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MST"
        if file_details["ole"]["clsid"] == "000c1084-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MSI" # or msm, depending on file extension
        if file_details["ole"]["clsid"] == "000c1086-0000-0000-c000-000000000046":
            file_details["ole"]["clsid_type"] = "MSP"

    for prop in md.SUMMARY_ATTRIBS:
        if value := getattr(md, prop, None):
            if type(value) is bytes:
                file_details["ole"][prop] = value.decode("unicode_escape")
            else:
                file_details["ole"][prop] = str(value)
    ole.close()
    return file_details