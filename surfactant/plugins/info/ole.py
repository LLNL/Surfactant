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
    file_hdr_details = {}
    file_details = {}

    ole = olefile.OleFileIO(filename)
    md = ole.get_metadata()
    file_hdr_details["ole"] = {}
    for prop in md.SUMMARY_ATTRIBS:
        if value := getattr(md, prop, None):
            if type(value) is bytes:
                file_hdr_details["ole"][prop] = value.decode("unicode_escape")
            else:
                file_hdr_details["ole"][prop] = str(value)
    ole.close()
    return file_hdr_details, file_details


