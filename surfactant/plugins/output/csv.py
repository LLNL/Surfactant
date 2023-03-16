import csv
import os
from collections.abc import Iterable
from typing import List

from surfactant import pluginsystem
from surfactant.sbomtypes import SBOM, Software


class CSV(pluginsystem.OutputPlugin):
    PLUGIN_NAME = "CSV"
    default_fields = [
        "Path",
        "SHA1",
        "Supplier",
        "Product",
        "Version",
        "Description",
        "Copyright",
    ]

    @classmethod
    def write(cls, sbom: SBOM, outfile):
        # plugin args could be handled here to change behavior
        fields = cls.default_fields

        # match output format with pandas.DataFrame.to_csv
        # equivalent to `excel` dialect, other than lineterminator
        writer = csv.DictWriter(outfile, fieldnames=fields, lineterminator=os.linesep)
        writer.writeheader()
        if sbom.software:
            for sw in sbom.software:
                cls.write_software_entry(writer, sw, fields)

    @classmethod
    def write_software_entry(cls, writer: csv.DictWriter, software: Software, fields: List[str]):
        pathkey = None
        if "Path" in fields:
            if software.installPath and isinstance(software.installPath, Iterable):
                # default to using "installPath"
                pathkey = "installPath"
            elif software.containerPath and isinstance(software.containerPath, Iterable):
                # use "containerPath" if it has entries but "installPath" does not
                pathkey = "containerPath"

        # an entry will be created for every entry with a valid path
        for p in getattr(software, pathkey):
            row = {}
            row["Path"] = p
            # if containerPath is being used, remove the UUID portion at the start
            if pathkey == "containerPath":
                row["Path"] = "".join(row["Path"].split("/")[1:])
            for f in fields:
                # Path already added to row info
                if f == "Path":
                    continue
                # normalize some special field names to actual SBOM field names
                fld_norm = f
                if f in ("SHA1", "SHA256", "MD5", "Version", "Description"):
                    fld_norm = str.lower(f)
                elif f == "Product":
                    fld_norm = "name"
                elif f == "Supplier":
                    fld_norm = "vendor"
                row[f] = cls.get_software_field(software, fld_norm)
            print(row)
            writer.writerow(row)

    @classmethod
    def get_software_field(cls, software, field):
        if hasattr(software, field):
            return getattr(software, field)
        # Copyright field currently only gets populated from Windows PE file metadata
        if field == "Copyright":
            if software.metadata and isinstance(software.metadata, Iterable):
                retval = []
                for entry in software.metadata:
                    if "FileInfo" in entry and "LegalCopyright" in entry["FileInfo"]:
                        return entry["FileInfo"]["LegalCopyright"]
        return None
