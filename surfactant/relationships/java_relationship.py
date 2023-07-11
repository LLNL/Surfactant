from typing import List, Optional

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software


def has_required_fields(metadata) -> bool:
    return "javaClasses" in metadata


class _ExportDict:
    created = False
    supplied_by = {}

    @classmethod
    def create_export_dict(cls, sbom: SBOM):
        if cls.created:
            return
        for software_entry in sbom.software:
            for metadata in software_entry.metadata:
                if "javaClasses" in metadata:
                    for class_info in metadata["javaClasses"].values():
                        for export in class_info["javaExports"]:
                            cls.supplied_by[export] = software_entry.UUID
        cls.created = True

    @classmethod
    def get_supplier(cls, import_name: str) -> Optional[str]:
        if import_name in cls.supplied_by:
            return cls.supplied_by[import_name]
        return None


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    if not has_required_fields(metadata):
        return None
    _ExportDict.create_export_dict(sbom)
    relationships = []
    dependant_uuid = software.UUID
    for class_info in metadata["javaClasses"].values():
        for import_ in class_info["javaImports"]:
            if supplier_uuid := _ExportDict.get_supplier(import_):
                if supplier_uuid != dependant_uuid:
                    rel = Relationship(dependant_uuid, supplier_uuid, "Uses")
                    if rel not in relationships:
                        relationships.append(rel)
    return relationships
