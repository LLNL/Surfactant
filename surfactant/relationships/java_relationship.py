from typing import Optional, List

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

def has_required_fields(metadata) -> bool:
    return "javaClasses" in metadata


class _ExportDict:
    created = False
    supplied_by = {}


def _create_export_dict(sbom: SBOM):
    if _ExportDict.created:
        return
    for software_entry in sbom.software:
        for metadata in software_entry.metadata:
            if "javaClasses" in metadata:
                for class_info in metadata["javaClasses"].values():
                    for export in class_info["javaExports"]:
                        _ExportDict.supplied_by[export] = software_entry.UUID
    _ExportDict.created = True


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    if not has_required_fields(metadata):
        return None
    _create_export_dict(sbom)
    relationships = []
    dependant_uuid = software.UUID
    for class_info in metadata["javaClasses"].values():
        for import_ in class_info["javaImports"]:
            if import_ in _ExportDict.supplied_by:
                supplier_uuid = _ExportDict.supplied_by[import_]
                if supplier_uuid != dependant_uuid:
                    rel = Relationship(dependant_uuid, supplier_uuid, "Uses")
                    if rel not in relationships:
                        relationships.append(rel)
    return relationships
