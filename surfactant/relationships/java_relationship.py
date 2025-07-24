import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software


def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes Java class information.
    """
    return "javaClasses" in metadata


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: Establish 'Uses' relationships for Java class-level imports.

    This plugin supports a three-phase resolution strategy:
      1. Primary: Resolve via exact path match using fs_tree (sbom.get_software_by_path).
      2. Secondary: Resolve via legacy installPath + fileName match.
      3. Tertiary: Heuristic fallback using fileName + same directory.

    Args:
        sbom (SBOM): The SBOM object containing all software entries and path graphs.
        software (Software): The software entry declaring Java class dependencies.
        metadata (dict): Metadata containing 'javaClasses' with import/export info.

    Returns:
        Optional[List[Relationship]]: List of `Uses` relationships, or None if not applicable.
    """
    if not has_required_fields(metadata):
        logger.debug(f"[Java] Skipping: No javaClasses metadata for {software.UUID}")
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    java_classes = metadata["javaClasses"]

    # Collect all imported class names
    imports = set()
    for class_info in java_classes.values():
        for imp in class_info.get("javaImports", []):
            imports.add(imp)

    logger.debug(f"[Java] {software.UUID} importing {len(imports)} classes")

    for import_class in imports:
        class_path = class_to_path(import_class)
        fname = class_path.rsplit("/", maxsplit=1)[-1]

        matched_uuids = set()
        used_method = {}

        logger.debug(f"[Java] Resolving class import: {import_class} → {class_path}")

        # ----------------------
        # Phase 1: fs_tree lookup
        # ----------------------
        for ipath in software.installPath or []:
            base_dir = pathlib.PurePath(ipath).parent.as_posix()
            full_path = f"{base_dir}/{class_path}"
            match = sbom.get_software_by_path(full_path)
            logger.debug(f"[Java][fs_tree] lookup {full_path} → {'found' if match else 'not found'}")
            if match:
                matched_uuids.add(match.UUID)
                used_method[match.UUID] = "fs_tree"

        # -----------------------------------------
        # Phase 2: Legacy installPath + fileName
        # -----------------------------------------
        if not matched_uuids:
            for sw in sbom.software:
                if sw.UUID == dependent_uuid:
                    continue
                if isinstance(sw.fileName, Iterable) and fname in sw.fileName:
                    if isinstance(sw.installPath, Iterable):
                        for ip in sw.installPath:
                            if ip.endswith(class_path):
                                logger.debug(f"[Java][legacy] Matched class {fname} at {ip}")
                                matched_uuids.add(sw.UUID)
                                used_method[sw.UUID] = "legacy_installPath"

        # ---------------------------------------------------
        # Phase 3: Heuristic fallback (same dir + file name)
        # ---------------------------------------------------
        if not matched_uuids:
            for sw in sbom.software:
                if sw.UUID == dependent_uuid:
                    continue
                if isinstance(sw.fileName, Iterable) and fname in sw.fileName:
                    if isinstance(sw.installPath, Iterable):
                        for ip in sw.installPath:
                            ip_dir = pathlib.PurePath(ip).parent.as_posix()
                            for ipath in software.installPath or []:
                                search_dir = pathlib.PurePath(ipath).parent.as_posix()
                                if ip_dir == search_dir:
                                    logger.debug(
                                        f"[Java][heuristic] Matched {fname} in shared dir: {ip_dir}"
                                    )
                                    matched_uuids.add(sw.UUID)
                                    used_method[sw.UUID] = "symlink_heuristic"

        # -----------------------------
        # Emit 'Uses' relationships
        # -----------------------------
        for uuid in matched_uuids:
            rel = Relationship(dependent_uuid, uuid, "Uses")
            if rel not in relationships:
                logger.debug(
                    f"[Java] Added relationship: {dependent_uuid} → {uuid} [via {used_method[uuid]}]"
                )
                relationships.append(rel)

        if not matched_uuids:
            logger.debug(f"[Java] No match found for: {import_class}")

    return relationships


def class_to_path(class_name: str) -> str:
    """
    Convert a fully qualified Java class name to a relative path.

    Example:
        "com.example.MyClass" → "com/example/MyClass.class"
    """
    return f"{class_name.replace('.', '/')}.class"
