# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from queue import Queue
from typing import Any, Dict, Optional

from extractcode import archive as ec_archive
from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.infoextractors.file_decompression import create_extraction
from surfactant.sbomtypes import SBOM, Software

ADDITIONAL_HANDLERS = {
    "Linux Kernel Image",
    "MSCAB",
    "ISCAB",
    "DOCKER_GZIP",
    "GZIP",
    "BZIP2",
    "XZ",
    "DOCKER_TAR",
    "TAR",
    "RAR",
    "ZIP",
    "JAR",
    "WAR",
    "EAR",
    "APK",
    "IPA",
    "MSIX",
    "ZLIB",
    "CPIO_BIN big",
    "CPIO_BIN little",
    "ZSTANDARD",
    "ZSTANDARD_DICTIONARY",
    "ISO_9660_CD",
    "MACOS_DMG",
    "RPM Package",
}


def get_handler(filename, filetype: str) -> Optional[ec_archive.Handler]:
    if not filetype:
        return None
    if filetype.startswith("EXTRACTCODE-"):
        name = filetype[len("EXTRACTCODE-") :]
        for handler in ec_archive.archive_handlers:
            if handler.name == name:
                return handler
        logger.error(f"Unknown EXTRACTCODE handler: {name}")
    handler = ec_archive.get_best_handler(filename)
    return handler


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: str,
    context_queue: "Queue[ContextEntry]",
    current_context: Optional[ContextEntry],
) -> Optional[Dict[str, Any]]:
    # Check if the file is compressed and get its format
    handler = get_handler(filename, filetype)

    if handler:
        create_extraction(
            filename,
            context_queue,
            current_context,
            lambda f, t: decompress_to(f, t, handler),
        )


def decompress_to(filename: str, output_folder: str, handler: ec_archive.Handler) -> bool:
    extractors = handler.extractors
    extractor = None
    if len(extractors) == 1:
        extractor = extractors[0]
    elif len(extractors) == 2:
        extractor = lambda f, t: ec_archive.extract_twice(f, t, extractors[0], extractors[1])
    else:
        logger.error(f"Unsupported number of extractors for {filename}: {len(extractors)}")
        return False

    logger.info(f"Extracting {filename} ({handler.name}) to {output_folder} using extractcode")
    warnings = extractor(filename, output_folder)
    if warnings:
        for warning in warnings:
            logger.warning(f"Warning while extracting {filename}: {warning}")

    return True
