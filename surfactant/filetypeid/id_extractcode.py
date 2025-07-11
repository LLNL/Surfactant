# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Optional

from loguru import logger

import surfactant.plugin

try:
    from extractcode import archive as ec_archive
    from extractcode import sevenzip

    EXTRACTCODE_AVAILABLE = True
# pylint: disable-next=broad-exception-caught
except Exception as e:
    # Catch NoMagicLibError and other library-specific errors during import
    if (
        type(e).__name__ != "NoMagicLibError"
        and not isinstance(e, ImportError)
        and not isinstance(e, AttributeError)
    ):
        raise e
    logger.warning(f"extractcode library not available in file type identification: {e}")
    EXTRACTCODE_AVAILABLE = False
    ec_archive = None
    sevenzip = None


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str) -> Optional[str]:
    if not EXTRACTCODE_AVAILABLE or ec_archive is None:
        return None

    try:
        ec_handler = ec_archive.get_best_handler(filepath)
        if ec_handler:
            return f"EXTRACTCODE-{ec_handler.name}"
        return None
    except FileNotFoundError:
        return None


@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    if EXTRACTCODE_AVAILABLE:
        WimHandler = ec_archive.Handler(
            name="Microsoft wim",
            filetypes=("Windows imaging (WIM) image"),
            mimetypes=("application/x-ms-wim",),
            extensions=(".wim",),
            kind=ec_archive.package,
            extractors=[sevenzip.extract],
            strict=True,
        )

        ec_archive.archive_handlers.append(WimHandler)
