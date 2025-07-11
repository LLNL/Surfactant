# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Optional
from extractcode import archive as ec_archive
from extractcode import sevenzip

import surfactant.plugin


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str) -> Optional[str]:
    try:
        ec_handler = ec_archive.get_best_handler(filepath)
        if ec_handler:
            return f"EXTRACTCODE-{ec_handler.name}"
        return None
    except FileNotFoundError:
        return None

@surfactant.plugin.hookimpl
def init_hook(command_name: Optional[str] = None) -> None:
    ec_archive.archive_handlers.append(WimHandler)

# Add WIM support to extractcode via 7zip
WimHandler = ec_archive.Handler(
    name='Microsoft wim',
    filetypes=('Windows imaging (WIM) image'),
    mimetypes=('application/x-ms-wim',),
    extensions=('.wim',),
    kind=ec_archive.package,
    extractors=[sevenzip.extract],
    strict=True
)