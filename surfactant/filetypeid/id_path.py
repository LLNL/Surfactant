# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
import re
from typing import Optional

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str, context: ContextEntry|None=None) -> Optional[str]:
    _substrings = {
        "var/lib/dkpg": "DPKG Database File"
    }
    for key, value in _substrings.items():
        if re.search(key, filepath):
            return value