# Copyright 2023 Lawrence Livermore Natioanl Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ContextEntry:
    extractPaths: List[str]
    archive: Optional[str] = None
    installPrefix: Optional[str] = None
