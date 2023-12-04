# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from .config import ContextEntry

try:
    from ._version import __version__, __version_tuple__
except ModuleNotFoundError:
    __version__ = ""
    __version_tuple__ = ()

__all__ = ["ContextEntry"]
