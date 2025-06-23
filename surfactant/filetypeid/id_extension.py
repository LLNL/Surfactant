# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
import re
from typing import List, Optional

from loguru import logger

import surfactant.plugin


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str) -> Optional[List[str]]:
    # pylint: disable=too-many-return-statements
    _filetype_extensions = {
        ".sh": "SHELL",
        ".bash": "BASH",
        ".zsh": "ZSH",
        ".py": "PYTHON",
        ".pyc": "PYTHON_COMPILED",
        ".js": "JAVASCRIPT",
        ".css": "CSS",
        ".html": "HTML",
        ".htm": "HTML",
        ".php": "PHP",
        ".bat": "BATCH",
        ".pl": "PERL_OR_PROLOG",
        ".pm": "PERL_MODULE",
    }
    _interpreters = {
        b"sh": "SHELL",
        b"bash": "BASH",
        b"zsh": "ZSH",
        b"php": "PHP",
        b"python": "PYTHON",
        b"python3": "PYTHON",
        b"perl": "PERL",
    }
    filetype_matches = []
    try:
        with open(filepath, "rb") as f:
            head = f.read(256)
            if head.startswith(b"<!DOCTYPE html>"):
                filetype_matches.append("HTML")
            if head.startswith(b"#!") and b"\n" in head:
                end_line = head.index(b"\n")
                head = head[:end_line]
                for interpreter, filetype in _interpreters.items():
                    if re.search(interpreter, head):
                        return filetype
                filetype_matches.append("SHEBANG")
    except FileNotFoundError:
        logger.warning(f"File not found: {filepath}")
        return None
    suffix = pathlib.Path(filepath).suffix.lower()
    if suffix in _filetype_extensions:
        filetype_matches.append(_filetype_extensions[suffix])
    if filetype_matches:
        return filetype_matches
    return None
