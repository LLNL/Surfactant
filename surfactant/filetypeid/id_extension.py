# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
import re
from typing import Optional

from loguru import logger

import surfactant.plugin


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str) -> Optional[str]:
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
    }
    _interpreters = {
        "sh": "SHELL",
        "bash": "BASH",
        "zsh": "ZSH",
        "php": "PHP",
        "python": "PYTHON",
        "python3": "PYTHON",
    }
    try:
        with open(filepath, "rb") as f:
            head = f.read(256)
            if head.startswith(b"<!DOCTYPE html>"):
                return "HTML"
            if head.startswith(b"#!") and b"\n" in head:
                end_line = head.index(b"\n")
                try:
                    head = head[:end_line].decode("utf-8")
                    for interpreter, filetype in _interpreters.items():
                        if re.search(interpreter, head):
                            return filetype
                except UnicodeDecodeError:
                    logger.warning(
                        f"Decode error in file {filepath}: {head[: end_line]}"
                    )
                return "SHEBANG"
    except FileNotFoundError:
        logger.warning(f"File not found: {filepath}")
        return None
    suffix = pathlib.Path(filepath).suffix.lower()
    if suffix in _filetype_extensions:
        return _filetype_extensions[suffix]
    return None
