# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
import re
from typing import Optional

import surfactant.plugin


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str) -> Optional[str]:
    # pylint: disable=too-many-return-statements
    try:
        with open(filepath, "r") as f:
            head = f.readline().strip("\n")
            suffix = pathlib.Path(filepath).suffix.lower()
            # Check for script files
            if re.match(r"#!.*bash", head) or suffix == ".sh":
                return "BASH"
            if re.match(r"#!.*zsh", head) or suffix == ".zsh":
                return "ZSH"
            if re.match(r"#!.*php", head) or suffix == ".php":
                return "PHP"
            if re.match(r"#!.*python", head) or suffix == ".py":
                return "PYTHON"
            if suffix == ".pyc":
                return "PYTHON_COMPILED"
            if suffix == ".js":
                return "JAVASCRIPT"
            if suffix == ".css":
                return "CSS"
            if head == "<!DOCTYPE html>" or suffix in (".html", ".htm"):
                return "HTML"
            return None
    except FileNotFoundError:
        return None
