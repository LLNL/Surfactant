# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import importlib.metadata
import sys

import click

from surfactant.cmd.generate import sbom as generate
from surfactant.cmd.stat import stat
from surfactant.cmd.merge import merge_command


@click.group()
def main():
    pass


@click.command("version")
def version():
    """Print version information."""
    click.echo(importlib.metadata.version("surfactant"))
    sys.exit(0)


main.add_command(generate)
main.add_command(version)
main.add_command(stat)
main.add_command(merge_command)

if __name__ == "__main__":
    main()
# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
