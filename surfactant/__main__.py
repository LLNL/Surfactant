# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import importlib.metadata
import sys

import click
from loguru import logger

from surfactant.cmd.generate import sbom as generate
from surfactant.cmd.stat import stat


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(
        ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
    default="info",
)
def main(log_level):
    # Can't change the logging level; need to remove and add a new logger with the desired log level
    logger.remove()
    logger.add(sys.stderr, level=log_level)


@click.command("version")
def version():
    """Print version information."""
    click.echo(importlib.metadata.version("surfactant"))
    sys.exit(0)


main.add_command(generate)
main.add_command(version)
main.add_command(stat)

if __name__ == "__main__":
    main()
