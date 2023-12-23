# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import importlib.metadata
import sys

import click
from loguru import logger

from surfactant.cmd.cli import add, edit, find
from surfactant.cmd.createconfig import create_config
from surfactant.cmd.generate import sbom as generate
from surfactant.cmd.merge import merge_command
from surfactant.cmd.stat import stat


@click.group()
@click.option(
    "--log-level",
    type=click.Choice(
        ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False
    ),
    default="INFO",
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


@main.group("cli")
def cli():
    """Commandline interface used to modify SBOM entries."""


# Main Commands
main.add_command(generate)
main.add_command(version)
main.add_command(stat)
main.add_command(merge_command)
main.add_command(create_config)

# CLI Subcommands
cli.add_command(find)
cli.add_command(edit)
cli.add_command(add)

if __name__ == "__main__":
    main(log_level="INFO")
