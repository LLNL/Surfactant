# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import importlib.metadata
import sys

import click
from loguru import logger

from surfactant.cmd.cli import (
    handle_cli_add,
    handle_cli_edit,
    handle_cli_find,
    handle_cli_load,
    handle_cli_save,
)
from surfactant.cmd.config import config
from surfactant.cmd.config_tui import config_tui
from surfactant.cmd.createconfig import create_config
from surfactant.cmd.generate import sbom as generate
from surfactant.cmd.merge import merge_command
from surfactant.cmd.plugin import (
    plugin_disable_cmd,
    plugin_enable_cmd,
    plugin_install_cmd,
    plugin_list_cmd,
    plugin_uninstall_cmd,
    plugin_update_db_cmd,
)
from surfactant.cmd.stat import stat
from surfactant.cmd.tui import tui


@click.group()
@click.version_option(
    importlib.metadata.version("surfactant"),
    "--version",
    "-v",
    message="%(version)s",
)
@click.option(
    "--log-level",
    type=click.Choice(
        ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"],
        case_sensitive=False,
    ),
    default="INFO",
)
def main(log_level="INFO"):
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


@main.group("plugin")
def plugin():
    """Manage plugins."""


# Main Commands
main.add_command(generate)
main.add_command(version)
main.add_command(config)
main.add_command(stat)
main.add_command(merge_command)
main.add_command(create_config)
main.add_command(plugin)
main.add_command(config_tui)
main.add_command(tui)

# CLI Subcommands
cli.add_command(handle_cli_find)
cli.add_command(handle_cli_edit)
cli.add_command(handle_cli_add)
cli.add_command(handle_cli_load)
cli.add_command(handle_cli_save)

# Plugin Subcommands
plugin.add_command(plugin_list_cmd)
plugin.add_command(plugin_enable_cmd)
plugin.add_command(plugin_disable_cmd)
plugin.add_command(plugin_install_cmd)
plugin.add_command(plugin_uninstall_cmd)
plugin.add_command(plugin_update_db_cmd)


if __name__ == "__main__":
    main()
