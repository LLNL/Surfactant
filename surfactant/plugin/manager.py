# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import sys

import pluggy
from loguru import logger

from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    # pylint: disable=import-outside-toplevel
    # don't want all these imports as part of the file-level scope
    from surfactant.filetypeid import id_hex, id_magic
    from surfactant.infoextractors import (
        a_out_file,
        coff_file,
        elf_file,
        java_file,
        ole_file,
        pe_file,
    )
    from surfactant.input_readers import cytrics_reader
    from surfactant.output import (
        csv_writer,
        cyclonedx_writer,
        cytrics_writer,
        spdx_writer,
    )
    from surfactant.relationships import (
        dotnet_relationship,
        elf_relationship,
        java_relationship,
        pe_relationship,
    )

    internal_plugins = (
        id_magic,
        id_hex,
        a_out_file,
        coff_file,
        elf_file,
        java_file,
        pe_file,
        ole_file,
        dotnet_relationship,
        elf_relationship,
        java_relationship,
        pe_relationship,
        csv_writer,
        cytrics_writer,
        cyclonedx_writer,
        spdx_writer,
        cytrics_reader,
    )
    for plugin in internal_plugins:
        pm.register(plugin)


def get_plugin_manager() -> pluggy.PluginManager:
    pm = pluggy.PluginManager("surfactant")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("surfactant")
    _register_plugins(pm)
    pm.check_pending()
    return pm


def print_plugins(pm: pluggy.PluginManager):
    print("-------")
    print("PLUGINS")
    for p in pm.get_plugins():
        print("-------")
        print("canonical name: " + pm.get_canonical_name(p))
        print("name: " + pm.get_name(p))


def find_io_plugin(pm: pluggy.PluginManager, io_format: str, function_name: str):
    found_plugin = pm.get_plugin(io_format)

    if found_plugin is None:
        for plugin in pm.get_plugins():
            try:
                if plugin.short_name().lower() == io_format.lower() and hasattr(
                    plugin, function_name
                ):
                    found_plugin = plugin
                    break
            except AttributeError:
                pass

    if found_plugin is None:
        logger.error(f'No "{function_name}" plugin for format "{io_format}" found')
        sys.exit(1)

    return found_plugin
