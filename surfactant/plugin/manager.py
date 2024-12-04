# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import sys

import pluggy
from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    # pylint: disable=import-outside-toplevel
    # don't want all these imports as part of the file-level scope
    from surfactant.filetypeid import id_extension, id_hex, id_magic
    from surfactant.infoextractors import (
        a_out_file,
        coff_file,
        docker_image,
        elf_file,
        java_file,
        js_file,
        mach_o_file,
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
        id_extension,
        a_out_file,
        coff_file,
        docker_image,
        elf_file,
        java_file,
        mach_o_file,
        js_file,
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


def set_blocked_plugins(pm: pluggy.PluginManager):
    """Gets the current list of blocked plugins from the config manager, then blocks and unregisters them with the plugin manager."""
    config_manager = ConfigManager()

    # Retrieve the current list of blocked plugins
    current_blocked_plugins = config_manager.get("core", "disable_plugins", [])
    for plugin_name in current_blocked_plugins:
        # Check if the plugin is already blocked
        if pm.is_blocked(plugin_name):
            logger.info(f"Plugin '{plugin_name}' is already disabled.")
            continue

        # Unregister the plugin
        plugin = pm.unregister(name=plugin_name)
        if plugin is None:
            logger.info(f"Disabled plugin '{plugin_name}' not found.")
            continue

        # Block the plugin to prevent future registration
        pm.set_blocked(plugin_name)


def get_plugin_manager() -> pluggy.PluginManager:
    pm = pluggy.PluginManager("surfactant")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("surfactant")
    _register_plugins(pm)
    set_blocked_plugins(pm)
    pm.check_pending()
    return pm


def is_hook_implemented(pm: pluggy.PluginManager, plugin: object, hook_name: str) -> bool:
    """
    Checks if a specific hook is implemented by a given plugin.

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        plugin (object): The plugin object to check.
        hook_name (str): The name of the hook to check for implementation.

    Returns:
        bool: True if the hook is implemented by the plugin, False otherwise.
    """
    hook_callers = pm.get_hookcallers(plugin)
    if hook_callers:
        for hook_caller in hook_callers:
            if hook_caller.name == hook_name:
                return True
    return False


def print_plugins(pm: pluggy.PluginManager):
    print("PLUGINS")
    for plugin in pm.get_plugins():
        plugin_name = pm.get_name(plugin) if pm.get_name(plugin) else ""
        print(f"\t> name: {plugin_name}")
        print(f"\t  canonical name: {pm.get_canonical_name(plugin)}")

        short_name = None        
        
        # Check if the plugin has implemented the short_name hook
        hook_impl = is_hook_implemented(pm, plugin, 'short_name')

        if hook_impl:
            short_name = plugin.short_name() # Get the short name

        print(f"\t  short name: {short_name}\n")


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


def find_plugin_by_name(pm: pluggy.PluginManager, name: str):
    """
    Finds a plugin by matching the given name against the plugin's registered name,
    canonical name, and its short name (if applicable).

    :param pm: The plugin manager instance.
    :param name: The name to match against the plugin's registered, canonical, and short names.
    :return: The matched plugin instance or None if no match is found.
    """
    # Convert the name to lowercase for case-insensitive comparison
    name_lower = name.lower()

    for plugin in pm.get_plugins():
        # Get the registered and canonical names
        registered_name = pm.get_name(plugin).lower()
        canonical_name = pm.get_canonical_name(plugin).lower()

        # Check if the plugin has implemented the short_name hook
        short_name = None
        hook_impl = is_hook_implemented(pm, plugin, 'short_name')

        if hook_impl:
            short_name = plugin.short_name() # Get the short name

        # Convert short_name to lowercase if it exists
        short_name_lower = short_name.lower() if short_name else None

        # Check if any of the names match the given name
        if (registered_name == name_lower) or (canonical_name == name_lower) or (short_name_lower == name_lower):
            return plugin

    return None
