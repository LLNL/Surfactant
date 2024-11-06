import click
from surfactant.cmd.config import config
from surfactant.plugin.manager import get_plugin_manager
from surfactant.configmanager import ConfigManager
@click.command(name="list")
def plugin_list_cmd():
    """Lists plugins."""
    pm = get_plugin_manager()
    print("-------")
    print("PLUGINS")
    for p in pm.get_plugins():
        print("-------")
        print(f"canonical name: {pm.get_canonical_name(p)}")
        plugin_name = pm.get_name(p) if pm.get_name(p) else ""
        print(f"name: {plugin_name}")

import click
from typing import List

@click.command(name="disable")
@click.argument('plugin_names', nargs=-1)
def plugin_disable_cmd(plugin_names):
    """Disables one or more plugins."""
    if not plugin_names:
        raise click.UsageError("At least one plugin name must be specified.")

    pm = get_plugin_manager()
    config_manager = ConfigManager()

    # Debugging: Print config file path and current config
    print(config_manager._get_config_file_path())
    config_manager.print_config()

    # Retrieve the current list of blocked plugins
    current_blocked_plugins = config_manager.get('plugins', 'blocked', [])

    # Ensure current_blocked_plugins is a list
    if isinstance(current_blocked_plugins, str):
        current_blocked_plugins = [current_blocked_plugins]

    for plugin_name in plugin_names:
        # Check if the plugin is already blocked
        if pm.is_blocked(plugin_name):
            print(f"Plugin '{plugin_name}' is already disabled.")
            continue

        # Unregister the plugin
        plugin = pm.unregister(name=plugin_name)
        if plugin is None:
            print(f"Plugin '{plugin_name}' not found.")
            continue

        # Block the plugin to prevent future registration
        pm.set_blocked(plugin_name)

        # Add the plugin to the blocked list if not already present
        if plugin_name not in current_blocked_plugins:
            current_blocked_plugins.append(plugin_name)

    # Update the configuration to reflect the disabled status
    if current_blocked_plugins:
        config_manager.set('plugins', 'blocked', current_blocked_plugins)
        click.echo(f"Updated blocked plugins: {current_blocked_plugins}")
