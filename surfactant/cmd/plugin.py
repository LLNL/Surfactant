import click
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

    # List disabled pluginsi
    config_manager = ConfigManager()
    section = 'core'
    section_key = 'disable_plugins'
    
    # Retrieve the current list of plugins that should be blocked
    current_blocked_plugins = config_manager.get(section, section_key, [])
    
    print("-------")
    print("Disabled Plugins")
    for disabled_plugin in current_blocked_plugins :
        print("-------")
        print(f"name: {disabled_plugin}")

from typing import List
from surfactant.plugin.manager import get_plugin_manager
@click.command(name="disable")
@click.argument('plugin_names', nargs=-1)
def plugin_disable_cmd(plugin_names):
    """Disables one or more plugins."""
    if not plugin_names:
        raise click.UsageError("At least one plugin name must be specified.")
    section = 'core'
    section_key = 'disable_plugins'

    config_manager = ConfigManager()

    # Retrieve the current list of plugins that should be blocked
    current_blocked_plugins = config_manager.get(section, section_key, [])

    # Ensure current_blocked_plugins is a list
    if isinstance(current_blocked_plugins, str):
        current_blocked_plugins = [current_blocked_plugins]
	
    # Add the plugin to the blocked list if not already present
    for plugin_name in plugin_names :
        if plugin_name not in current_blocked_plugins:
            current_blocked_plugins.append(plugin_name)

    # Update the configuration to add plugins to be disabled
    if current_blocked_plugins:
        config_manager.set(section, section_key, current_blocked_plugins)
        click.echo(f"Updated blocked plugins: {current_blocked_plugins}")
