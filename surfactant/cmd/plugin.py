import subprocess
import sys

import click

from surfactant.configmanager import ConfigManager
from surfactant.plugin.manager import (
    call_init_hooks,
    find_plugin_by_name,
    get_plugin_manager,
    is_hook_implemented,
    print_plugins,
)


@click.command(name="list")
def plugin_list_cmd():
    """Lists plugins."""
    pm = get_plugin_manager()
    print_plugins(pm)

    # List disabled plugins
    config_manager = ConfigManager()
    section = "core"
    section_key = "disable_plugins"

    # Retrieve the current list of plugins that should be blocked
    current_blocked_plugins = config_manager.get(section, section_key, [])

    print("\nDISABLED PLUGINS")
    if not current_blocked_plugins:
        print("\tThere are no disabled plugins.")
    else:
        for disabled_plugin in current_blocked_plugins:
            print(f"\tname: {disabled_plugin}")


@click.command(name="enable")
@click.argument("plugin_names", nargs=-1)
def plugin_enable_cmd(plugin_names):
    """Enables one or more plugins."""
    if not plugin_names:
        raise click.UsageError("At least one plugin name must be specified.")
    section = "core"
    section_key = "disable_plugins"

    config_manager = ConfigManager()

    # Retrieve the current list of plugins that should be blocked
    current_blocked_plugins = config_manager.get(section, section_key, [])

    # Ensure current_blocked_plugins is a list
    if isinstance(current_blocked_plugins, str):
        current_blocked_plugins = [current_blocked_plugins]

    # Remove the plugin from the blocked list if present
    for plugin_name in plugin_names:
        if plugin_name in current_blocked_plugins:
            current_blocked_plugins.remove(plugin_name)

    # Update the configuration to remove plugins from being disabled
    config_manager.set(section, section_key, current_blocked_plugins)
    click.echo(f"Updated blocked plugins: {current_blocked_plugins}")


@click.command(name="disable")
@click.argument("plugin_names", nargs=-1)
def plugin_disable_cmd(plugin_names):
    """Disables one or more plugins."""
    if not plugin_names:
        raise click.UsageError("At least one plugin name must be specified.")
    section = "core"
    section_key = "disable_plugins"

    config_manager = ConfigManager()

    # Retrieve the current list of plugins that should be blocked
    current_blocked_plugins = config_manager.get(section, section_key, [])

    # Ensure current_blocked_plugins is a list
    if isinstance(current_blocked_plugins, str):
        current_blocked_plugins = [current_blocked_plugins]

    # Add the plugin to the blocked list if not already present
    for plugin_name in plugin_names:
        if plugin_name not in current_blocked_plugins:
            current_blocked_plugins.append(plugin_name)

    # Update the configuration to add plugins to be disabled
    if current_blocked_plugins:
        config_manager.set(section, section_key, current_blocked_plugins)
        click.echo(f"Updated blocked plugins: {current_blocked_plugins}")


@click.command(name="install")
@click.argument("plugin_name")
def plugin_install_cmd(plugin_name):
    """Installs a plugin."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", plugin_name])
        click.echo(f"Successfully installed {plugin_name}.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to install {plugin_name}: {e}", err=True)


@click.command(name="uninstall")
@click.argument("plugin_name")
def plugin_uninstall_cmd(plugin_name):
    """Uninstalls a plugin."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", plugin_name])
        click.echo(f"Successfully uninstalled {plugin_name}.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to uninstall {plugin_name}: {e}", err=True)


@click.command(name="update-db")
@click.argument("plugin_name", required=False)
@click.option(
    "--all",
    "update_all",
    is_flag=True,
    help="Update all plugins that implement the 'update_db' hook.",
)
@click.option(
    "--allow-gpl",
    "allow_gpl",
    default=None,
    is_flag=False,
    flag_value="",  # When used without =, it will be set to empty string
    help="Allow GPL-licensed databases. Use '--allow-gpl' for one-time acceptance, or '--allow-gpl=always' or '--allow-gpl=never' to update the stored config setting.",
)
def plugin_update_db_cmd(plugin_name, update_all, allow_gpl):
    """Updates the database for a specified plugin or all plugins if --all is used."""
    pm = get_plugin_manager()
    config_manager = ConfigManager()
    
    # Handle --allow-gpl flag
    # When used as --allow-gpl (without =), Click sets it to empty string (from flag_value)
    # When used as --allow-gpl=value, Click sets it to the value
    # When not used, it's None
    if allow_gpl is not None:
        # If it's an empty string, treat as one-time acceptance
        if allow_gpl == "":
            allow_gpl = "once"
            config_manager.set("runtime", "allow_gpl", "once")
        else:
            # Normalize the value
            allow_gpl_lower = allow_gpl.lower()
            
            if allow_gpl_lower in ("always", "a"):
                # Permanently set to always accept GPL
                allow_gpl = "always"
                config_manager.set("sources", "gpl_license_ok", "always")
                click.echo("GPL license acceptance set to 'always'.")
            elif allow_gpl_lower in ("never", "n"):
                # Permanently set to never accept GPL
                allow_gpl = "never"
                config_manager.set("sources", "gpl_license_ok", "never")
                click.echo("GPL license acceptance set to 'never'.")
            else:
                # Unknown value, treat as error
                click.echo(f"Error: Invalid value for --allow-gpl: '{allow_gpl}'. Use 'always' or 'never', or use the flag without a value for one-time acceptance.", err=True)
                return
    
    try:
        call_init_hooks(pm, hook_filter=["update_db"], command_name="update-db")

        if update_all:
            # Update all plugins that implement the update_db hook
            for plugin in pm.get_plugins():
                if is_hook_implemented(pm, plugin, "update_db"):
                    plugin_name = pm.get_name(plugin) or pm.get_canonical_name(plugin)
                    click.echo(f"Updating {plugin_name} ...")
                    update_result = plugin.update_db()
                    if update_result:
                        click.echo(f"Update result for {plugin_name}: {update_result}")
                    else:
                        click.echo(f"No update operation performed for {plugin_name}.")
        else:
            if not plugin_name:
                click.echo("Please specify a plugin name or use --all to update all plugins.", err=True)
                return

            plugin = find_plugin_by_name(pm, plugin_name)  # Get an instance of the plugin

            # Check if the plugin is registered
            if not plugin:
                click.echo(f"Plugin '{plugin_name}' not found.", err=True)
                return

            # Check if the plugin has implemented the update_db hook
            has_update_db_hook = is_hook_implemented(pm, plugin, "update_db")

            if not has_update_db_hook:
                click.echo(f"Plugin '{plugin_name}' does not implement the 'update_db' hook.", err=True)
                return

            # Call the update_db hook for the specified plugin
            plugin_name = pm.get_name(plugin) or pm.get_canonical_name(plugin)
            click.echo(f"Updating {plugin_name} ...")
            update_result = plugin.update_db()

            if update_result:
                click.echo(f"Update result for {plugin_name}: {update_result}")
            else:
                click.echo(f"No update operation performed for {plugin_name}.")
    finally:
        # Clean up temporary runtime setting
        if allow_gpl == "once":
            runtime_section = config_manager["runtime"]
            if runtime_section and "allow_gpl" in runtime_section:
                del runtime_section["allow_gpl"]
                config_manager._save_config()
