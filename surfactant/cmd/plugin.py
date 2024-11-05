import click

from surfactant.plugin.manager import get_plugin_manager

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


@click.command(name="disable")
@click.argument('plugin_names', nargs=-1)
def plugin_disable_cmd(plugin_names):
    """Disables one or more plugins."""
    if not plugin_names:
        raise click.UsageError("At least one plugin name must be specified.")
    
    for plugin_name in plugin_names:
        print(f"Disabling {plugin_name} plugin")
