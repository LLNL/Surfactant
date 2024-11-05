import click
from surfactant.plugin.manager import get_plugin_manager

@click.command(name="list")
def display():
    pm = get_plugin_manager()
    print("-------")
    print("PLUGINS")
    for p in pm.get_plugins():
        print("-------")
        print(f"canonical name: {pm.get_canonical_name(p)}")
        plugin_name = pm.get_name(p) if pm.get_name(p) else ""
        print(f"name: {plugin_name}")
