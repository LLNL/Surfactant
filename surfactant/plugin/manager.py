import pluggy

from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    from surfactant.output import csv_writer, cytrics_writer
    from surfactant.relationships import dotnet, elf

    internal_plugins = (
        dotnet,
        elf,
        csv_writer,
        cytrics_writer,
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


pm_test = get_plugin_manager()
for p in pm_test.get_plugins():
    print("------")
    print("canonical name: " + pm_test.get_canonical_name(p))
    print("name: " + pm_test.get_name(p))
# pm.get_plugin("anotherplugin").write_sbom(sbom=None, outfile=None)
# pm.hook.write_sbom(sbom="sbom", outfile="outfile")
# print(pm.hook.establish_relationships(sbom=[], software=[], metadata=[]))
