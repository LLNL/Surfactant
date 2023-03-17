import pluggy

from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    # pylint: disable=import-outside-toplevel
    # don't want all these imports as part of the file-level scope
    from surfactant.infoextractors import elf_file, ole_file, pe_file
    from surfactant.output import csv_writer, cytrics_writer
    from surfactant.relationships import (
        dotnet_relationship,
        elf_relationship,
        pe_relationship,
    )

    internal_plugins = (
        elf_file,
        pe_file,
        ole_file,
        dotnet_relationship,
        elf_relationship,
        pe_relationship,
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
