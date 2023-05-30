import pluggy

from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    # pylint: disable=import-outside-toplevel
    # don't want all these imports as part of the file-level scope
    from surfactant.filetypeid import id_hex, id_magic
    from surfactant.infoextractors import a_out_file, elf_file, ole_file, pe_file
    from surfactant.output import csv_writer, cytrics_writer, spdx_writer
    from surfactant.relationships import (
        dotnet_relationship,
        elf_relationship,
        pe_relationship,
    )

    internal_plugins = (
        id_magic,
        id_hex,
        a_out_file,
        elf_file,
        pe_file,
        ole_file,
        dotnet_relationship,
        elf_relationship,
        pe_relationship,
        csv_writer,
        cytrics_writer,
        spdx_writer,
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
