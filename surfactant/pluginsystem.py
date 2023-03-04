import os
import pathlib


class _PluginRegistrationMetaClass(type):
    _PLUGINS = {}

    def __init__(cls, name, bases, namespace):
        # get the current list of plugins of the particular type (or empty list if none added yet), and add this new plugin to the list
        currentPlugins = cls._PLUGINS.get(cls.PLUGIN_TYPE, [])
        currentPlugins.append(cls)
        cls._PLUGINS[cls.PLUGIN_TYPE] = currentPlugins


class PluginBase(object, metaclass=_PluginRegistrationMetaClass):
    PLUGIN_TYPE = ""
    PLUGIN_NAME = ""

    @classmethod
    def get_plugins(cls):
        if cls.PLUGIN_TYPE not in cls._PLUGINS.keys():
            return []
        return [
            plugin
            for plugin in cls._PLUGINS[cls.PLUGIN_TYPE]
            if issubclass(plugin, cls) and plugin.PLUGIN_NAME != ""
        ]

    @classmethod
    def get_plugin(cls, plugin_name):
        if cls.PLUGIN_TYPE not in cls._PLUGINS.keys():
            return None
        for plugin in cls._PLUGINS[cls.PLUGIN_TYPE]:
            if plugin.PLUGIN_NAME == plugin_name:
                return plugin
        return None


class InfoPlugin(PluginBase):
    PLUGIN_TYPE = "INFO"
    PLUGIN_NAME = ""

    @classmethod
    def supports_file(cls, filename="", filetype=None) -> bool:
        raise NotImplemented("supports_file not implemented")

    @classmethod
    def extract_info(cls, filename) -> dict:
        raise NotImplemented("extract_info not implemented")


class RelationshipPlugin(PluginBase):
    PLUGIN_TYPE = "RELATIONSHIP"
    PLUGIN_NAME = ""

    @staticmethod
    def create_relationship(xUUID, yUUID, relationship):
        return {"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship}

    @classmethod
    def has_required_fields(cls, metadata) -> bool:
        raise NotImplemented("has_required_fields not implemented")

    @classmethod
    def get_relationships(cls, sbom, sw, metadata) -> list:
        raise NotImplemented("get_relationships not implemented")


class OutputPlugin(PluginBase):
    PLUGIN_TYPE = "OUTPUT"
    PLUGIN_NAME = ""

    @classmethod
    def write(cls, sbom, outfile):
        raise NotImplemented("write not implemented")


def print_available_plugins():
    print("------INFO PLUGINS------")
    for p in InfoPlugin.get_plugins():
        print(p.PLUGIN_NAME)
    print("------RELATIONSHIP PLUGINS------")
    for p in RelationshipPlugin.get_plugins():
        print(p.PLUGIN_NAME)
    print("------OUTPUT PLUGINS------")
    for p in OutputPlugin.get_plugins():
        print(p.PLUGIN_NAME)


# function to load local user plugins from a directory (default: ~/.surfactant/plugins)
def load_user_plugins(directory=pathlib.Path.home().joinpath(".surfactant", "plugins")):
    import importlib.machinery
    import importlib.util

    for root, dirs, files in os.walk(
        pathlib.Path.home().joinpath(".surfactant", "plugins"), topdown=True
    ):
        # skip __pycache__ subdirectories by modifying dirs in-place (topdown=True argument to os.walk allows this to work)
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for filename in files:
            # load any files found that end in a .py extension
            full_plugin_path = pathlib.Path(root, filename)
            if full_plugin_path.suffix == ".py":
                spec = importlib.util.spec_from_file_location(
                    full_plugin_path.stem, full_plugin_path
                )
                plugin_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin_module)


# load plugins included with surfactant
import surfactant.plugins

# load user plugins
load_user_plugins()
# print_available_plugins()
