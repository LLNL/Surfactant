import pkgutil

__all__ = []
for finder, name, _ispkg in pkgutil.walk_packages(__path__):
    __all__.append(name)
    module = finder.find_module(name).load_module(name)
