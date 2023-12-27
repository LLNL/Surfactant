# Syft Plugin for SBOM Surfactant

A plugin for Surfactant that uses Anchore Syft(https://github.com/anchore/syft) version 0.76 to gather information about software contained in disk images.

## Quickstart
In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installation, this plugin will run whenever surfactant discovers a .tar file to be examined.

## Uninstalling
The plugin can be uninstalled with `pip uninstall surfactantplugin-syft`.
