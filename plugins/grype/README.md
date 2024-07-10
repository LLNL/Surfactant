# Syft Plugin for SBOM Surfactant

A plugin for Surfactant that uses [grype](https://github.com/anchore/grype)


## Quickstart
To start, install grype following the instructions on [the github page](https://github.com/anchore/grype)

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installation, this plugin will run whenever surfactant discovers an applicable file to be examined.

## Uninstalling
The plugin can be uninstalled with `pip uninstall surfactantplugin-grype`.
