# Grype Plugin for SBOM Surfactant

A plugin for Surfactant that uses [grype](https://github.com/anchore/grype)


## Quickstart
To start, install grype following the instructions on [the github page](https://github.com/anchore/grype#installation)

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install git+https://github.com/LLNL/Surfactant#subdirectory=plugins/grype`. If pipx was used to install Surfactant, install this plugin with `pipx inject surfactant git+https://github.com/LLNL/Surfactant#subdirectory=plugins/grype`.

For developers making changes to this plugin, install it with `pip install -e .` using a clone of the git repository.

After installation, this plugin will run whenever Surfactant discovers an applicable file (saved Docker image tarball) to be examined.

## Uninstalling
The plugin can be uninstalled with `pip uninstall surfactantplugin-grype`. If pipx was used, it can be uninstalled with `pipx uninject surfactant surfactantplugin-grype`.
