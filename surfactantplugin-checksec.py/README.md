# checksec.py Plugin for SBOM Surfactant

A plugin for Surfactant that uses the [checksec.py](https://github.com/Wenzel/checksec.py)
Python library to gather information on security related features enabled for ELF and PE files.

## Quickstart
In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installing the plugin, run Surfactant to generate an SBOM as usual and entries for ELF
and PE files will contain a metadata object with the information that checksec.py was able
to get about security related features.

From some limited benchmarks, gathering this information incurs at least a 15-25% performance
penalty, though it could be much higher depending on the files being processed (ELF files may
take longer than PE files -- possibly due the fortify checks).

Surfactant features for controlling which plugins are enabled/disabled can be used to control
whether or not this plugin will run using the plugin name `checksec.py` (the name given in
`pyproject.toml` under the `project.entry-points."surfactant"` section).

## Uninstalling
The plugin can be uninstalled with `pip uninstall surfactantplugin-checksec.py`.
