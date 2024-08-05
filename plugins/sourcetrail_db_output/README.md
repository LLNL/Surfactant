# Sourcetrail DB Output Plugin for SBOM Surfactant

A plugin for Surfactant that outputs databases for vizualization in [Sourcetrail](https://github.com/CoatiSoftware/Sourcetrail/tree/master).


## Quickstart
This plugin requires Python 3.10 or greater.

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install git+https://github.com/LLNL/Surfactant#subdirectory=plugins/sourcetrail_db_output`. If pipx was used to install Surfactant, install this plugin with `pipx inject surfactant git+https://github.com/LLNL/Surfactant#subdirectory=plugins/sourcetrail_db_output`.

For developers making changes to this plugin, install it with `pip install -e .` using a clone of the git repository.

After installation, add the option `--output_format=sourcetrail_db` to generate to generate a database.

Alternatively, to create a database for an already existing file run a command similar to:
```bash
surfactant generate --output_format=sourcetrail_db --skip_relationships --skip_gather IN_CONFIG OUT_FILE SBOM_IN
```

This plugin will output multiple files; note that the output file name will have its extension stripped.

## Mapping

The following mapping, from Sourcetrail to Surfactant meaning, is used:

Class -> Name (or first file name if no name is found)

Field -> Install path

Method -> File name

Typedef -> Symlink

## Uninstalling
The plugin can be uninstalled with `pip uninstall surfactantplugin-sourcetrail-db-output`. If pipx was used, it can be uninstalled with `pipx uninject surfactant surfactantplugin-sourcetrail-db-output`.
