# stringextract Plugin for SBOM Surfactant

A plugin for Surfactant that uses the [binary2strings](https://github.com/glmcdona/binary2strings)
Python library to extract strings from ELF and PE files.

## Quickstart

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installing the plugin, run Surfactant to generate an SBOM as usual and entries for ELF
and PE files will generate additional json files in the working directory that contain the strings of those files.
If there are duplicate hashed files the extractor will skip the entry.
Example:

`Output Filename: $(md5hash)_$(filename).json`

```json
{
  "md5hash": "",
  "filename": "",
  "strings": []
}
```

Surfactant features for controlling which plugins are enabled/disabled can be used to control
whether or not this plugin will run using the plugin name `surfactantplugin_stringextract.py` (the name given in
`pyproject.toml` under the `project.entry-points."surfactant"` section).

## Uninstalling

The plugin can be uninstalled with `pip uninstall surfactantplugin_stringextract.py`.