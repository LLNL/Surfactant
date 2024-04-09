# Fuzzy H Plugin for SBOM Surfactant

A plugin for Surfactant that uses TLSH and SSDEEP to generate fuzzy hashes.

## Quickstart
**Note:** By default only TLSH is enabled as SSDEEP has a more complex build process, if you wish to include SSDEEP see the relevant section.

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

This will output within the metadata field of the main SBOM output JSON. The metadata field added will be in the below format.

```json
{
    "ssdeep": "3072:zk9IYDIW/+wxfiqV/jKneO1S4r88117lHc7ws47Fg5Q+ZLgFYY5:zsIYzpQqV/YLr8811P5",
    "tlsh": "T1C3449303A267DC9FC4445AB105A75168FB38FC16CF36BB1BB242B73E6A31F009EA5640"
}
```

Surfactant features for controlling which plugins are enabled/disabled can be used to control
whether or not this plugin will run using the plugin name `surfactantplugin_fuzzyhashes` (the name given in
`pyproject.toml` under the `project.entry-points."surfactant"` section).

## SSDEEP

If you do not have SSDEEP library already installed, you must run `export BUILD_LIB=1` before running `pip install`.

The SSDEEP package also required the following packages on a ubuntu 22 system:
  libtool
  build-essential
  automake

To install SSDEEP run the following:
`pip install .[ssdeep]` or `pip install -e .[ssdeep]`

## Uninstalling

The plugin can be uninstalled with `pip uninstall surfactantplugin-fuzzyhashes`.
