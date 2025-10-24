# DAPper Plugin for SBOM Surfactant

A plugin for Surfactant that uses [DAPper](https://github.com/LLNL/dapper) to identify software packages from binary files by querying comprehensive package databases.

## Overview

The DAPper plugin enhances Surfactant's SBOM generation by identifying which software packages provide specific binary files. It queries multiple Linux distribution databases (Ubuntu, Debian) to find package information for ELF files, and Windows PE files via NuGet databases.

## Features

- **Multi-distribution package detection**: Queries all available Linux distributions (Ubuntu Focal/Jammy/Noble, Debian Buster/Bullseye/Bookworm)
- **Comprehensive results**: Returns all matching packages across distributions
- **File normalization**: Handles various file naming conventions through intelligent normalization
- **Structured output**: Provides detailed package information including package names, versions, and source distributions

## Prerequisites

### Install Dapper and Datasets

Before using this plugin, you need to install Dapper and download the package databases:

1. Install Dapper:
   ```bash
   cargo install dapper
   ```

2. Download required datasets (must be run from the dapper directory):
   ```bash
   # List available datasets
   dapper db list-available

   # Install specific Linux datasets
   dapper db install ubuntu-focal
   dapper db install ubuntu-jammy
   dapper db install ubuntu-noble
   dapper db install debian-bookworm

   # Install nuget datasets
   dapper db install nuget

   # Install all available datasets
   dapper db install all
   ```

## Installation

In the same virtual environment that Surfactant was installed in, install this plugin:

```bash
# From PyPI (when available)
pip install surfactantplugin-dapper

# From GitHub
pip install git+https://github.com/LLNL/Surfactant#subdirectory=plugins/dapper

# For developers making changes to this plugin
git clone https://github.com/LLNL/Surfactant.git
cd Surfactant/plugins/dapper
pip install -e .
```


## Output Format

The plugin adds package information to the metadata field of software entries in the SBOM. For each binary file, it provides:

```json
{
   "dapper_packages": [
            {
              "package_name": "libssl3",
              "package_dataset": "ubuntu-jammy",
              "original_name": "libssl.so.3",
              "file_path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
              "normalized_name": "libssl.so",
              "version": null,
              "soabi": "3"
            },
            {
              "package_name": "libssl3t64",
              "package_dataset": "ubuntu-noble",
              "original_name": "libssl.so.3",
              "file_path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
              "normalized_name": "libssl.so",
              "version": null,
              "soabi": "3"
            }
          ]
}
```

### Key Fields

- **package_name**: Short package name (e.g., "libssl3")
- **full_package_name**: Complete package identifier with version
- **package_dataset**: Source dataset/distribution
- **normalized_name**: Normalized filename used for matching
- **original_name**: Original filename as found
- **file_path**: Installation path within the package

## Configuration

### Enabling/Disabling

The plugin can be controlled using Surfactant's plugin management features with the plugin name `surfactantplugin_dapper` (defined in `pyproject.toml`).

```bash
# Disable the plugin
surfactant plugin disable surfactantplugin_dapper

# Enable the plugin
surfactant plugin enable surfactantplugin_dapper
```

### Dataset Management

All dataset commands must be run from the dapper directory:

```bash
cd ~/dapper
```

Then run:

```bash
# List installed datasets
dapper db list-installed

# Update all datasets
dapper db update all

# Remove a dataset
dapper db uninstall ubuntu-focal
```

## Supported File Types

Currently supported:
- **ELF files** (Linux binaries and libraries): `.so`, `.o`, and extensionless executables

Planned support:
- **PE files** (Windows binaries): `.dll`, `.exe`, `.sys` (pending NuGet dataset availability)


## Uninstalling

Remove the plugin with:
```bash
pip uninstall surfactantplugin-dapper
```

If pipx was used:
```bash
pipx uninject surfactant surfactantplugin-dapper
```

## License

MIT License (same as Surfactant)

## Additional Resources
- [DAPper on crates.io](https://crates.io/crates/dapper)
- [DAPper Documentation](https://dapper.readthedocs.io)
- [DAPper GitHub Repository](https://github.com/LLNL/dapper)
- [Surfactant Documentation](https://surfactant.readthedocs.io)
- [Dataset Repository](https://huggingface.co/datasets/dapper-datasets)
