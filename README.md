<p align="center">
<picture>
<source srcset="https://user-images.githubusercontent.com/3969255/290751328-fe11d1de-c2a9-4602-a7cd-b0e34bfce728.png#gh-dark-mode-only" media="(prefers-color-scheme: dark)" width="250" alt="Blue magnifying glass Surfactant logo">
<img src="https://user-images.githubusercontent.com/3969255/290751330-77003e89-944a-4269-9821-843abe35fe4a.png#gh-light-mode-only" width="250" alt="Blue magnifying glass Surfactant logo">
</picture>
</p>

# Surfactant


A modular framework to gather file information for SBOM generation and dependency analysis.

[![CI Test Status](https://github.com/LLNL/Surfactant/actions/workflows/pytest.yml/badge.svg)](https://github.com/LLNL/Surfactant/actions/workflows/pytest.yml)
[![PyPI](https://img.shields.io/pypi/v/surfactant)](https://pypi.org/project/Surfactant/)
[![Python Versions](https://img.shields.io/pypi/pyversions/surfactant.svg)](https://pypi.org/project/Surfactant/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/LLNL/Surfactant/blob/main/LICENSE)
[![Documentation Status](https://readthedocs.org/projects/surfactant/badge/?version=latest)](https://surfactant.readthedocs.io/en/latest/?badge=latest)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/LLNL/Surfactant/main.svg)](https://results.pre-commit.ci/latest/github/LLNL/Surfactant/main)

[Documentation](https://surfactant.readthedocs.io/en/latest/)

## Description

Surfactant can be used to gather information from a set of files to generate an SBOM, along with manipulating SBOMs and analyzing the information in them. It pulls information from recognized file types (such as PE, ELF, or MSI files) contained within a directory structure corresponding to an extracted software package. By default, the information is "surface-level" metadata contained in the files that does not require running the files
or decompilation.

## Installation

### For Users:

1. Create a virtual environment with python >= 3.8 [Optional, but recommended]

```bash
python -m venv cytrics_venv
source cytrics_venv/bin/activate
```

2. Install Surfactant with pip

```bash
pip install surfactant
```

### For Developers:

1. Create a virtual environment with python >= 3.8 [Optional, but recommended]

```bash
python -m venv cytrics_venv
source cytrics_venv/bin/activate
```

2. Clone sbom-surfactant

```bash
git clone git@github.com:LLNL/Surfactant.git
```

3. Create an editable surfactant install (changes to code will take effect immediately):

```bash
pip install -e .
```

To install optional dependencies required for running pytest and pre-commit:

```bash
pip install -e ".[test,dev]"
```

## Usage

### Identify sample file

In order to test out surfactant, you will need a sample file/folder. If you don't have one on hand, you can download and use the portable .zip file from <https://github.com/ShareX/ShareX/releases> or the Linux .tar.gz file from <https://github.com/GMLC-TDC/HELICS/releases>. Alternatively, you can pick a sample from https://lc.llnl.gov/gitlab/cir-software-assurance/unpacker-to-sbom-test-files

### Build configuration file

A configuration file contains the information about the sample to gather information from. Example JSON configuration files can be found in the examples folder of this repository.

**extractPaths**: (required) the absolute path or relative path from location of current working directory that `surfactant` is being run from to the sample folders, cannot be a file (Note that even on Windows, Unix style `/` directory separators should be used in paths)\
**archive**: (optional) the full path, including file name, of the zip, exe installer, or other archive file that the folders in **extractPaths** were extracted from. This is used to collect metadata about the overall sample and will be added as a "Contains" relationship to all software entries found in the various **extractPaths**\
**installPrefix**: (optional) where the files in **extractPaths** would be if installed correctly on an actual system i.e. "C:/", "C:/Program Files/", etc (Note that even on Windows, Unix style `/` directory separators should be used in the path). If not given then the **extractPaths** will be used as the install paths

#### Create config command

A basic configuration file can be easily built using the `create-config` command. This will take a path as a command line argument and will save a file with the default name of the end directory passed to it as a json file. i.e., `/home/user/Desktop/myfolder` will create `myfolder.json`.

```bash
$  surfactant create-config [INPUT_PATH]
```

The --output flag can be used to specify the configuration output name. The --install-prefix can be used to specify the install prefix, the default is '/'.

```bash
$  surfactant create-config [INPUT_PATH] --output new_output.json --install-prefix 'C:/'
```

#### Example configuration file

Lets say you have a .tar.gz file that you want to run surfactant on. For this example, we will be using the HELICS release .tar.gz example. In this scenario, the absolute path for this file is `/home/samples/helics.tar.gz`. Upon extracting this file, we get a helics folder with 4 sub-folders: bin, include, lib64, and share.

##### Example 1: Simple Configuration File

If we want to include only the folders that contain binary files to analyze, our most basic configuration would be:

```json
[
  {
    "extractPaths": ["/home/samples/helics/bin", "/home/samples/helics/lib64"]
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/home/samples/helics/bin/helics_binary"],
      "containerPath": null
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/home/samples/helics/lib64/lib1.so"],
      "containerPath": null
    }
  ],
  "relationships": [
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    }
  ]
}
```

##### Example 2: Detailed Configuration File

A more detailed configuration file might look like the example below. The resulting SBOM would have a software entry for the helics.tar.gz with a "Contains" relationship to all binaries found to in the extractPaths. Providing the install prefix of `/` and an extractPaths as `/home/samples/helics` will allow to surfactant correctly assign the install paths in the SBOM for binaries in the subfolders as `/bin` and `/lib64`.

```json
[
  {
    "archive": "/home/samples/helics.tar.gz",
    "extractPaths": ["/home/samples/helics"],
    "installPrefix": "/"
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc0",
      "fileName": ["helics.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/bin/helics_binary"],
      "containerPath": ["abc0/bin/helics_binary"]
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/lib64/lib1.so"],
      "containerPath": ["abc0/lib64/lib1.so"]
    }
  ],
  "relationships": [
    {
      "xUUID": "abc0",
      "yUUID": "abc1",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc2",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    }
  ]
}
```

##### Example 3: Adding Related Binaries

If our sample helics tar.gz file came with a related tar.gz file to install a plugin extension module (extracted into a helics_plugin folder that contains bin and lib64 subfolders), we could add that into the configuration file as well:

```json
[
  {
    "archive": "/home/samples/helics.tar.gz",
    "extractPaths": ["/home/samples/helics"],
    "installPrefix": "/"
  },
  {
    "archive": "/home/samples/helics_plugin.tar.gz",
    "extractPaths": ["/home/samples/helics_plugin"],
    "installPrefix": "/"
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc0",
      "fileName": ["helics.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/bin/helics_binary"],
      "containerPath": ["abc0/bin/helics_binary"]
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/lib64/lib1.so"],
      "containerPath": ["abc0/lib64/lib1.so"]
    },
    {
      "UUID": "abc3",
      "fileName": ["helics_plugin.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc4",
      "fileName": ["helics_plugin"],
      "installPath": ["/bin/helics_plugin"],
      "containerPath": ["abc3/bin/helics_plugin"]
    },
    {
      "UUID": "abc5",
      "fileName": ["lib_plugin.so"],
      "installPath": ["/lib64/lib_plugin.so"],
      "containerPath": ["abc3/lib64/lib_plugin.so"]
    }
  ],
  "relationships": [
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc4",
      "yUUID": "abc5",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc5",
      "yUUID": "abc2",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc1",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc2",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc3",
      "yUUID": "abc4",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc3",
      "yUUID": "abc5",
      "relationship": "Contains"
    }
  ]
}
```

NOTE: These examples have been simplified to show differences in output based on configuration.

### Run surfactant

```bash
$  surfactant generate [OPTIONS] CONFIG_FILE SBOM_OUTFILE [INPUT_SBOM]
```

**CONFIG_FILE**: (required) the config file created earlier that contains the information on the sample\
**SBOM OUTPUT**: (required) the desired name of the output file\
**INPUT_SBOM**: (optional) a base sbom, should be used with care as relationships could be messed up when files are installed on different systems\
**--skip_gather**: (optional) skips the gathering of information on files and adding software entires\
**--skip_relationships**: (optional) skips the adding of relationships based on metadata\
**--skip_install_path**: (optional) skips including an install path for the files discovered. This may cause "Uses" relationships to also not be generated\
**--recorded_institution**: (optional) the name of the institution collecting the SBOM data (default: LLNL)\
**--output_format**: (optional) changes the output format for the SBOM (given as full module name of a surfactant plugin implementing the `write_sbom` hook)\
**--input_format**: (optional) specifies the format of the input SBOM if one is being used (default: cytrics) (given as full module name of a surfactant plugin implementing the `read_sbom` hook)\
**--help**: (optional) show the help message and exit

## Understanding the SBOM Output

### Software

This section contains a list of entries relating to each piece of software found in the sample. Metadata including file size, vendor, version, etc are included in this section along with a uuid to uniquely identify the software entry.

### Relationships

This section contains information on how each of the software entries in the previous section are linked.

**Uses**: this relationship type means that x software uses y software i.e. y is a helper module to x\
**Contains**: this relationship type means that x software contains y software (often x software is an installer or archive such as a zip file)

### Observations:

This section contains information about notable observations about individual software components. This could be vulnerabilities, observed features, etc

## Merging SBOMs


A folder containing multiple separate SBOM JSON files can be combined using merge_sbom.py with a command such the one below that gets a list of files using ls, and then uses xargs to pass the resulting list of files to merge_sbom.py as arguments.

`ls -d ~/Folder_With_SBOMs/Surfactant-* | xargs -d '\n' surfactant merge --config_file=merge_config.json --sbom_outfile combined_sbom.json`

If the config file option is given, a top-level system entry will be created that all other software entries are tied to (directly or indirectly based on other relationships). Specifying an empty UUID will make a random UUID get generated for the new system entry, otherwise it will use the one provided.

Details on the merge command can be found in the docs page [here](./docs/basic_usage.md#merging-sboms).

## Plugins

Surfactant supports using plugins to add additional features. For users, installing and enabling a plugin usually just involves
doing a `pip install` of the plugin.

Detailed information on configuration options for the plugin system and how to develop new plugins can be found [here](./docs/plugins.md).

## Support

Full user guides for Surfactant are available [online](https://surfactant.readthedocs.io)
and in the [docs](./docs) directory.

For questions or support, please create a new discussion on [GitHub Discussions](https://github.com/LLNL/Surfactant/discussions/categories/q-a),
or [open an issue](https://github.com/LLNL/Surfactant/issues/new/choose) for bug reports and feature requests.

## Contributing

Contributions are welcome. Bug fixes or minor changes are preferred via a
pull request to the [Surfactant GitHub repository](https://github.com/LLNL/Surfactant).
For more information on contributing see the [CONTRIBUTING](./CONTRIBUTING.md) file.

## License

Surfactant is released under the MIT license. See the [LICENSE](./LICENSE)
and [NOTICE](./NOTICE) files for details. All new contributions must be made
under this license.

SPDX-License-Identifier: MIT

LLNL-CODE-850771
