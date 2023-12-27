# Configuration Files

There are several files for configuring different aspects of Surfactant functionality based on the subcommand used.
This page currently describes the format for the file used to generate an SBOM, but will eventually cover other
configuration files as well.

## Build configuration file

A configuration file contains the information about the sample to gather information from. Example JSON configuration files can be found in the examples folder of this repository.

**extractPaths**: (required) the absolute path or relative path from location of current working directory that `surfactant` is being run from to the sample folders, cannot be a file (Note that even on Windows, Unix style `/` directory separators should be used in paths)\
**archive**: (optional) the full path, including file name, of the zip, exe installer, or other archive file that the folders in **extractPaths** were extracted from. This is used to collect metadata about the overall sample and will be added as a "Contains" relationship to all software entries found in the various **extractPaths**\
**installPrefix**: (optional) where the files in **extractPaths** would be if installed correctly on an actual system i.e. "C:/", "C:/Program Files/", etc (Note that even on Windows, Unix style `/` directory separators should be used in the path). If not given then the **extractPaths** will be used as the install paths

## Example configuration files

Lets say you have a .tar.gz file that you want to run surfactant on. For this example, we will be using the HELICS release .tar.gz example. In this scenario, the absolute path for this file is /home/samples/helics.tar.gz. Upon extracting this file, we get a helics folder with 4 sub-folders: bin, include, lib64, and share.

### Example 1: Simple Configuration File

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

### Example 2: Detailed Configuration File

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

### Example 3: Adding Related Binaries

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
