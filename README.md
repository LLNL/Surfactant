# SBOM Surfactant

## Name
SBOM Surfactant

## Description
This project contains scripts that can be used to generate a surface-level, face-value, SBOM.  It pulls information from the PE files contained within a directory structure corresponding to an extracted software package.

## Installation
1. Create a virtual environment with python >= 3.8
```bash
$ python -m venv cytrics_venv
$ source cytrics_venv/bin/activate
```

2. Clone sbom-surfactant
```bash
$ git clone ssh://git@czgitlab.llnl.gov:7999/cir-software-assurance/sbom-surfactant.git
```
OR
```bash
$ git clone https://lc.llnl.gov/gitlab/cir-software-assurance/sbom-surfactant.git
```

3. Install other required python modules:
```bash
$ pip install -r sbom-surfactant/requirements.txt
```

## Usage
### Identify sample file
In order to test out surfactant, you will need a sample file/folder. If you don't have one on hand, you can download and use the portable .zip file from <https://github.com/ShareX/ShareX/releases> or the Linux .tar.gz file from <https://github.com/GMLC-TDC/HELICS/releases>. Or any previous CyTRICS sample will do.

### Build configuration file
A configuration file contains the information about the sample to gather information from. Example JSON configuration files can be found in the examples folder of this repository.

**extractPaths**: (required) the absolute path or relative path from location of current working directory that generate_cytrics_sbom.py is being run from to the sample folders, cannot be a file\
**archive**: (optional) the full path, including file name, of the zip, exe installer, or other archive file that the folders in **extractPaths** were extracted from. This is used to collect metadata about the overall sample and will be added as a "Contains" relationship to all software entries found in the various **extractPaths**\
**installPrefix**: (optional) where the files in **extractPaths** would be if installed correctly on an actual system i.e. "C:/", "C:/Program Files/", etc

#### Example configuration file
Lets say you have a .tar.gz file that you want to run surfactant on. For this example, we will be using the HELICS release .tar.gz example. In this scenario, the absolute path for this file is "/home/samples/helics.tar.gz". Upon extracting this file, we get a helics folder with 4 sub-folders: bin, include, lib64, and share. If we want to include only the folders that contain binary files to analyze, our most basic configuration would be:
```json
{
  [
    {
      "extractPaths": [
        "/home/samples/helics/bin",
        "/home/samples/helics/lib64"
      ]
    }
  ]
}
```
A more detailed configuration file that also has a software entry for helics.tar.gz with a "Contains" relationship to all binaries found to in the extractPaths, and an install prefix of `/` so that the install paths for binaries in the subfolders will be `/bin` and `/lib64` might look something like this:
```json
{
  [
    {
      "archive": "/home/samples/helics.tar.gz",
      "extractPaths": [
        "/home/samples/helics"
      ],
      "installPrefix": "/"
    }
  ]
}
```
If our sample helics tar.gz file came with a related zip file to install a helper module (extracted into a helper_module folder that contains bin and lib64 subfolders), we could add that into the configuration file as well:
```json
{
  [
    {
      "archive": "/home/samples/helics.zip",
      "extractPaths": [
        "/home/samples/helics"
      ],
      "installPrefix": "/"
    },
    {
      "archive": "/home/samples/helper_module.zip",
      "extractPaths": [
        "/home/samples/helper_module"
      ],
      "installPrefix": "/"
    }
  ]
}
```

### Run surfactant
```bash
$  python generate_cytrics_sbom.py [-h] [-i INPUT_SBOM] [--skip_gather] [--skip_relationships] [CONFIG_FILE] [SBOM_OUTPUT]
```
**CONFIG_FILE**: (required) the config file created earlier that contains the information on the sample\
**SBOM OUTPUT**: (required) the desired name of the output file\
**INPUT_SBOM**: (optional) a base sbom, should be used with care as relationships could be messed up when files are installed on different systems\
**skip_gather**: (optional) skips the gathering of information on files and adding software entires\
**skip_relationships**: (optional) skips the adding of relationships based on metadata

## Understanding the SBOM Output
### Software
This section contains a list of entries relating to each piece of software found in the sample. Metadata including file size, vendor, version, etc are included in this section along with a uuid to uniquely identify the software entry. 

### Relationships
This section contains information on how each of the software entries in the previous section are linked.

**Uses**: this relationship type means that x software uses y software\
**Contains**: this relationship type means that x software contains y software (often x software is an installer or archive such as a zip file)

### Observations:
This section contains information about notable observations about individual software components. This could be vulnerabilities, observed features, etc

## Merging SBOMs
TODO: Insert documentation on how to merge sboms here

## Support
For questions or support, contact TODO: who should be contacted for help
