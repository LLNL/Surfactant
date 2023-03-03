# SBOM Surfactant

## Name
SBOM Surfactant

## Description
This project contains scripts that can be used to generate a surface-level, face-value, SBOM.  It pulls information from the PE files contained within a directory structure corresponding to an extracted software package.

## Installation
1. Create a virtual environment with python >= 3.8
```bash
$ python -m venv cytrics_venv
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
$ pip install -r sbom-surfactant/requirements
```
## Usage
### Download sample file
In order to test out surfactant, you will need a sample file/folder. If you don't have one on hand, you can download use the portable .zip from here: https://github.com/ShareX/ShareX/releases or the Linux .tar.gx file from here https://github.com/GMLC-TDC/HELICS/releases. Or any previous CyTRICS sample will do.

### Build configuration file
A configuration file contains the information about the sample you are providing. Examples can be found in the sbom-surfactant/examples folder

**extractPaths**: (required) the absolute path or relative path from location of generate_cytrics_sbom.py of the sample folders, cannot be a file\
**archive**: (optional) the name of the zip, exe, or other file extension\
**installPrefix**: (optional) where the file would be if installed correctly i.e. "C://"\
**containerPath**: (optional) uuid and path within the container (zip, or installer file), if provided\

### Run surfactant
```bash
$  python generate_cytrics_sbom.py [-h] [-i INPUT_SBOM] [--skip_gather] [--skip_relationships] [CONFIG_FILE] [SBOM_OUTPUT]
```
**CONFIG_FILE**: (required) the config file created earlier that contains the information on the sample\
**SBOM OUTPUT**: (required) the desired name of the output file\
**INPUT_SBOM**: (optional) a base sbom, should be used with care as relationships could be messed up when files are installed on different systems\
**skip_gather**: (optional) skips the gathering of information on files and adding software entires\
**skip_relationships**: (optional) skips the adding relationships based on metadata\

## Understanding the SBOM Output

### Software
This section contains a list of entries relating two each piece of software found in the sample. Metadata including size, vendor, version etc are included in this section along with a uuid. 
### Relationships
This section contains information on how each of the software entries in the previous section are linked.

**Uses**: this relationship type means that x software uses y software\
**Contains**: this relationship type means that x software contains y software\
### Observations:
This section contains information about notable observations about individual software components. This could be vulnerabilities, observed features, etc
## Support
For questions or support, contact TODO: who should be contacted for help
