# SBOM Surfactant

## Name
SBOM Surfactant

## Description
This project contains scripts that can be used to generate a surface-level, face-value, SBOM.  It pulls information from the PE files contained within a directory structure corresponding to an extracted software package.

## Installation
1. Clone sbom-surfactant with submodules
```bash
$ git clone ssh://git@czgitlab.llnl.gov:7999/cir-software-assurance/sbom-surfactant.git
```

2. Install python-longclaw module
```bash
$ git clone ssh://git@czgitlab.llnl.gov:7999/cir-software-assurance/python-longclaw.git
$ pip install -e python-longclaw
```

3. Install other required python modules:
```bash
$ pip install -r requirements
```
## Usage
The first step is to produce a list of filepaths to include in the SBOM.  We do this by finding all the PE files in an extracted directory
```bash
$ find ./extracted -type f | xargs file | egrep "\:.+PE" | awk '{ print $1 }' | sort > files.txt
```

Next we extract the metadata from the files:
```bash
$ python extract_file_info.py files.txt > metadata.csv
```

Edit the doc and package attributes in the generate_sbom.py file to suit your needs and then generate the SBOM:
```bash
$ python generate_sbom.py output.csv > example.sbom.json
```

## Support
For questions or support, contact lloyd27@llnl.gov
