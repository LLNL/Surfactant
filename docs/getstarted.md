# Getting Started

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

## Understanding the SBOM Output

### Software

This section contains a list of entries relating to each piece of software found in the sample. Metadata including file size, vendor, version, etc are included in this section along with a uuid to uniquely identify the software entry.

### Relationships

This section contains information on how each of the software entries in the previous section are linked.

**Uses**: this relationship type means that x software uses y software i.e. y is a helper module to x\
**Contains**: this relationship type means that x software contains y software (often x software is an installer or archive such as a zip file)
### Observations

TODO: Section information
