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

TODO: Section information

### Relationships

TODO: Section information

### Observations

TODO: Section information
