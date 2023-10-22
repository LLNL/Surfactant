# Contributing Guidelines

Thank you for considering contributing to our project! We appreciate your help.

## Reporting Issues

If you find a bug or have a feature request, please [open a new issue](https://github.com/LLNL/Surfactant/issues) and provide detailed information about the problem.

## Making Contributions

We welcome contributions from the community. To contribute to this project, follow these steps:

1. Fork the repository on GitHub.
2. Clone your forked repository to your local machine.

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
