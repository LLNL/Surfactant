# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from setuptools import setup

setup(
    # Other fields
    extras_require={
        "docs": [
            "Sphinx>=4.0",  # Documentation generator
            "sphinx-rtd-theme",  # Read the Docs theme
            "surfactant @ file:.\Surfactant",  # Specify path if needed
            "sphinx.ext.autodoc",  # For automatic API documentation
            "sphinx.ext.napoleon",  # For Google style docstrings
            "sphinx.ext.viewcode",  # To include source code in documentation
            "sphinx.ext.intersphinx",  # For linking to other projects' documentation
            "sphinx.ext.githubpages",  # For GitHub Pages integration
        ]
    },
    # Other setup fields as needed (author, description, etc.)
)
