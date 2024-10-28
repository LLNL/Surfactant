# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

# Add custom paths for modules
sys.path.insert(0, os.path.abspath("../plugins"))
sys.path.insert(1, os.path.abspath("../scripts"))
sys.path.insert(2, os.path.abspath("../Surfactant"))
# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Surfactant Documentation"
copyright = "2024, surfactant"
author = "surfactant"
release = "1.0.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",  # Automatically generate documentation from docstrings
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.githubpages",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# -- Extension configuration -------------------------------------------------

# Napoleon settings for NumPy and Google style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True

# To include todos in the output
todo_include_todos = True

# Intersphinx mapping example (adjust as needed)
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
