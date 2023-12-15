# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Surfactant"
# pylint: disable-next=redefined-builtin
copyright = "2023, Lawrence Livermore National Security"
author = "Ryan Mast, Kendall Harter, Micaela Gallegos, Shayna Kapadia, Apoorv Pochiraju, Alexander Armstrong, Levi Lloyd"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["myst_parser"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "alabaster"
html_theme_options = {
    "description": "Surfactant",
    "github_user": "LLNL",
    "github_repo": "Surfactant",
    "github_button": "true",
    "github_banner": "true",
    "badge_branch": "main",
    "fixed_sidebar": "false",
}
html_logo = "./logos/surfactant-logo-light.png"
html_favicon = html_logo
html_sidebars = {"**": ["globaltoc.html", "relations.html", "searchbox.html"]}
html_static_path = ["_static"]
