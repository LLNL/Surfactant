import os
import sys

import requests

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


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

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.githubpages",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "images.toml"]

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

# -- Extension configuration -------------------------------------------------

# Napoleon settings for NumPy and Google style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
html_logo = "./logos/surfactant-logo-light.png"
html_favicon = html_logo
html_sidebars = {"**": ["globaltoc.html", "relations.html", "searchbox.html"]}
html_static_path = ["_static"]


# -- Fetch image references --------------------------------------------------
# Download all of the image files referenced in images.toml
def download_images_from_toml(toml_file, image_dir):
    with open(toml_file, "rb") as f:
        data = tomllib.load(f)

    if not os.path.exists(image_dir):
        os.makedirs(image_dir)

    for file_name, url in data.get("images", {}).items():
        if file_name and url:
            response = requests.get(url)
            if response.status_code == 200:
                with open(os.path.join(image_dir, file_name), "wb") as img_file:
                    img_file.write(response.content)
            else:
                print(f"Failed to download {url}")


# Path to the TOML file
toml_file_path = os.path.join(os.path.dirname(__file__), "images.toml")
# Directory to save the images
image_directory = os.path.join(os.path.dirname(__file__), "img")

# Download images
download_images_from_toml(toml_file_path, image_directory)

# -------------------------------------------------------------------
# Make database_sources.toml available as a static file at the site root
# https://surfactant.readthedocs.io/en/latest/database_sources.toml
# -------------------------------------------------------------------
html_extra_path = ["database_sources.toml"]
