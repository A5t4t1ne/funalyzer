# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import os
import sys
sys.path.insert(0, os.path.abspath('../../..'))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Funalyzer'
copyright = '2025, A5t4t1ne'
author = 'A5t4t1ne'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    # 'sphinx.ext.napoleon',  # For Google-style or NumPy-style docstrings
    # 'numpydoc',
    'sphinx.ext.autosummary',
]


templates_path = ['_templates']
exclude_patterns = ['*binaryninja*']

autodoc_mock_imports = ['binaryninjaui', 'PySide6']


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']


