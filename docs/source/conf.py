import os
import sys
sys.path.insert(0, os.path.abspath('../..'))

project = 'Pyroughtime'
copyright = '2019-2024 Marcus Dansarie'
author = 'Marcus Dansarie'
release = '0.11.0'
version = '0.11.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon'
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'alabaster'
html_static_path = ['_static']
# html_sidebars = {
#     '**': [
#         'about.html',
#         'searchfield.html',
#         'navigation.html',
#         'relations.html',
#         'donate.html',
#     ]
# }
