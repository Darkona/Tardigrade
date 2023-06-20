from distutils.core import setup
from setuptools import find_packages
import os

# Optional project description in README.md:
current_directory = os.path.dirname(os.path.abspath(__file__))

try:
    with open(os.path.join(current_directory, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except Exception:
    long_description = ''
setup(

# Project name:
name='Tardigrade',

# Packages to include in the distribution:
packages=find_packages(','),

# Project version number:
version='1.0',

# List a license for the project, eg. MIT License
license='',

# Short description of your library:
description='Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing, meant for development work and simple testing',

# Long description of your library:
long_description='see README.md',
long_description_content_type='text/markdown',

# Your name:
author='Javier Darkona',

# Your email address:
author_email='Javier.Darkona@Gmail.com',

# Link to your github repository or website:
url='https://github.com/Darkona/Tardigrade',

# Download Link from where the project can be downloaded from:
download_url='https://github.com/Darkona/Tardigrade/releases',

# List of keywords:
keywords=["http", "postman", "files", "devtool"],

# List project dependencies:
install_requires=["simplejson", "psutil", "setuptools"],

# https://pypi.org/classifiers/
classifiers=["Development Status :: 4 - Beta"]
)