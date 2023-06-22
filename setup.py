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
with open(os.path.join("src", 'VERSION')) as version_file:
    version = version_file.read().strip()
setup(

    name='tardigrade',
    packages=find_packages('tardigrade'),
    package_data={'tardigrade': ['README.md', 'input/*.*', 'config/config.yaml', 'postman/*.*']},
    version=version,
    license='MIT License',
    description='Small footprint SimpleHTTPServer implementation with nice logging and POST requests processing, meant for development work and simple testing',
    long_description='',
    long_description_content_type='text/markdown',
    author='Javier Darkona',
    author_email='Javier.Darkona@Gmail.com',
    url='https://github.com/Darkona/Tardigrade',
    download_url='https://github.com/Darkona/Tardigrade/releases',
    keywords=["http", "postman", "files", "devtool"],
    python_requires='>=3.11',
    install_requires=["simplejson", "psutil", "setuptools", "PyYAML"],
    classifiers=["Programming Language :: Python :: 3",
                 "License :: OSI Approved :: MIT License",
                 "Operating System :: Windows"]
)
