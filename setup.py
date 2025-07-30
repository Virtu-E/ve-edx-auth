#!/usr/bin/env python
import os
from setuptools import find_packages, setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='ve-edx-auth',
    version='2.0.2',
    packages=find_packages(),
    include_package_data=True,
    description='An Edx app to get users token from Edu Vault backend',
    url='https://github.com/Virtu-E/ve-edx-auth',
    author='Virtu Educate',
    author_email='kkamundi@gmail.com',
    install_requires=[
        'django>=1.8'
    ],
    entry_points={
        'lms.djangoapp': [
            've_edx_vault = ve_edx_vault.apps:EdxAuthApp',
        ],
    },
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
