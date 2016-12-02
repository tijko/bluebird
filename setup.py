#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup, Extension, find_packages
except ImportError:
    from distutils.core import setup, Extension


setup( 
    name='bluebird',
    version='0.0.1',
    author='Tim Konick',
    description='Allows access to running process internals',
    install_requires=['pyelftools'],
    py_modules=['bluebird'],
    ext_modules=[Extension('bluebird_cext', 
                 sources=['bluebird_cext/bluebird_cext.c'])]
)
