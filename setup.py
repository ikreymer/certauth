#!/usr/bin/env python
# vim: set sw=4 et:

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_suite = True

    def run_tests(self):
        import pytest
        import sys
        import os
        cmdline = ' --cov certauth -v test/'
        errcode = pytest.main(cmdline)
        sys.exit(errcode)

setup(
    name='certauth',
    version='1.0',
    author='Ilya Kreymer',
    author_email='ikreymer@gmail.com',
    license='MIT',
    packages=find_packages(),
    description='Simple Certificate Authority for MITM proxies',
    long_description='Simple Certificate Authority for MITM proxies',
    provides=[
        'certauth',
        ],
    install_requires=[
        'pyopenssl',
        ],
    zip_safe=True,
    entry_points="""
        [console_scripts]
        certauth = certauth.certauth:main
    """,
    cmdclass={'test': PyTest},
    test_suite='',
    tests_require=[
        'pytest',
        'pytest-cov',
    ])
