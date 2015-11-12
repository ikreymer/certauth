#!/usr/bin/env python
# vim: set sw=4 et:

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_suite = True
        self.test_args = []

    def run_tests(self):
        import pytest
        import sys
        import os
        cmdline = ' --cov certauth -v test/'
        errcode = pytest.main(cmdline)
        sys.exit(errcode)

setup(
    name='certauth',
    version='1.1.2',
    author='Ilya Kreymer',
    author_email='ikreymer@gmail.com',
    license='MIT',
    packages=find_packages(),
    url='https://github.com/ikreymer/certauth',
    description='Simple Certificate Authority for MITM proxies',
    long_description=open('README.rst').read(),
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
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
    ]
)
