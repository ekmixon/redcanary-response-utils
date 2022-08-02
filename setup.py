#!/usr/bin/env python

from setuptools import setup, find_packages
import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def find_scripts():
    exclude = ['setup.py']
    return [
        file.name
        for file in os.scandir('.')
        if file.name.endswith('.py')
        and file.is_file()
        and (file.name not in exclude)
    ]


setup(
    name='redcanary-response-utils',
    author='Keith McCammon',
    author_email='keith@redcanary.com',
    url='https://github.com/redcanaryco/redcanary-response-utils',
    license='MIT',
    packages=find_packages(),
    scripts=find_scripts(),
    description='Tools to automate and/or expedite response.',
    version='0.1',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: Freely Distributable',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        ],
    install_requires=[
        'cbapi'
        ]
    )
