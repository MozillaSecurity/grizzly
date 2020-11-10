#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Grizzly setup"""
from os.path import dirname, join as pathjoin
from itertools import chain
from setuptools import setup


EXTRAS = {
    'reduce': ['cssbeautifier', 'lithium-reducer>=0.4.3', 'jsbeautifier'],
    's3': ['boto3'],
}
EXTRAS['all'] = list(set(chain.from_iterable(EXTRAS.values())))
EXTRAS['test'] = ['pytest>=3.9', 'pytest-cov', 'pytest-mock']


if __name__ == '__main__':
    with open(pathjoin(dirname(__file__), 'README.md'), 'r') as infp:
        README = infp.read()
    setup(
        classifiers=[
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Testing',
            'Topic :: Security',
            'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8'
        ],
        description='A framework for developing and running browser fuzzers',
        entry_points={
            'console_scripts': [
                'grizzly = grizzly.main:console_main',
                'grizzly.status = grizzly.common.status_reporter:main',
            ],
            'grizzly_targets': [
                'ffpuppet = grizzly.target.puppet_target:PuppetTarget',
            ],
            'grizzly_reduce_strategies': [
                'chars = grizzly.reduce.strategies:MinimizeChars',
                'check = grizzly.reduce.strategies:Check',
                'collapsebraces = grizzly.reduce.strategies:CollapseEmptyBraces',
                'cssbeautify = grizzly.reduce.strategies:CSSBeautify',
                'jsbeautify = grizzly.reduce.strategies:JSBeautify',
                'jschars = grizzly.reduce.strategies:MinimizeJSChars',
                'lines = grizzly.reduce.strategies:MinimizeLines',
                'list = grizzly.reduce.strategies:MinimizeTestcaseList',
            ],
        },
        extras_require=EXTRAS,
        install_requires=[
            'fasteners',
            'ffpuppet',
            'FuzzManager',
            'prefpicker',
            'psutil'
        ],
        keywords='firefox framework fuzz fuzzing test testing',
        license='MPL 2.0',
        long_description=README,
        long_description_content_type='text/markdown',
        maintainer='Mozilla Fuzzing Team',
        maintainer_email='fuzzing@mozilla.com',
        name='grizzly-framework',
        packages=[
            'grizzly',
            'grizzly.adapters',
            'grizzly.adapters.NoOpAdapter',
            'grizzly.common',
            'grizzly.reduce',
            'grizzly.replay',
            'grizzly.target',
            'loki',
            'sapphire',
        ],
        package_data={"grizzly.common": ["harness.html"]},
        url='https://github.com/MozillaSecurity/grizzly',
        version='0.9.8')
