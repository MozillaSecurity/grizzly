#!/usr/bin/env python
# coding=utf-8
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import itertools
from setuptools import setup


EXTRAS = {
    'reduce': ['lithium-reducer', 'FuzzManager', 'jsbeautifier'],
    's3': ['boto3'],
}
EXTRAS['all'] = list(set(itertools.chain.from_iterable(EXTRAS.values())))
EXTRAS['test'] = ['pytest']


if __name__ == '__main__':
    setup(
        classifiers=[
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Testing',
            'Topic :: Security',
            'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6'
        ],
        description='A framework for developing and running browser fuzzers',
        extras_require=EXTRAS,
        install_requires=['ffpuppet', 'psutil', 'sapphire'],
        license='MPL 2.0',
        maintainer='Tyson Smith',
        maintainer_email='twsmith@mozilla.com',
        name='grizzly',
        packages=[
            'grizzly',
            'grizzly.corpman',
            'grizzly.reduce',
        ],
        url='https://github.com/MozillaSecurity/grizzly',
        version='0.0.1')
