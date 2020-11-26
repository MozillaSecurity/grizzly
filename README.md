Grizzly
=======
[![Build Status](https://travis-ci.com/MozillaSecurity/grizzly.svg?branch=master)](https://travis-ci.com/MozillaSecurity/grizzly)
[![codecov](https://codecov.io/gh/MozillaSecurity/grizzly/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/grizzly)
[![Matrix](https://img.shields.io/badge/dynamic/json?color=green&label=chat&query=%24.chunk[%3F(%40.canonical_alias%3D%3D%22%23fuzzing%3Amozilla.org%22)].num_joined_members&suffix=%20users&url=https%3A%2F%2Fmozilla.modular.im%2F_matrix%2Fclient%2Fr0%2FpublicRooms&style=flat&logo=matrix)](https://riot.im/app/#/room/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/grizzly-framework)](https://pypi.org/project/grizzly-framework)

Grizzly is a general purpose browser fuzzing framework made up of multiple modules.
The intention is to create a platform that can be extended by the creation of adapters
and targets to support different fuzzers that target browsers.
An adapter is used to wrap an existing fuzzer to allow it to be run via Grizzly.
Adapters take the content output by fuzzers and transform it (if needed) into a format that can
be served to and processed by the browser.
Cross platform compatibility is available for Windows, Linux and MacOS.
However not all features may be available.

For additional information please check out the [wiki](https://github.com/MozillaSecurity/grizzly/wiki) or the [announcement](https://blog.mozilla.org/security/2019/07/10/grizzly/).

Installation
------------
To install the latest version from PyPI run `python3 -m pip install grizzly-framework`. See [getting started](https://github.com/MozillaSecurity/grizzly/wiki/Getting-Started) on the wiki for more details.

Target platforms
-------
Other target platforms can be defined as [setuptools entry-points](https://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins),
using the name "grizzly_targets".  Targets must implement `grizzly.target.Target`.
