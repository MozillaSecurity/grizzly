Grizzly
=======
[![Task Status](https://community-tc.services.mozilla.com/api/github/v1/repository/MozillaSecurity/grizzly/master/badge.svg)](https://community-tc.services.mozilla.com/api/github/v1/repository/MozillaSecurity/grizzly/master/latest)
[![codecov](https://codecov.io/gh/MozillaSecurity/grizzly/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/grizzly)
[![Matrix](https://img.shields.io/badge/dynamic/json?color=green&label=chat&query=%24.chunk[%3F(%40.canonical_alias%3D%3D%22%23fuzzing%3Amozilla.org%22)].num_joined_members&suffix=%20users&url=https%3A%2F%2Fmozilla.modular.im%2F_matrix%2Fclient%2Fr0%2FpublicRooms&style=flat&logo=matrix)](https://riot.im/app/#/room/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/grizzly-framework)](https://pypi.org/project/grizzly-framework)

Grizzly is a modular general purpose browser fuzzing framework. The goal is to create a platform that can be extended via the creation of plug-ins to support multiple combinations of browsers and fuzzers. An Adapter is used to add support for a fuzzer and a Target to add support for a browser. Generated test cases are intended to be standalone and not require Grizzly.

Cross platform compatibility is available for Windows, Linux and MacOS.
However not all features may be available.

For additional information please check out the [wiki](https://github.com/MozillaSecurity/grizzly/wiki) or the [announcement](https://blog.mozilla.org/security/2019/07/10/grizzly/).

Quick Start
------------
Install the latest version from PyPI. For more details see [getting started](https://github.com/MozillaSecurity/grizzly/wiki/Getting-Started) on the wiki.

```python3 -m pip install grizzly-framework```

**Fuzz** - Run the `no-op` test adapter to check everything is working.

```python3 -m grizzly <browser-binary> no-op```

**Reduce** - [Grizzly Reduce](https://github.com/MozillaSecurity/grizzly/wiki/Grizzly-Reduce) can reduce a test case.

```python3 -m grizzly.reduce <browser-binary> <testcase>```

**Replay** - [Grizzly Replay](https://github.com/MozillaSecurity/grizzly/wiki/Grizzly-Replay) can replay a test case with different builds and debuggers.

```python3 -m grizzly.replay <browser-binary> <testcase>```
