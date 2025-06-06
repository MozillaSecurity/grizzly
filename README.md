Grizzly
=======
[![CI](https://github.com/MozillaSecurity/grizzly/actions/workflows/ci.yml/badge.svg)](https://github.com/MozillaSecurity/grizzly/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MozillaSecurity/grizzly/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/grizzly)
[![Matrix](https://img.shields.io/badge/chat-%23fuzzing-green?logo=matrix)](https://matrix.to/#/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/grizzly-framework)](https://pypi.org/project/grizzly-framework)

Grizzly is a modular general purpose browser fuzzing framework. The goal is to create a platform that can be extended via the creation of plug-ins to support multiple combinations of browsers and fuzzers. An Adapter is used to add support for a fuzzer and a Target to add support for a browser. Generated test cases are intended to be standalone and not require Grizzly.

Cross platform compatibility is available for Windows, Linux and MacOS.
However not all features may be available.

For additional information please check out the [wiki](https://github.com/MozillaSecurity/grizzly/wiki) or the [announcement](https://blog.mozilla.org/security/2019/07/10/grizzly/).

Quick Start
-----------
Install the latest version from PyPI. For more details see [getting started](https://github.com/MozillaSecurity/grizzly/wiki/Getting-Started) on the wiki.

```
python3 -m pip install grizzly-framework --upgrade
```

**Fuzzing** - Run the `no-op` test adapter to check everything is working.

```
grizzly <browser-binary> no-op
```

**Reduce** - [Grizzly Reduce](https://github.com/MozillaSecurity/grizzly/wiki/Grizzly-Reduce) can reduce a test case.

```
grizzly-reduce <browser-binary> <testcase>
```

**Replay** - [Grizzly Replay](https://github.com/MozillaSecurity/grizzly/wiki/Grizzly-Replay) can replay a test case with different builds and debuggers.

```
grizzly-replay <browser-binary> <testcase>
```

[Bugzilla](https://bugzilla.mozilla.org/) is also supported by Grizzly Replay. Bugs can be replayed via a bug ID:

```
grizzly-replay-bugzilla <browser-binary> <bug_id>
```

Questions
---------

Common questions can be found on the [Q&A](https://github.com/MozillaSecurity/grizzly/wiki/Q&A) page.
Questions can also be asked in the [#fuzzing](https://riot.im/app/#/room/#fuzzing:mozilla.org) channel.

Please be sure you are using the latest version Grizzly before reporting issues.
