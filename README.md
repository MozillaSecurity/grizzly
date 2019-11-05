Grizzly
=======
[![Build Status](https://travis-ci.org/MozillaSecurity/grizzly.svg?branch=master)](https://travis-ci.org/MozillaSecurity/grizzly)
[![codecov](https://codecov.io/gh/MozillaSecurity/grizzly/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/grizzly)
[![IRC](https://img.shields.io/badge/IRC-%23fuzzing-1e72ff.svg?style=flat)](https://www.irccloud.com/invite?channel=%23fuzzing&amp;hostname=irc.mozilla.org&amp;port=6697&amp;ssl=1)

Grizzly is a general purpose browser fuzzing framework made up of multiple modules.
The intention is to create a platform that can be extended by the creation of adapters
and targets to support different fuzzers that target browsers.
An adapter is used to wrap an existing fuzzer to allow it to be run via Grizzly.
Adapters take the content output by fuzzers and transform it (if needed) into a format that can
be served to and processed by the browser.
Cross platform compatibility is available for Windows, Linux and OSX.
However not all features may be available.

For additional information please check out the [wiki](https://github.com/MozillaSecurity/grizzly/wiki) or the [announcement](https://blog.mozilla.org/security/2019/07/10/grizzly/)

Installation
------------
See [getting started](https://github.com/MozillaSecurity/grizzly/wiki/Getting-Started) on the wiki.

Target platforms
-------
Other target platforms can be defined as [setuptools entry-points](https://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins),
using the name "grizzly_targets".  Targets must implement `grizzly.target.Target`.
