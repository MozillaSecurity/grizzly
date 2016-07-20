Grizzly
=======

Grizzly is a general purpose browser fuzzer made of up of multiple modules. The intention is to create a platform that can be extended by the creation of corpus managers to fuzz different components of the browsers.
Grizzly is not meant to be much more than the automation glue code between the modules.
A corpus manager is used to wrap an existing fuzzer to allow it to be run with grizzly. Corpus managers take the content output by fuzzers and transform it into a format that can be served to and processed by a browser.
Cross platform compatibility should be maintained for Windows, Linux and OSX. However not all features may be available.

NOTE: Grizzly is under development at the moment and may still undergo major changes.

Installation
------------
The following modules are required:
* https://github.com/MozillaSecurity/ffpuppet
* https://github.com/MozillaSecurity/loki
* https://github.com/MozillaSecurity/sapphire
* https://github.com/MozillaSecurity/avalanche

For now add symlinks to the project folders and files as needed. NOTE: This will change. I am open to suggestions for how to make this simple. Perhaps submodules?

```
cd grizzly
ln -s <path_to_ffpuppet_dir> ffpuppet
ln -s <path_to_sapphire_dir> sapphire
cd corpman
ln -s <path_to_loki_dir> loki
ln -s <path_to_avalanche_dir> avalanche

```

The python psutil is module is also required if you use memory limiting.

Usage
-----
```
python grizzly.py -h
usage: grizzly.py [-h] [-a AGGRESSION] [-c CACHE] [-l LOG] [-m MEMORY]
                  [--mime MIME] [-p PREFS] [-q] [--replay]
                  [--relaunch RELAUNCH] [--rotate ROTATE] [-s]
                  [--timeout TIMEOUT] [--valgrind] [--xvfb]
                  binary input corpus_manager

positional arguments:
  binary                Firefox binary to run
  input                 Test case or directory containing test cases
  corpus_manager        Supported corpus managers: audio, image_basic, image,
                        avalanche, video, font... all available corpus managers

optional arguments:
  -h, --help            show this help message and exit
  -a AGGRESSION, --aggression AGGRESSION
                        0.001 == 1/1000
  -c CACHE, --cache CACHE
                        Maximum number of previous test cases to dump after
                        crash
  -l LOG, --log LOG     log file name
  -m MEMORY, --memory MEMORY
                        Firefox process memory limit in MBs
  --mime MIME           Specify a mime type
  -p PREFS, --prefs PREFS
                        prefs.js file to use
  -q, --quiet           Output is minimal
  --replay              Replay do not fuzz the test cases
  --relaunch RELAUNCH   Number of iterations to perform before closing and
                        relaunching the browser
  --rotate ROTATE       Number of iterations per test case before switching
  -s, --asserts         Detect soft assertions
  --timeout TIMEOUT     Iteration timeout
  --valgrind            Use valgrind
  --xvfb                Use xvfb
```
