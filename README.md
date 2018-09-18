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
* https://github.com/MozillaSecurity/avalanche

For now add symlinks to the project folders and files as needed. NOTE: This will change. I am open to suggestions for how to make this simple. Perhaps submodules?

```
cd grizzly
ln -s <path_to_ffpuppet_dir> ffpuppet
cd corpman
ln -s <path_to_avalanche_dir> avalanche

```

Usage
-----
```
usage: grizzly.py [-h] [-a AGGRESSION] [-c CACHE] [-e EXTENSION]
                  [--fuzzmanager] [--ignore-timeouts]
                  [--launch-timeout LAUNCH_TIMEOUT] [-m MEMORY] [--mime MIME]
                  [-p PREFS] [-q] [-v] [--replay] [--relaunch RELAUNCH]
                  [--rotate ROTATE] [-s] [-t TIMEOUT] [--valgrind] [--windbg]
                  [--xvfb]
                  binary input corpus_manager

positional arguments:
  binary                Firefox binary to run
  input                 Test case or directory containing test cases
  corpus_manager        Available corpus managers: audio, image,
                        video, font ... all available corpus managers

optional arguments:
  -h, --help            show this help message and exit
  -a AGGRESSION, --aggression AGGRESSION
                        0.001 == 1/1000 (default: 0.001)
  -c CACHE, --cache CACHE
                        Maximum number of previous test cases to dump after
                        crash (default: 1)
  -e EXTENSION, --extension EXTENSION
                        Install the fuzzPriv extension (specify path to
                        funfuzz/dom/extension)
  --fuzzmanager         Report results to FuzzManager
  --ignore-timeouts     Don't save the logs/results from a timeout
  --launch-timeout LAUNCH_TIMEOUT
                        Number of seconds to wait before LaunchError is raised
                        (default: 300)
  -m MEMORY, --memory MEMORY
                        Browser process memory limit in MBs (default: No
                        limit)
  --mime MIME           Specify a mime type
  -p PREFS, --prefs PREFS
                        prefs.js file to use
  -q, --quiet           Output is minimal
  -v, --verbose         Output is less minimal
  --replay              Replay do not fuzz the test cases
  --relaunch RELAUNCH   Number of iterations performed before relaunching the
                        browser (default: 1000)
  --rotate ROTATE       Number of iterations per test case before rotating
                        (default: 10)
  -s, --asserts         Detect soft assertions
  -t TIMEOUT, --timeout TIMEOUT
                        Iteration timeout in seconds (default: 60)
  --valgrind            Use valgrind
  --windbg              Collect crash log with WinDBG (Windows only)
  --xvfb                Use xvfb (Linux only)
```
