Grizzly
=======

Grizzly is a general purpose browser fuzzer made up of multiple modules.
The intention is to create a platform that can be extended by the creation of adapters to support
different fuzzers that target the browser.
An adapter is used to wrap an existing fuzzer to allow it to be run via Grizzly.
Adapters take the content output by fuzzers and transform it (if needed) into a format that can
be served to and processed by the browser.
Cross platform compatibility should be maintained for Windows, Linux and OSX.
However not all features may be available.

NOTE: Grizzly is under development at the moment and may still undergo major changes.

Installation
------------
The following modules are required:
* https://github.com/MozillaSecurity/ffpuppet
* https://github.com/giampaolo/psutil

The FuzzManager module is required to support reporting results via FM:
 * https://github.com/MozillaSecurity/FuzzManager

FFPuppet must be installed first. Steps can be found [here](https://github.com/MozillaSecurity/ffpuppet#installation)

##### To install after cloning the repository
    pip install --user -e <grizzly_repository>

Usage
-----
```
$ python -m grizzly -h
usage: __main__.py
                   [--accepted-extensions ACCEPTED_EXTENSIONS [ACCEPTED_EXTENSIONS ...]]
                   [-c CACHE] [--coverage] [-e EXTENSION] [--fuzzmanager] [-h]
                   [--ignore IGNORE [IGNORE ...]]
                   [--launch-timeout LAUNCH_TIMEOUT] [--log-limit LOG_LIMIT]
                   [-m MEMORY] [--mime MIME] [-p PREFS] [--relaunch RELAUNCH]
                   [--rr] [--s3-fuzzmanager] [--soft-asserts] [-t TIMEOUT]
                   [--tool TOOL] [--valgrind] [-w WORKING_PATH] [--xvfb]
                   binary input adapter

positional arguments:
  binary                Firefox binary to run
  input                 Test case or directory containing test cases
  adapter               Available adapters: <list of adapters>

optional arguments:
  --accepted-extensions ACCEPTED_EXTENSIONS [ACCEPTED_EXTENSIONS ...]
                        Space separated list of supported file extensions. ie:
                        html svg (default: all)
  -c CACHE, --cache CACHE
                        Maximum number of additional test cases to include in
                        report (default: 0)
  --coverage            Enable coverage collection
  -e EXTENSION, --extension EXTENSION
                        Install an extension. Specify the path to the xpi or
                        the directory containing the unpacked extension. To
                        install multiple extensions specify multiple times
  --fuzzmanager         Report results to FuzzManager
  -h, --help            show this help message and exit
  --ignore IGNORE [IGNORE ...]
                        Space separated ignore list. ie: log-limit memory
                        timeout (default: nothing)
  --launch-timeout LAUNCH_TIMEOUT
                        Number of seconds to wait before LaunchError is raised
                        (default: 300)
  --log-limit LOG_LIMIT
                        Log file size limit in MBs (default: 'no limit')
  -m MEMORY, --memory MEMORY
                        Browser process memory limit in MBs (default: 'no
                        limit')
  --mime MIME           Specify a mime type
  -p PREFS, --prefs PREFS
                        prefs.js file to use
  --relaunch RELAUNCH   Number of iterations performed before relaunching the
                        browser (default: 1000)
  --rr                  Use RR (Linux only)
  --s3-fuzzmanager      Report large attachments (if any) to S3 and then the
                        crash & S3 link to FuzzManager
  --soft-asserts        Detect soft assertions
  -t TIMEOUT, --timeout TIMEOUT
                        Iteration timeout in seconds (default: 60)
  --tool TOOL           Override tool name used when reporting issues to
                        FuzzManager
  --valgrind            Use Valgrind (Linux only)
  -w WORKING_PATH, --working-path WORKING_PATH
                        Working directory. Intended to be used with ram-
                        drives. (default: '/tmp')
  --xvfb                Use Xvfb (Linux only)
```
