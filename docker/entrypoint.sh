#!/bin/bash -ex
PREFS=/code/browsers/prefs.js

# Download a Firefox ASan fuzzing build
python -m fuzzfetch -a -n firefox --fuzzing -o /code/browsers/

# Download a pref.js from fuzzdata
wget -O $PREFS  https://raw.githubusercontent.com/MozillaSecurity/fuzzdata/master/settings/firefox/prefs-default-e10s.js

# Runs 'no-op' example adapter
python -m grizzly /code/browsers/firefox/firefox no-op -p $PREFS
