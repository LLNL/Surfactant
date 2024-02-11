# Scripts

## retirejs_db.py

Running this script retrieves vulnerability information from various javascript libraries from
[retire.js](https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository-master.json)
and only keeps the contents under each library's "extractors" section, which contains regexes
relevant for detecting a specific javascript library.

The resulting smaller json is written to `reduced.json` in the same directory. This smaller file
will be read from to make the checks later on.
