# Scripts

## get_retirejs_db.py

Running this script retrieves the javascript library CVE database used by
[retire.js](https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository-master.json)
and only keeps the contents under each library's "extractors" section, which contains file hashes and
regexes relevant for detecting a specific javascript library by its file name or contents.

The resulting smaller json is written to `js_library_patterns.json` in the same directory. This smaller file
will be read from to make the checks later on.

## match_javascript.py

This is an example script that retrieves
[this javascript library file](https://cdnjs.cloudflare.com/ajax/libs/select2/3.5.4/select2.min.js)
and checks it against the regular expressions in `js_library_patterns.json`. It prints the javascript library
whose regex entries matched the contents of the file.
