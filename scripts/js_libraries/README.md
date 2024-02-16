# Scripts

## get_retirejs_db.py

Running this script retrieves vulnerability information from various javascript libraries from
[retire.js](https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository-master.json)
and only keeps the contents under each library's "extractors" section, which contains regexes
relevant for detecting a specific javascript library.

The resulting smaller json is written to `reduced.json` in the same directory. This smaller file
will be read from to make the checks later on.

## match_javascript.py

This is an example script that retrieves
[this javascript library file](https://cdnjs.cloudflare.com/ajax/libs/select2/3.0.0/select2.min.js)
and checks it against the regular expressions in `reduced.json`. It prints the javascript library
whose regex entries matched the contents of the file.
