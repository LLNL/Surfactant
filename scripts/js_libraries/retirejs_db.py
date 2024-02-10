import json
import requests


def load_database() -> dict:
    url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"
    response = requests.get(url)
    if response.status_code == 200:
        return json.loads(response.text)
    return None


def strip_irrelevant_data(retirejs_db: dict) -> dict:
    clean_db = {}
    for library, lib_entry in retirejs_db.items():
        if "extractors" in lib_entry:
            clean_db[library] = {}
            patterns = lib_entry["extractors"]
            possible_entries = [
                "func",
                "uri",
                "filename",
                "filecontent",
                "hashes",
            ]
            for entry in possible_entries:
                if entry in patterns:
                    clean_db[library][entry] = patterns[entry]
    return clean_db


retirejs = load_database()

if retirejs is not None:
    cleaned = strip_irrelevant_data(retirejs)
    with open("reduced.json", "w") as f:
        json.dump(cleaned, f, indent=4)
