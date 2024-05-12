import json
import re

import requests


def get_test_file():
    url = "https://cdnjs.cloudflare.com/ajax/libs/select2/3.5.4/select2.min.js"
    response = requests.get(url)
    if response.status_code == 200:
        with open("testFile.js", "w") as js:
            js.write(response.text)


def find_js_match(expressions: dict, filename: str) -> str:
    for name, library in expressions.items():
        if "filename" in library:
            for pattern in library["filename"]:
                if re.search(pattern, filename):
                    return name
    try:
        with open(filename, "r") as jsfile:
            contents = jsfile.read()
        for name, library in expressions.items():
            if "filecontent" in library:
                for pattern in library["filecontent"]:
                    if re.search(pattern, contents):
                        return name
    except FileNotFoundError:
        print(f"File not found: {filename}")
    return None


get_test_file()

with open("js_library_patterns.json", "r") as f:
    patterns = json.load(f)

library_name = find_js_match(patterns, "testFile.js")
print(library_name)
