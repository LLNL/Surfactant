import json
import re
import requests


def get_test_file():
    url = "https://cdnjs.cloudflare.com/ajax/libs/select2/3.0.0/select2.min.js"
    response = requests.get(url)
    if response.status_code == 200:
        with open("testFile.js", "w") as js:
            js.write(response.text)


def find_match(expressions: dict, content: str) -> str:
    for name, library in expressions.items():
        if "filecontent" in library:
            for pattern in library["filecontent"]:
                if re.search(pattern, content):
                    return name
    return None


# Call this to locally get the dataTables file
get_test_file()

with open("reduced.json", "r") as f:
    patterns = json.load(f)

with open("testFile.js", "r") as f:
    contents = f.read()

library_name = find_match(patterns, contents)
print(library_name)
