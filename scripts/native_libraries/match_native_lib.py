import json
import re


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



with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
    patterns = json.load(f)

#print("this is patterns: ", patterns)

library_name = find_js_match(patterns, "7z_win32.exe")
print(library_name)
