import json
import re


def find_native_match(expressions: dict, filename: str) -> str:
    for name, library in expressions.items():
        if "filename" in library:
            for pattern in library["filename"]:
                try:
                    if re.search(pattern, filename):
                        print("found through filename")
                        return name
                except:
                    breakpoint()

    try:
        with open(filename, "r", encoding="ISO-8859-1") as nativefile:
            contents = nativefile.read()
        print("this is contents: ", contents)
        for name, library in expressions.items():
            if "filecontent" in library:
                for pattern in library["filecontent"]:
                    try:
                        if re.search(pattern, contents):
                            print("found through filecontent")
                            print("pattern")
                            return name
                    except re.error as e:
                        print(f"Regex error with pattern '{pattern}': {e}")                        
    except FileNotFoundError:
        print(f"File not found: {filename}")
    return None

with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
    patterns = json.load(f)

library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/busybox-1_36_1.tar.bz2")
print(library_name)