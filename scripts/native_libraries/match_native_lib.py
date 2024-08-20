# import json
# import re


# def find_native_match(expressions: dict, filename: str) -> str:
#     for name, library in expressions.items():
#         if "filename" in library:
#             for pattern in library["filename"]:
#                 try:
#                     if re.search(pattern, filename):
#                         print("found through filename")
#                         return name
#                 except:
#                     breakpoint()

#     try:
#         with open(filename, "r", encoding="ISO-8859-1") as nativefile:
#             contents = nativefile.read()
#         for name, library in expressions.items():
#             if "filecontent" in library:
#                 for pattern in library["filecontent"]:
#                     try:
#                         if re.search(pattern, contents):
#                             print("found through filecontent")
#                             print("pattern")
#                             return name
#                     except re.error as e:
#                         print(f"Regex error with pattern '{pattern}': {e}")                        
#     except FileNotFoundError:
#         print(f"File not found: {filename}")
#     print("this is last: ", pattern)
#     return None

# with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
#     patterns = json.load(f)

# library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/busybox-1_36_1.tar.bz2")
# print(library_name)


import json
import re
import tarfile
import os

def find_native_match(expressions: dict, filename: str) -> str:
    for name, library in expressions.items():
        if "filename" in library:
            for pattern in library["filename"]:
                try:
                    if re.search(pattern, filename):
                        print("found through filename")
                        return name
                except re.error as e:
                    print(f"Regex error with filename pattern '{pattern}': {e}")

    try:
        # with open(filename, "r", encoding="ISO-8859-1") as nativefile:
        #     contents = nativefile.read()
        with tarfile.open(filename, "r:bz2") as tar:
            tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files")

        # Add matches to list
        match_list = []
        
        for name, library in expressions.items():
            if "filecontent" in library:
                for pattern in library["filecontent"]:
                    try:
                        #change 'contents' to temp dir where decompressed files are
                        # loop through all files in temp file and search against patterns below
                        for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files"):
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                try:
                                    with open(file_path, "r", encoding="ISO-8859-1") as f:
                                        contents = f.read()
                                        if re.search(pattern, contents):
                                            print("found through filecontent")
                                            match_list.append(name)
                                except Exception as e:
                                    print(f"Could not read file {file_path}: {e}")            
                            
                    except re.error as e:
                        print(f"Regex error with filecontent pattern '{pattern}': {e}")     
        return match_list  
    
    # Delete all temp files after matches are found to keep dir clean?
                                     
    except FileNotFoundError:
        print(f"File not found: {filename}")
    print("No matches found.")
    return None

with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
    patterns = json.load(f)

library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/binutils-2.13.92.tar.bz2")
print(library_name)