import json
import re
import tarfile
import os
#from scripts import native_binaries

#def check_file(filename):
    

def find_native_match(expressions: dict, filename: str) -> str:
    for name, library in expressions.items():
        if "filename" in library:
            for pattern in library["filename"]:
                try:
                    if re.search(pattern, filename):
                        print("found through filename")
                        return name
                except re.error as e:
                    print(f"Invalid regex filename pattern '{pattern}': {e}")

    try:
        #try to use tempfile module here so it takes care of cleanup
        # first check to see if file is compressed? .tar is not compressed
        # if not compressed, keep it here
        # if compressed, call tar_decompression() -> 
        
        # check to see if it's a tar file:

        # IF MODE == .gz, .bz2, or .xz, call tar_decompression()
        mode = ""

        if filename.endswith('.tar'):
            mode = 'r:gz'

        elif filename.endswith('.tar.gz'):
            mode = 'r:gz'

        elif filename.endswith('.tar.bz2'):
            mode = 'r:bz2'

        elif filename.endswith('.tar.xz'):
            mode = 'r:xz' 

        if mode == '.tar':
            with tarfile.open(filename, 'r') as tar:
                
                print("Opened tarfile")
            tar.extractall(path="./extraction_dir")
            print("All files extracted")

        else:    
            with tarfile.open(filename, mode) as tar:
                tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3")

        match_list = []
        
        for name, library in expressions.items():
            if "filecontent" in library:
                for pattern in library["filecontent"]:
                    try:
                        # Save all decompressed files in temp dir
                        # loop through all files in temp dir and search against patterns below
                        if mode != '.tar':
                            for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3"):
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
                        else:
                            print("not .tar")         
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

library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/bgpd.pl-0.08.tar")
print(library_name)






# def find_native_match(expressions: dict, filename: str) -> str:
#     for name, library in expressions.items():
#         if "filename" in library:
#             for pattern in library["filename"]:
#                 try:
#                     if re.search(pattern, filename):
#                         print("found through filename")
#                         return name
#                 except re.error as e:
#                     print(f"Invalid regex filename pattern '{pattern}': {e}")

#     try:
#         #try to use tempfile module here so it takes care of cleanup
#         # first check to see if file is compressed? .tar is not compressed
#         # if not compressed, keep it here
#         # if compressed, call tar_decompression() -> 
        
#         # check to see if it's a tar file:

#         with tarfile.open(filename, "r:bz2") as tar:
#             tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3")

#         match_list = []
        
#         for name, library in expressions.items():
#             if "filecontent" in library:
#                 for pattern in library["filecontent"]:
#                     try:
#                         # Save all decompressed files in temp dir
#                         # loop through all files in temp dir and search against patterns below
#                         for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3"):
#                             for file_name in files:
#                                 file_path = os.path.join(root, file_name)
#                                 try:
#                                     with open(file_path, "r", encoding="ISO-8859-1") as f:
#                                         contents = f.read()
#                                         if re.search(pattern, contents):
#                                             print("found through filecontent")
#                                             match_list.append(name)
#                                 except Exception as e:
#                                     print(f"Could not read file {file_path}: {e}")            
#                     except re.error as e:
#                         print(f"Regex error with filecontent pattern '{pattern}': {e}")     
#         return match_list  
    
#     # Delete all temp files after matches are found to keep dir clean?
                                     
#     except FileNotFoundError:
#         print(f"File not found: {filename}")
#     print("No matches found.")
#     return None

# with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
#     patterns = json.load(f)

# library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/7z_win32.exe")
# print(library_name)