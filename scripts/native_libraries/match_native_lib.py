import json
import re
import tarfile
import os
import file_decompression
#from scripts import native_binaries

#def check_file(filename):
    

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

#         # IF MODE == .gz, .bz2, or .xz, call tar_decompression()
#         mode = ""

#         if filename.endswith('.tar') or filename.endswith('.tar.gz') or filename.endswith('.tar.bz2') or filename.endswith('.tar') or filename.endswith('.zip'):
#             pass
#             # call 

#         elif filename.endswith('.exe') or filename.endswith('.so') or filename.endswith('.dll'):
#             pass 

#         match_list = []
        
#         for name, library in expressions.items():
#             if "filecontent" in library:
#                 for pattern in library["filecontent"]:
#                     try:
#                         # Save all decompressed files in temp dir
#                         # loop through all files in temp dir and search against patterns below
#                         if mode != '.tar':
#                             for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3"):
#                                 for file_name in files:
#                                     file_path = os.path.join(root, file_name)
#                                     try:
#                                         with open(file_path, "r", encoding="ISO-8859-1") as f:
#                                             contents = f.read()
#                                             if re.search(pattern, contents):
#                                                 print("found through filecontent")
#                                                 match_list.append(name)
#                                     except Exception as e:
#                                         print(f"Could not read file {file_path}: {e}")   
#                         else:
#                             print("not .tar")         
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

# library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/bgpd.pl-0.08.tar")
# print(library_name)


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

#         if filename.endswith('.tar.bz2'):
#             with tarfile.open(filename, "r:bz2") as tar:
#                 tar.extractall(path="/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3")

#                 match_list = []
                
#                 for name, library in expressions.items():
#                     if "filecontent" in library:
#                         for pattern in library["filecontent"]:
#                             try:
#                                 # Save all decompressed files in temp dir
#                                 # loop through all files in temp dir and search against patterns below
#                                 for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_3"):
#                                     for file_name in files:
#                                         file_path = os.path.join(root, file_name)
#                                         try:
#                                             with open(file_path, "r", encoding="ISO-8859-1") as f:
#                                                 contents = f.read()
#                                                 if re.search(pattern, contents):
#                                                     print("found through filecontent")
#                                                     match_list.append(name)
#                                         except Exception as e:
#                                             print(f"Could not read file {file_path}: {e}")            
#                             except re.error as e:
#                                 print(f"Regex error with filecontent pattern '{pattern}': {e}")     
#                 return match_list  
#         else:
#             with open(filename, 'rb') as file:
#                 elf_file = ELFFile(file)

#                 sections = {}
#                 for section in elf_file.iter_sections():
#                     section_name = section.name
#                     section_data = section.data()
#                     sections[section_name] = section_data

#                 # Extract segments
#                 segments = {}
#                 for segment in elf_file.iter_segments():
#                     segment_type = segment.header.p_type
#                     segment_data = segment.data()
#                     segments[segment_type] = segment_data

#     except FileNotFoundError:
#         print(f"File not found: {filename}")

    

    
#     # Delete all temp files after matches are found to keep dir clean?

#     print("No matches found.")
#     return None

# with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
#     patterns = json.load(f)

# library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/busybox")
# print(library_name)




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
        # check to see if it's a tar file
        pattern = r'\.tar(\.(gz|bz2|xz))?$'
        if re.search(pattern, filename):
            compression_type = file_decompression.check_compression_type(filename)

        # check to see if it's a zip file
        pattern = r'\.zip$'
        if re.search(pattern, filename):
            compression_type = file_decompression.check_compression_type(filename)

        match_list = []
        
        # check if it's a file or a dir
        # this is catching everything, even dirs
        if os.path.isfile(filename):
            print("i was one file")
            for name, library in expressions.items():
                if "filecontent" in library:
                    for pattern in library["filecontent"]:
                        try:
                            with open(filename, "rb") as f:
                                contents = f.read()
                                if re.search(pattern.encode('utf-8'), contents):
                                    print("found through filecontent")
                                    match_list.append(name)
                        except Exception as e:
                            print(f"Could not read file {filename}: {e}") 
            return match_list

        # should have dir here to traverse
        elif os.path.isdir(filename):
            print("i was more files")
            for name, library in expressions.items():
                if "filecontent" in library:
                    for pattern in library["filecontent"]:
                        try:
                            # Save all decompressed files in temp dir
                            # loop through all files in temp dir and search against patterns below

                            # also, how do we get the dir where the decompressed files are?
                            # can we call supports_file() here again and only run this on ELF, PE, MACH-O files
                            for root, dirs, files in os.walk("/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/decompressed_files_5"):
                                for file_name in files:
                                    file_path = os.path.join(root, file_name)
                                    try:
                                        with open(file_path, "rb") as f:
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
    # print("No matches found.")
    return None

with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
    patterns = json.load(f)

library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/binutils-2.13.92.tar.bz2")
print(library_name)