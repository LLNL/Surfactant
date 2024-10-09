import json
import re
import tarfile
import os
import file_decompression

def is_elf(file_path):
    with open(file_path, "rb") as f:
        header = f.read(4)
    return header == b'\x7fELF'

def is_pe(file_path):
    with open(file_path, "rb") as f:
        header = f.read(2)
    return header == b'MZ'

def is_macho(file_path):
    with open(file_path, "rb") as f:
        header = f.read(4)
    return header in [b'\xCF\xFA\xED\xFE', b'\xCE\xFA\xED\xFE']  # 64-bit and 32-bit

def supports_file(file_path):
    """Check if the file is ELF, PE, or MACH-O."""
    return is_elf(file_path) or is_pe(file_path) or is_macho(file_path)

def find_native_match(expressions: dict, filename: str) -> str:
    match_list = []
    temp_folder = None

    #find match through filename
    for name, library in expressions.items():
        #does this check to see if the field filename exists or if the filename field has elements?
        if "filename" in library:
            for pattern in library["filename"]:
                try:
                    if re.search(pattern, filename):
                        print("this is pattern, ", pattern)
                        print("found through filename")
                        return name
                except re.error as e:
                    print(f"Invalid regex filename pattern '{pattern}': {e}")

    try:
        # Check for tar or zip files
        pattern = r'\.tar(\.(gz|bz2|xz))?$|\.zip$' 
        if re.search(pattern, filename):
            temp_folder = file_decompression.check_compression_type(filename)
        else:
            temp_folder = filename
        print("This is the returned temp_folder: ", temp_folder)
        
        # check if it's a file or a dir
        #MAybe we keep this as temp_folder. Basically, if the file is not compressed, set temp_folder to the filename. 
        if os.path.isfile(temp_folder):
            print("Is a single file")
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
        
        elif os.path.isdir(temp_folder):
            print("Is a dir")
            for name, library in expressions.items():
                if "filecontent" in library:
                    for pattern in library["filecontent"]:
                        # can we call supports_file() here again and only run this on ELF, PE, MACH-O files
                        for root, dirs, files in os.walk(temp_folder):
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                if supports_file(file_path):
                                    try:
                                        with open(file_path, "rb") as f:
                                            contents = f.read()
                                            if re.search(pattern, contents):
                                                print("found through filecontent")
                                                match_list.append(name)
                                            else:
                                                print(f"No match in {file_path} for pattern: {pattern}")
                                    except Exception as e:
                                        print(f"Could not read file {file_path}: {e}")
                                # else:
                                #     print("no elf, pe, or macho files")                
            return match_list  
    
    # Delete all temp files after matches are found to keep dir clean?
                                     
    except FileNotFoundError:
         print(f"File not found: {filename}")
    return match_list


with open("/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json", "r") as f:
    patterns = json.load(f)


library_name = find_native_match(patterns, "/Users/tenzing1/surfactant_new_venv/Surfactant/scripts/native_libraries/zlib1.dll")
print("Libs found: ", library_name)