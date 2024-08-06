import json
import requests
import os

def load_database(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def parse_cfg_file(content):
    database = {}
    lines = content.splitlines()
    filtered_lines = []

    for line in lines:
        if not (line.startswith('#') or line.startswith('identifier')):
            filtered_lines.append(line)
    
    for line in filtered_lines:
        line = line.strip()

        # Split by semicolons
        fields = line.split(';')
        
        # Name of library
        lib_name = fields[0]
        
        # Custom name pattern combined with the original name
        name = [f"{lib_name}-\\b(lib|lib[A-Za-z0-9_\\-]+)\\.(dll|so|dylib)\\b(?:\\s*\\d+\\.\\d+(\\.\\d+)?)?"]
        
        ### usually package names will have this pattern
        ### ^libexample-(\d+\.\d+\.\d+)$ OR ^libexample-(\d+\.\d+\.\d+)\.(dll|so|dylib)$    
        # May look like this:

        # DLL or SO Files: libexample-1.0.0.dll, mylibrary-2.3.4.so
        # Package Archives: example-library-1.2.3.tar.gz, my-toolkit-v1.0.0.zip

        #filecontent = fields[2] if len(fields) > 2 else ''
        filecontent = fields[3].strip('"') if len(fields) > 3 else ''
        #transformation_rule = fields[4].strip('"') if len(fields) > 4 else ''
        
        # Create a dictionary for this entry and add it to the database
        if lib_name not in database:
            database[lib_name] = {
                'filename': name,
                'filecontent': [filecontent],
                #'transformation_rule': transformation_rule
            }
        else:
            database[lib_name]['filecontent'].append(filecontent)

    return database


url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
json_file_path = "surfactant/infoextractors/native_lib_patterns.json"

# Load the content from the URL
file_content = load_database(url)

# Parse the content
parsed_data = parse_cfg_file(file_content)

for key in parsed_data:
    filecontent_list = parsed_data[key]["filecontent"]
    
    # Remove leading ^ from each string in the filecontent list
    for i in range(len(filecontent_list)):
        if filecontent_list[i].startswith('^'):
            filecontent_list[i] = filecontent_list[i][1:]

        if filecontent_list[i].endswith('$'):
            filecontent_list[i] = filecontent_list[i][:-1]


# Write the parsed data to a JSON file
with open(json_file_path, 'w') as json_file:
    json.dump(parsed_data, json_file, indent=4)
