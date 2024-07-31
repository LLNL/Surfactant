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
    
    print("this is lines[1]: ", lines[1])
    print("this is lines[10]: ", lines[10])

    for line in lines:
        if not (line.startswith('#') or line.startswith('identifier')):
            filtered_lines.append(line)
    
    for line in filtered_lines:
        line = line.strip()

        # Split by semicolons
        fields = line.split(';')
        #print("this is fields: ", fields)

        for line in fields:
            if (len(line) == 6 or len(line) == 5):
                break;
            else:
                print("not 6: ", len(line))
        
        # Name of library
        lib_name = fields[0]
        
        # Custom name pattern combined with the original name
        name = f"{lib_name}-\\b(lib|lib[A-Za-z0-9_\\-]+)\\.(dll|so|dylib)\\b(?:\\s*\\d+\\.\\d+(\\.\\d+)?)?"
        
        ### usually package names will have this pattern
        ### ^libexample-(\d+\.\d+\.\d+)$ OR ^libexample-(\d+\.\d+\.\d+)\.(dll|so|dylib)$    
        # May look like this:

        # DLL or SO Files: libexample-1.0.0.dll, mylibrary-2.3.4.so
        # Package Archives: example-library-1.2.3.tar.gz, my-toolkit-v1.0.0.zip

        #filecontent = fields[2] if len(fields) > 2 else ''
        filecontent = fields[3].strip('"') if len(fields) > 3 else ''
        transformation_rule = fields[4].strip('"') if len(fields) > 4 else ''
        
        # Create a dictionary for this entry and add it to the database
        database[lib_name] = {
            'filename': name,
            'filecontent': filecontent,
            'transformation_rule': transformation_rule
        }
    print("this is fil_lines[0]: ", filtered_lines[0])
    print("this is fil_lines[1]: ", filtered_lines[1])
    print("this is fil_lines[2]: ", filtered_lines[2])
    print("this is fil_lines[10]: ", filtered_lines[10])
    fields2 = filtered_lines[1].split(';')
    fields3 = len(filtered_lines[1].split(';'))
    print("fields2: ", fields2)
    print("len of fields3: ", fields3)

    print("length: ", len(fields[0]))
    print("length: ", len(fields[1]))
    print("length: ", len(fields))
    print("this is fields[0]", fields[0])
    print("this is fields[1]", fields[1])
    print("this is fields: ", fields)
    return database

url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
json_file_path = "surfactant/infoextractors/native_lib_patterns.json"

# Load the content from the URL
file_content = load_database(url)

# Parse the content
parsed_data = parse_cfg_file(file_content)

# # Write the parsed data to a JSON file
# with open(json_file_path, 'w') as json_file:
#     json.dump(parsed_data, json_file, indent=4)
