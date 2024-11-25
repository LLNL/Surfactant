import json

import os
import requests

from surfactant.configmanager import ConfigManager

def load_database(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text


def parse_cfg_file(content):
    database = {}
    lines = content.splitlines()
    filtered_lines = []

    for line in lines:
        if not (line.startswith("#") or line.startswith("identifier")):
            filtered_lines.append(line)

    for line in filtered_lines:
        line = line.strip()

        # Split by semicolons
        fields = line.split(";")

        # Name of library
        lib_name = fields[0]

        # Empty filename because EMBA doesn't need filename patterns
        name_patterns = []

        # Check if it starts with one double quote and ends with two double quotes
        if fields[3].startswith('"') and fields[3].endswith('""'):
            filecontent = fields[3][1:-1]  
        elif fields[3].endswith('""'):
            filecontent = fields[3][:-1]  
        else:
            filecontent = fields[3].strip('"')  
        
        # Create a dictionary for this entry and add it to the database
        if fields[1] == "" or fields[1] == "strict":
            if fields[1] == "strict":
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": [lib_name],
                        "filecontent": [],
                    }
            else:
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": name_patterns,
                        "filecontent": [filecontent],
                    }
                else:
                    database[lib_name]["filecontent"].append(filecontent)

    return database

# Use database from specific commit
emba_database_url = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"
json_file_path = ConfigManager().get_data_dir_path() / "native_lib_patterns"/ "emba.json"

file_content = load_database(emba_database_url)

parsed_data = parse_cfg_file(file_content)

for key, value in parsed_data.items():
    filecontent_list = value["filecontent"]

    # Remove leading ^ from each string in the filecontent list
    for i, content in enumerate(filecontent_list):  # Use enumerate to get index and value
            if content.startswith("^"):
                filecontent_list[i] = content[1:]

            if not content.endswith("\\$"):
                if content.endswith("$"):
                    filecontent_list[i] = content[:-1]

os.makedirs(os.path.dirname(json_file_path), exist_ok=True)
with open(json_file_path, 'w') as json_file:
    json.dump(parsed_data, json_file, indent=4)