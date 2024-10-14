import json

import requests


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

        # Remove double quotes, if any-> 'grape' instead of '"grape"'
        filecontent = fields[3].strip('"') if len(fields) > 3 else ""

        # Create a dictionary for this entry and add it to the database
        if fields[1] == "" or fields[1] == "strict":
            if fields[1] == "strict":
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": [lib_name],
                        "filecontent": [],
                    }
                # else:
                #    database[lib_name]['filecontent'].append(filecontent)
            else:
                if lib_name not in database:
                    database[lib_name] = {
                        "filename": name_patterns,
                        "filecontent": [filecontent],
                    }
                else:
                    database[lib_name]["filecontent"].append(filecontent)

    return database


url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
json_file_path = "/Users/tenzing1/surfactant_new_venv/Surfactant/surfactant/infoextractors/native_lib_patterns.json"

file_content = load_database(url)

parsed_data = parse_cfg_file(file_content)

for key in parsed_data:
    filecontent_list = parsed_data[key]["filecontent"]

    # Remove leading ^ from each string in the filecontent list
    for i in range(len(filecontent_list)):
        if filecontent_list[i].startswith("^"):
            filecontent_list[i] = filecontent_list[i][1:]

        if filecontent_list[i].endswith("\\$"):
            pass
        else:
            if filecontent_list[i].endswith("$"):
                filecontent_list[i] = filecontent_list[i][:-1]

with open(json_file_path, "w") as json_file:
    json.dump(parsed_data, json_file, indent=4)
