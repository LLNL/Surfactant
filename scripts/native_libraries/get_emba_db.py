# import json
# import requests


# def load_database() -> dict:
#     url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
#     response = requests.get(url)
#     if response.status_code == 200:
#         print("success")
#         return json.loads(response.text)
#     return None




# import requests
# import json

# def load_database() -> dict:
#     url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
#     response = requests.get(url)
#     print(f"HTTP Status Code: {response.status_code}")  # Print status code

#     if response.status_code == 200:
#         print("success")
#         try:
#             return json.loads(response.text)
#         except json.JSONDecodeError as e:
#             print(f"JSON decoding failed: {e}")
#             return None
#     else:
#         print(f"Failed to fetch data. Status code: {response.status_code}")
#         return None

# database = load_database()
# if database:
#     print("Loaded data:", database)
# else:
#     print("No data loaded.")




# import requests

# def load_database() -> list:
#     url = "https://raw.githubusercontent.com/e-m-b-a/emba/master/config/bin_version_strings.cfg"
#     response = requests.get(url)
#     print(f"HTTP Status Code: {response.status_code}")  # Print status code

#     if response.status_code == 200:
#         print("success")
#         data = response.text
#         database = []
#         for line in data.splitlines():
#             line = line.strip()
#             # Skip empty lines and comments
#             if not line or line.startswith("#"):
#                 continue
#             # Split the line into fields
#             fields = line.split(';')
#             if len(fields) == 5:  # Adjusted to 5 fields based on your example
#                 identifier, mode, license_type, version_identifier_regex, version_transformation_regex = fields
#                 database.append({
#                     'identifier': identifier,
#                     'mode': mode,
#                     'license_type': license_type,
#                     'version_identifier_regex': version_identifier_regex,
#                     'version_transformation_regex': version_transformation_regex,
#                 })
#         return database
#     else:
#         print(f"Failed to fetch data. Status code: {response.status_code}")
#         return None

# database = load_database()
# if database:
#     print("Loaded entries:", len(database))
#     for entry in database:
#         print("this is entry: ", entry)
# else:
#     print("No data loaded.")



import json

import requests


def load_database() -> dict:
    url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"
    response = requests.get(url)
    if response.status_code == 200:
        return json.loads(response.text)
    return None


def strip_irrelevant_data(emba_db: dict) -> dict:
    clean_db = {}
    reg_temp = "\u00a7\u00a7version\u00a7\u00a7"
    version_regex = r"\d+(?:\.\d+)*"
    for library, lib_entry in emba_db.items():
        if "extractors" in lib_entry:
            clean_db[library] = {}
            patterns = lib_entry["extractors"]
            possible_entries = [
                "filename",
                "filecontent",
                "hashes",
            ]
            for entry in possible_entries:
                if entry in patterns:
                    entry_list = []
                    for reg in patterns[entry]:
                        entry_list.append(reg.replace(reg_temp, version_regex))
                    clean_db[library][entry] = entry_list
    return clean_db


newdb = load_database()

if newdb is not None:
    cleaned = strip_irrelevant_data(newdb)
    with open("native_lib_patterns.json", "w") as f:
        json.dump(cleaned, f, indent=4)