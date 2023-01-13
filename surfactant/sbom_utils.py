from deepdiff import DeepDiff


def entry_search(sbom, hsh):
    if len(sbom['software']) == 0:
        return False, None
    for index, item in enumerate(sbom['software']):
        if hsh in item['sha256']:
            return True, index
        
    return False, None


# updates fields in an entry, with the assumption that the hashes match (e.g. most extracted values should match)
def update_entry(sbom, entry, index):
    if index != None:
        # duplicate entry, check other fields to see if data differs. 
        existing_entry = sbom['software'][index]
        if existing_entry != entry:
            # go through each key-value pair between the entries to find the differences and update accordingly.
            existing_uuid = existing_entry['UUID']
            entry_uuid = entry['UUID']
            diff = DeepDiff(existing_entry, entry)['values_changed']
            for key in diff:
                value = diff[key]['new_value']
                # key will look something like root['fileName'][0], we only want the first location/key
                location = key.replace("root", "")
                location = location[2:location.index("']")]
                if location not in ['UUID', 'captureTime']:
                    # if new value to replace is an empty string or None - just leave as is
                    if value not in ['', " ", None]:
                        # if value is an array, append the new values; only add if not a duplicate
                        # ex: containerPath (array), fileName, installPath, vendor, provenance, metadata, supplementaryFiles, components
                        if isinstance(sbom['software'][index][location], list):
                            if location in ["containerPath", "fileName", "installPath", "vendor", "provenance", "metadata", "supplementaryFiles", "components"]:
                                if not value in sbom['software'][index][location]:
                                    sbom['software'][index][location].append(value)                     
                        # if value is a string, update the dictionary
                        # ex: name, comments, version, description, relationshipAssertion, recordedInstitution
                        if location in ["name", "comments", "version", "description", "relationshipAssertion", "recordedInstitution"]:
                            sbom['software'][index].update({location : value})
                
                    # TODO: for intermediate file format, find/figure out way to resolve conflicts between surfactant sboms and those with manual additions
  
            # return UUID of existing entry, UUID of entry being discarded, existing_entry object
            return existing_uuid, entry_uuid, existing_entry