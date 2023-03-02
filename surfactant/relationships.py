import pathlib
import surfactant.pluginsystem


def create_relationship(xUUID, yUUID, relationship):
    return {"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship}


def add_relationship(sbom, xUUID, yUUID, relationship):
    sbom['relationships'].append(create_relationship(xUUID, yUUID, relationship))


def find_relationship(sbom, xUUID, yUUID, relationship):
    return {"xUUID": xUUID, "yUUID": yUUID, "relationship": relationship} in sbom['relationships']


# TODO for an intermediate SBOM format, have ability to search more efficiently by hashes/filepath/filename
# currently, establishing relationships is something around O(n^2) due to searching entire sbom for matches
def parse_relationships(sbom):
    for sw in sbom['software']:
        # Skip for temporary files/installer that don't have any installPath to find dependencies with
        if sw['installPath'] == None:
            continue

        # Find metadata saying what dependencies are used by the software entry
        for md in sw['metadata']:
            # handle ELF dependecies, PE imports, and dotNet assembly references using included plugins
            for p in surfactant.pluginsystem.RelationshipPlugin.get_plugins():
                if p.has_required_fields(md):
                    print(f"====={p.PLUGIN_NAME} RelationshipPlugin=====")
                    relationships = p.get_relationships(sbom, sw, md)
                    if relationships:
                        print(relationships)
                    for r in relationships:
                        if not find_relationship(sbom, r["xUUID"], r["yUUID"], r["relationship"]):
                            add_relationship(sbom, r["xUUID"], r["yUUID"], r["relationship"])