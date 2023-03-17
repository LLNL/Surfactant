from collections.abc import Iterable

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM


# TODO for an intermediate SBOM format, have ability to search more efficiently by hashes/filepath/filename
# currently, establishing relationships is something around O(n^2) due to searching entire sbom for matches
def parse_relationships(sbom: SBOM):
    for sw in sbom.software:
        # Skip for temporary files/installer that don't have any installPath to find dependencies with
        if sw.installPath is None:
            continue

        pm = get_plugin_manager()

        # Find metadata saying what dependencies are used by the software entry
        for md in sw.metadata:
            # handle ELF dependencies, PE imports, and dotNet assembly references using included plugins
            for relationships in pm.hook.establish_relationships(
                sbom=sbom, software=sw, metadata=md
            ):
                if relationships:
                    print(relationships)
                if isinstance(relationships, Iterable):
                    for r in relationships:
                        if not sbom.find_relationship_object(r):
                            sbom.add_relationship(r)
