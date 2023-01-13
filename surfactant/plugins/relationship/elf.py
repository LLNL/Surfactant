
import surfactant.pluginsystem as pluginsystem


class ELF(pluginsystem.RelationshipPlugin):
    PLUGIN_NAME = "ELF"

    @classmethod
    def has_required_fields(cls, metadata) -> bool:
        return 'elfDependencies' in metadata

    @classmethod
    def get_relationships(cls, sbom, sw, metadata) -> list:
        relationships = []
        dependent_uuid = sw.get('UUID')
        for fname in metadata['elfDependencies']:
            # TODO if there are many symlinks to the same file, if item.get('fileName')[0] should be changed to check against every name
            # for multiple separate file systems, checking only a portion of sbom['software'] might need to be handled
            if dependency_uuid := [item.get('UUID') for item in sbom['software'] if item.get('fileName')[0] == fname]:
                # shouldn't find multiple entries with the same UUID
                # if we did, there may be files outside of the correct search path that were considered in the previous step
                relationships.append(pluginsystem.RelationshipPlugin.create_relationship(dependent_uuid, dependency_uuid[0], "Uses"))
            else:
                pass
                # this mostly just prints system libraries
                #print(f" Dependency {fname} not found for sbom['software'] entry={sw}")
        return relationships