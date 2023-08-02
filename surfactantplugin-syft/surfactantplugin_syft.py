import surfactant.plugin, subprocess, json
import time
from surfactant.sbomtypes import SBOM, Software, Relationship
from surfactant.plugin.manager import get_plugin_manager
from typing import List, Optional

@surfactant.plugin.hookimpl
def extract_image_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
  pm = get_plugin_manager()
  #Change to properly filter filetypes
  #if filetype == "TAR":
  if True:
      data = subprocess.check_output('anchore_syft ' + filename + ' -o json --scope all-layers', shell=True)
      data = json.loads(data.decode())
      #software.installPath = data['source']['target']['userInput']
      sw_list = []
      for i in data['artifacts']:
        sw_entry = Software(
            sha1=None,
            sha256=i['id'],
            md5=None,
            name=[i['name']],
            fileName=None,
            installPath=[i['locations'][0]['path']],
            containerPath=[filename],
            size=i['metadata']['installedSize'],
            captureTime=int(time.time()),
            version=i['metadata']['version'],
            vendor=[i['metadata']['maintainer']],
            description="",
            relationshipAssertion="Unknown",
            comments="Discovered using the Syft plugin",
            metadata=[],
            supplementaryFiles=[],
            provenance=None,
            components=[],
        )
        sw_list.append(sw_entry)
      gather_relationship_data(software, data, sw_list)
      return sw_list
  else:
    return None
  
@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
  relationship_list = []
  for meta in software.metadata:
    if 'syftRelationships' in meta:
      for rel in meta['syftRelationships']:
        relationship_list.append(Relationship(rel[0], rel[1], rel[2]))
  return relationship_list

def gather_relationship_data(image_sw: Software, data: str, sw_list: object):
    uuid_dict = {}
    uuid_dict[data['source']['id']] = [-1, image_sw.UUID]
    for count, sw in enumerate(sw_list):
       index_uuid_list = [count, sw.UUID]
       uuid_dict[sw.sha256] = index_uuid_list
    for rel in data['artifactRelationships']:
      if rel['parent'] in uuid_dict and rel['child'] in uuid_dict:
        parent_info = uuid_dict[rel['parent']]
        child_info = uuid_dict[rel['child']]
        if parent_info[0] == -1:
          sw = image_sw
        else:
          sw = sw_list[parent_info[0]]
        sw.relationshipAssertion = "Known"
        sw_list[child_info[0]].relationshipAssertion = "Known"
        relationship_list = []
        for meta in sw.metadata:
          if 'syftRelationships' in meta:
            relationship_list = meta['syftRelationships']
            break
        if len(relationship_list) == 0:
          sw.metadata.append({})
          sw.metadata[-1]['syftRelationships'] = relationship_list
        relationship_list.append([parent_info[1], child_info[1], rel['type']])
    return