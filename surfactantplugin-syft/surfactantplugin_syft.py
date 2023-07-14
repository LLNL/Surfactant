import surfactant.plugin, os, anchore_syft, subprocess, json
from surfactant.sbomtypes import SBOM, Software
from surfactant.plugin.manager import get_plugin_manager

@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
  pm = get_plugin_manager()
  #if filetype in [".tar", ".sif"]:
  if filetype == "TAR":
      data = subprocess.check_output('anchore_syft ' + filename + ' -o json', shell=True)
      data = json.loads(data.decode())
      #print(data)
      #print("TEST######################################")
      info = []
      count = 1
      for i in data['artifacts']:
        testblock = {}
        count = count + 1
        testblock['name'] = i['name']
        testblock['version'] = i['version']
        testblock['size'] = i['metadata']['installedSize']
        testblock['vendor'] = i['metadata']['maintainer']
        #info['metadata']['collectedBy'] = 'Syft: ' + i['foundBy']
        info.append(testblock)
        print(info)
      return info
  else:
    return None
  