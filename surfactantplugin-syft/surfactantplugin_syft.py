import surfactant.plugin, os, anchore_syft, subprocess, json
from surfactant.sbomtypes import SBOM, Software

@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: str) -> object:
  print("TEST######################################")
  if filetype in [".tar", ".sif"]:
      data = subprocess.check_output('anchore_syft' + filename + '-o json', shell=True)
      data = json.load(data)
      info = {}
      for i in data['artifacts']:
         info['name'] = i['name']
         info['version'] = i['version']
         info['size'] = i['metaata']['installedSize']
         info['vendor'] = i['maintainer']
         info['metadata']['collectedBy'] = 'Syft: ' + i['foundBy']
      return info
  else:
    return None
  