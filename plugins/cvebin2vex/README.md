# CVE-to-OpenVEX Plugin for SBOM Surfactant

A plugin for Surfactant that leverages [cve-bin-tool](https://github.com/intel/cve-bin-tool) and a custom conversion process to generate OpenVEX vulnerability statements from binary files. This tool supports analyzing binary strings to identify known vulnerabilities and outputs them in the standardized CycloneDX and OpenVEX format.

The cve-bin-tool is licensed under GPL-3 and is available to review [here](https://github.com/intel/cve-bin-tool?tab=GPL-3.0-1-ov-file#readme).

## Quickstart

To install this plugin within the same virtual environment as Surfactant, use the command `pip install .`.

For developers modifying the plugin, the editable installation can be achieved with `pip install -e .`.

Since the plugin is designed to run in `--offline` mode, before your initial run of the script please run the command `cve-bin-tool --update now`. This will provide you a freshly updated local database that the script will check against in the offline mode.

After the plugin installation, run Surfactant as you normally would to create an SBOM. For binary files analyzed by this plugin, additional JSON files will be generated containing vulnerability data extracted from the binaries. If there are duplicate hashed files, the extractor will skip the entry.

Example:
Output Filename: `$(sha256hash)_additional_metadata.json`

```json
{
  "sha256hash": " ",
  "filename": [],
  "openvex": [],
  "cyclonedx-vex": [],
  "cve-bin-tool": []
}
```

The plugin's functionality can be toggled via Surfactant's plugin management features, using the plugin name `surfactantplugin_cvebintool2vex.py` as defined in the `pyproject.toml` under the `project.entry-points."surfactant"` section.

## Features

- **Offline Vulnerability Analysis**: Utilizes CVE-bin-tool in offline mode to scan binaries for known vulnerabilities.
- **OpenVEX Format Conversion**: Transforms CVE-bin-tool JSON output into the OpenVEX format, a standardized way to report vulnerabilities.

## Uninstalling

Remove the plugin from your environment with `pip uninstall surfactantplugin_cvebintool2vex.py`.

## License
The CVE-to-OpenVEX Plugin for SBOM Surfactant is licensed under the MIT License. However, it leverages the cve-bin-tool, which is licensed under the GPL-3.0 License.

## Important Licensing Information
Main Project License (Surfactant): MIT License.
Plugin License: MIT License, but it includes and uses cve-bin-tool, which is GPL-3.0 licensed.
## Implications
Using this plugin means that when it operates, it invokes the cve-bin-tool (GPL-3.0 licensed). This interaction does not automatically change the license of your project to GPL-3.0, but any distribution of the combined work that includes this plugin must comply with the GPL-3.0 terms.

For more details on GPL-3.0, please review the GPL-3.0 License.