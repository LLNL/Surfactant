# SBOM Visualization Plugin
A plugin for Surfactant that generates interactive visualizations of CyTRICS-formatted SBOMs
![Example Output](https://github.com/user-attachments/assets/fb3efd41-7e09-4bbf-a56e-2bd2c16cbe9b)

## Installation
SBOMVis can be installed as a plugin for Surfactant or as a standalone executable with `pip` & `pipx`. Commands for installing with `pipx` (recommended) are shown below:
### As a Surfactant plugin
```bash
$ pipx inject surfactant sbomvis
```

### Standalone installation
```bash
$ pipx install sbomvis
```

## Usage
The plugin can generate visualizations when running Surfactant's `generate` command or from an existing SBOM.

### Generating visualizations during a Surfactant run
Passing in `sbomvis` as the output format will cause Surfactant to generate an HTML file with the same name as the SBOM containing the visualization. The original JSON SBOM will also be saved to the same directory.
```bash
$ surfactant generate --output_format=sbomvis SPECIMEN_CONFIG SBOM_OUTFILE
```

### Generating visualizations from an existing SBOM
Visualizations can be created from an existing Surfactant SBOM by running `sbomvis` and passing in it's path with `-p`.

Surfactant SBOM Visualization

options:
  -h, --help            show this help message and exit
  -p PATH [PATH ...], --path PATH [PATH ...]
                        Path(s) to JSON SBOMs
  -c, --cull            Enable culling of isolated nodes (may improve performance on large graphs at the cost of completeness)
  -pb, --use-progress-bar
                        Display progress bar while waiting for large graphs to load instead of disabling physics
```

## Controls
Several controls are included:
* Clicking on a node will reveal a sidebar with more information about it
* Right clicking on a node will pin/unpin it in place
* Archives and containers can be expanded or collapsed by double clicking

Note: Physics is initially disabled for large graphs (~600+ nodes) to improve loading times. Once the graph is on screen it should be re-enabled via clicking the toggle in the upper left corner.
