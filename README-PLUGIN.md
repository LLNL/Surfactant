# Surfactant Plugin System
The surfactant plugin system uses the [pluggy](https://pluggy.readthedocs.io/en/stable) module. This module is used by projects such as pytest and tox for their plugin systems; installing and writing plugins for surfactant is a similar to using plugins for those projects. Most of the core surfactant functionality is also implemented as plugins (see [surfactant/output](surfactant/output), [surfactant/infoextractors](surfactant/infoextractors), [surfactant/filetypeid](surfactant/filetypeid), and [surfactant/relationships](surfactant/relationships)).

## Using the Plugin System
TODO: Once plugins are configurable, insert documentation on how to specify plugins to use here

## Creating a Plugin
### Step 1: Write Plugin
In order to create a plugin, you will need to write your implementation for one or more of the functions in the [hookspec.py](surfactant/plugin/hookspecs.py) file. Which functions you implement will depend on the goals of your plugin.

#### Brief overview of functions
[identify_file_type](surfactant/plugin/hookspecs.py#L15)
- Return a string representation of the type of file passed in

[extract_file_info](surfactant/plugin/hookspecs.py#L29)
- Determine how file info is supposed to be extracted

[establish_relationships](surfactant/plugin/hookspecs.py#L47)
- Determines how to establish relationships between the software/metadata that has been passed to it

[write_sbom](surfactant/plugin/hookspecs.py#L70)
- Determine what format to write the SBOM to file

[read_sbom](surfactant/plugin/hookspecs.py#L80)
- If reading from input SBOMs, specifies what format the input SBOMs are

### Step 2. Write .toml File
Once you have written your plugin, you will need to write a pyproject.toml file. Include any relevant project metadata/dependencies for your plugin, as well as an entry-point specification (example below) to make the plugin discoverable by surfactant. Once you write your .toml file, you can `pip install .` your plugin.
More information on entry points can be found [here](https://setuptools.pypa.io/en/latest/userguide/entry_point.html#entry-points-syntax)
### Example
#### sampleplugin.py
```python
import surfactant.plugin
from surfactant.sbomtypes import SBOM

@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
  outfile.write(sbom.to_json(indent=10))
```
#### pyproject.toml
```toml
... generic pyproject info ...
[project.entry-points."surfactant"]
sampleplugin = "sampleplugin"
```
From the same folder as your sampleplugin files, run `pip install .` to install your plugin and surfactant will automatically load and use the plugin.

Another example can be found in the [surfactantplugin-checksec.py](surfactantplugin-checksec.py) folder. There you can see the [pyproject.toml](surfactantplugin-checksec.py/pyproject.toml) file with the `[project.entry-points."surfactant"]` entry. In the [surfactantplugin_checksec.py](surfactantplugin-checksec.py/surfactantplugin_checksec.py) file, you can identify the hooked functions with the `@surfactant.plugin.hookimpl` hook.
