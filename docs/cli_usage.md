# CLI Usage
The Surfactant CLI interface allows users to easily and quickly find, add, and edit entries within a given SBOM.
Some functionality we support includes:
- Specify a file to find, add, or edit its entry in a given SBOM
- Fix up path prefixes, i.e. installPath or containerPath
- Add relationships

## surfactant cli load
The ***cli load* command loads an sbom file into the cli and serializes it for faster processing when running other cli commands. On Unix-like platforms (including macOS), the XDG directory specification is followed and the serialized sbom will be stored in `${XDG_CONFIG_HOME}/surfactant/config.toml`. If the `XDG_CONFIG_HOME` environment variable is not set, the location defaults
to `~/.config`. On Windows, the file is stored in the Roaming AppData folder at `%APPDATA%\\surfactant\\sbom_cli`.

### Example
```bash
surfactant cli load sbom.json
```

## surfactant cli find
The **cli find** command allows users to find specific entries within a SBOM. This will allow users to:
- Verify entries exist within the SBOM
- Manually inspect one or more related entries within a SBOM for errors or bad formatting
- Provide a subset of entries to supply to the `cli edit` or `cli add` commands.

### Example 1: Find Exact Matches
```bash
surfactant cli find sbom.json --UUID 123
{
"UUID": 123,
"filename": foo.exe,
"sha256": <hash>,
"installPath": ["C:/Users/Test/Downloads/"]
}
surfactant cli find --file ../test.exe # File matches are found by hash matching, not filename matches.
{
"UUID": 456,
"filename": test.exe,
"sha256": <hash>,
"installPath": ["C:/Users/Test/Documents/"]
}
```
### Example 2: Find Partial Matches
```bash
surfactant cli find --installpath C:/Users/Test/Downloads/
{
"UUID": 123,
"filename": foo.exe,
"sha256": <hash>
"installPath": ["C:/Users/Test/Downloads/"]
}
```

## surfactant cli add
The **cli add** command will allow users to easily add manual entries to an SBOM. This command should allow users to:
- Add key value pairs to existing SBOM entries
- Add whole new entries to the SBOM
- Add new installPaths based on existing containerPaths
### Adding a relationship
```bash
surfactant cli add --relationship "{xUUID:"123",yUUID:456, "relationship: "Uses"}" sbom.json
```
### Example 1: Adding a manual entry
```bash
surfactant cli add --entry "{UUID:"123",filename:"test.exe", "sha256": "3423csdlkf13048kj"}" sbom.json
```
### Example 2: Adding an entry by file
```bash
surfactant cli add --file test.exe sbom.json
```
### Example 3: Creating new installPaths from containerPaths
```bash
surfactant cli add --installPath 123/ /bin/ sbom.json
```
Our SBOM before the `cli add` command:
```bash
{
"UUID": 456,
"filename": test.exe,
"sha256": <hash>
"installPath": [],
"containerPath": ["123/helpers/test/exe"]
}
```
Our SBOM after the `cli add` command:
```bash
{
"UUID": 456,
"filename": test.exe,
"sha256": <hash>
"installPath": ["/bin/helpers/test.exe"],
"containerPath": ["123/helpers/test.exe"]
}
```

## surfactant cli save
The **cli save** command saves the edited sbom to the output file specified.

### Example:
```bash
surfactant cli save new_sbom.json
```
