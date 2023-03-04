A folder containing multiple separate SBOM JSON files can be combined using `merge_sbom.py`
with a command such the one below that gets a list of files using `ls`, and then uses `xargs`
to pass the resulting list of files to `merge_sbom.py` as arguments.

`ls -d ~/Folder_With_SBOMs/Surfactant-* | xargs -d '\n' python3.8 merge_sbom.py --config_file=merge_config.json --sbom_outfile combined_sbom.json`

If the config file option is given, a top-level system entry will be created that all other
software entries are tied to (directly or indirectly based on other relationships). Specifying
an empty UUID will make a random UUID get generated for the new system entry, otherwise it will
use the one provided.
