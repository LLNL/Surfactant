# Settings

This page details the non-plugin settings available within the Surfactant configuration file.
Each subsection should be prepended to the option name to form the complete option, e.g., `core.output_format`.
See the [this page](configuration_files.md#settings-configuration-file) for details on how to change settings using `surfactant config`.

## core

- output_format
    - SBOM output format, see `--list-output-formats` for list of options; default is CyTRICS.
- recorded_institution
    - Name of user's institution.

## macho

> Note: Mach-O file support requires installing Surfactant with the `macho` optional dependencies (e.g. `pipx install surfactant[macho]`).

- include_bindings_exports
    - Include bindings/exports information for Mach-O files.
- include_signature_content
    - Include signature content for Mach-O files.
