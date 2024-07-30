# Settings

This page details the non-plugin settings available within the Surfactant configuration file.
Each subsection should be prepended to the option name to form the complete option, e.g., `core.output_format`.

## core

- output_format
    - SBOM output format, see `--list-output-formats` for list of options; default is CyTRICS.
- recorded_institution
    - Name of user's institution.

## macho

- include_bindings_exports
    - Include bindings/exports information for Mach-O files.
- include_signature_content
    - Include signature content for Mach-O files.
