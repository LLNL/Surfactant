# Settings

This page details the non-plugin settings available within the Surfactant configuration file.
Each subsection should be prepended to the option name to form the complete option, e.g., `core.output_format`.
See the [this page](configuration_files.md#settings-configuration-file) for details on how to change settings using `surfactant config`.

## core

- output_format
    - SBOM output format, see `--list-output-formats` for list of options; default is CyTRICS.
- recorded_institution
    - Name of user's institution.
- include_all_files
    - Include all files in the SBOM (default). Set to `false` to only include files with types recognized by Surfactant; default is `true`.

## docker

- enable_docker_scout
    - Controls whether Docker Scout is enabled. Default is `true`. Docker Scout must be installed on the same system as Surfactant to work. To disable Docker Scout and/or suppress the message about installing Docker Scout, run `surfactant config docker.enable_docker_scout false`.

## macho

> Note: Mach-O file support requires installing Surfactant with the `macho` optional dependencies (e.g. `pipx install surfactant[macho]`).

- include_bindings_exports
    - Include bindings/exports information for Mach-O files.
- include_signature_content
    - Include signature content for Mach-O files.

## sources

Surfactant supports overriding database source URLs via the sources section in the settings configuration file. Each option is of the form <category>.<library>, where <category> is a database category (e.g., js_library_patterns or native_library_patterns), and <library> is the specific database key. See the [databases](https://surfactant.readthedocs.io/en/latest/external_databases.html) section for more information about the hosted list of database patterns. Note that this section is to override specific urls in the hosted list.

- sources.<category>.<library>

    - Override the URL for the specified database at runtime. Values set via surfactant config take precedence over entries in `database_sources.toml` and hard-coded defaults.

    - Usage:

        ```bash
        surfactant config sources.<category>.<library> <new_url>
        ```

    - Example:

        ```bash
        surfactant config sources.js_library_patterns.retirejs https://new-url.com
        ```
