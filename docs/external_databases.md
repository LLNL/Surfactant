# Pattern Database Sources

Surfactant supports external configuration for pattern database URLs via a central TOML file. This file is hosted on [ReadTheDocs](https://surfactant.readthedocs.io/en/latest/external_databases.html) and enables maintainers to update database source URLs independently of a new Surfactant release. The file can be found in the [Surfactant git repository](https://github.com/LLNL/Surfactant/blob/main/docs/database_sources.toml), and when running Surfactant from an editable install the copy of the file in your local source code checkout will be used (and can be modified).

## Command for Overriding Database URLs

Surfactant supports overriding database URLs directly through the command line. This feature allows users to set custom database URLs without needing to modify the configuration files manually.

Use the following command to override the URL for a specific database category and library:

```bash
surfactant config sources.<category>.<library> <new_url>
```

Example Usage

To override the URL for the retirejs library in the js_library_patterns category, use the following command:

```bash
surfactant config sources.js_library_patterns.retirejs https://new-url.com
```

This will update the database URL in Surfactant’s runtime configuration file, which will take precedence over any values in the ReadTheDocs (or local git cloned for editable installs) `database_sources.toml` file.

Precedence Order:

    1. Command Line Override (surfactant config override-db-url <category.library> <new_url>) — Highest precedence

    2. docs/database_sources.toml — Only used when running Surfactant from an editable install from a clone of the git repo (e.g. developers adding features to Surfactant)

    3. ReadTheDocs hosted database_sources.toml — Most common source for the URLs, for the typical user

    4. Hardcoded URLs in the Source Code — Last fallback option if no URL is provided through the command line or configuration file


## Database Sources TOML File

Surfactant supports external configuration for pattern database URLs via a central TOML file. This file is hosted on [ReadTheDocs](https://surfactant.readthedocs.io/en/latest/external_databases.html) and enables maintainers to update database source URLs independently of a new Surfactant release. The file that gets added to the ReadTheDocs site can be found at [docs/database_sources.toml](https://github.com/LLNL/Surfactant/blob/main/docs/database_sources.toml) in the Surfactant git repository. Users running Surfactant from an editable install of a git clone of Surfactant can modify this local copy of the file to override URLs (e.g. for testing changes).

### TOML File Format

The configuration file, `database_sources.toml`, is organized into several sections:

```toml
[metadata]
version = "1.0"
last_updated = "2025-04-24"

[sources]
# JavaScript libraries
[sources.js_library_patterns]
retirejs = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json"

# Native libraries
[sources.native_library_patterns]
emba = "https://raw.githubusercontent.com/e-m-b-a/emba/11d6c281189c3a14fc56f243859b0bccccce8b9a/config/bin_version_strings.cfg"

# Additional categories can be added as needed:
[sources.other_category]
other_db = "https://example.com/other_patterns.json"
