# Command Line Override for Database Sources

In addition to the configuration file (`database_sources.toml`), Surfactant supports overriding database URLs directly through the command line. This feature allows users to set custom database URLs without needing to modify the configuration files manually.

## Command for Overriding Database URLs

Use the following command to override the URL for a specific database category and library:

```bash
surfactant config sources.<category>.<library> <new_url>
```

Example Usage

To override the URL for the retirejs library in the js_library_patterns category, use the following command:

```bash
surfactant config sources.js_library_patterns.retirejs https://new-url.com
```

This will update the database URL in Surfactant’s runtime configuration file, which will take precedence over any values in database_sources.toml.

Precedence Order

    1. Command Line Override (surfactant config override-db-url <category.library> <new_url>) — Highest precedence.

    2. docs/database_sources.toml — Secondary source for database URLs.

    3. Hardcoded URLs in the Source Code — Last fallback option if no URL is provided through the command line or configuration file.


# Database Sources

Surfactant supports external configuration for pattern database URLs via a central TOML file. This file is hosted on [ReadTheDocs](https://surfactant.readthedocs.io/en/latest/external_databases.html) and enables maintainers to update database source URLs independently of a new Surfactant release. The file can also be find in the [directory tree](https://github.com/LLNL/Surfactant/blob/main/docs/database_sources.toml)

## TOML File

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
```

## Adding a New Category

To add a new database category, follow these steps:

1. Open the `database_sources.toml` file in your docs directory.
2. Under the `[sources]` section, add a new table for your category. For example:

   ```toml
   [sources.your_category]
   your_db_key = "https://your.domain/path/to/database.json"
   ```

3. Save and commit your changes.
4. Update any plugin code to reference the new category name when fetching overrides.
5. Run `surfactant plugin update-db <plugin_name>` to fetch and apply the new database.

Once added, Surfactant will automatically pick up the new URL override without requiring a new release.
