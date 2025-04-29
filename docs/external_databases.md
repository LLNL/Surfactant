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
