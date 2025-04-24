# External Database Sources Configuration

Surfactant supports external configuration for pattern database URLs via a central TOML file. This file is hosted on ReadTheDocs and enables maintainers to update database source URLs independently of a new Surfactant release.

## TOML File Structure

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
some_db = "https://example.com/native_patterns.json"

# Additional categories can be added as needed:
[sources.other_category]
other_db = "https://example.com/other_patterns.json"
