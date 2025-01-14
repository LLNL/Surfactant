# Internal Implementation

Surfactant is built around a plugin architecture, allowing other developers to extend its functionality. Most of the functionality Surfactant has for generating an SBOM is also implemented using the same set of hooks that are available for others. The [plugins](plugins.md) page has more information on how to write a plugin for Surfactant.

The following diagram gives a rough overview of how Surfactant works internally, and shows when some of the main types of plugin hooks get called when generating an SBOM.

![Surfactant Internal Design](img/surfactant_internal_sbom_generate_diagram.svg)
