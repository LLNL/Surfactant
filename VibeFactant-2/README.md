# SBOM Visualizer

A lightweight, browser-based tool to visualize Software Bill of Materials (SBOM) files and highlight common dependencies across multiple SBOMs.

## Features

- Pure HTML, CSS, and JavaScript implementation (no server-side dependencies)
- Upload and parse SBOM JSON files
- Static visualization of SBOM components and dependencies
- Color-coded highlighting of common dependencies across multiple SBOMs
- Hash validation to identify components with matching names but different hash values
- Ranking feature to sort components by shared dependency count or validated files
- Basic statistics on components and dependencies
- Responsive design with zoom functionality

## Getting Started

1. Clone or download this repository
2. Open `index.html` in a web browser
3. Upload one or more SBOM JSON files using the file selector or drag-and-drop
4. Click "Visualize SBOMs" to generate the visualization
5. Use the ranking buttons to sort components based on different criteria:
   - "Rank by Shared Dependencies" prioritizes components with the most shared dependencies
   - "Rank by Validated Files" prioritizes components with files that have matching hashes across SBOMs

## How It Works

The visualizer analyzes the uploaded SBOM files to extract components and their dependencies. Each SBOM is displayed as a separate column, with components shown as rectangular blocks. Dependencies are highlighted with different colors based on how many SBOMs they appear in:

- Light blue: Unique dependencies (appear in only one SBOM)
- Yellow: Shared by 2 SBOMs
- Red: Shared by 3 or more SBOMs

This allows you to quickly identify common dependencies across your software components.

### Ranking Feature

The "Rank by Shared Dependencies" button sorts the components in each SBOM based on how many shared dependencies they contain. Components with the most shared dependencies appear at the top, making it easier to identify critical components with many common dependencies across your SBOMs.

When ranking is active:
- Components are sorted by their total dependency sharing score
- Dependencies within each component are sorted by how many SBOMs they appear in
- Dependencies show a count prefix (e.g., "[3] libzmq.so.5") for easier identification

### Hash Validation

The hash validation feature compares the cryptographic hashes of files with the same name across different SBOMs. If the same library or component appears in multiple SBOMs but with different hash values, it will be highlighted with a dotted border and warning indicator. This helps identify potential version discrepancies or tampered files.

- Components with hash conflicts are displayed with a dotted border and warning icon
- Hover tooltips provide additional information about the hash conflict
- The statistics panel shows the total number of hash conflicts found

### Validated Files Ranking

The "Rank by Validated Files" button sorts components based on how many of their dependencies have been validated by matching hash values across multiple SBOMs. This helps prioritize components that have been properly validated by cryptographic hashes.

When validated files ranking is active:
- Components are sorted by a validation score that prioritizes validated dependencies
- Validated dependencies (matching hashes) appear at the top of each component
- Dependencies are marked with special indicators:
  - `[✓]` for validated files (matching hashes across SBOMs)
  - `[!]` for hash conflicts (different hashes across SBOMs)
  - `[N]` for shared dependencies (appears in N SBOMs)
- Validated files are highlighted with a green border and checkmark
- The statistics panel shows the total number of validated files found

## Supported SBOM Format

The visualizer is designed to work with SBOM files that follow the structure shown in the sample files. Key elements that should be present:

- A `software` array containing component objects
- Each component should have either:
  - Metadata containing `elfDependencies` arrays
  - Library names in the `fileName` field
- Basic component information like UUID, name, version, etc.
- Cryptographic hashes (SHA256, SHA1, or MD5) for hash validation

## Browser Compatibility

The visualizer has been tested and works in modern browsers including:
- Chrome (latest)
- Firefox (latest)
- Edge (latest)
- Safari (latest)

## License

This project is available under the MIT License. See the LICENSE file for details.

## Sample Files

The repository includes sample SBOM files in the `samples` directory that can be used to test the visualizer. 