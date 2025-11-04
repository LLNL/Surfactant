# Interactive Demo

Try Surfactant directly in your browser without any installation!

## [🚀 Launch the Interactive Demo](demo.html)

The Surfactant Interactive Demo allows you to:

- **Upload Files**: Select files or directories from your computer to analyze
- **Generate SBOMs**: Create Software Bills of Materials in multiple formats (CyTRICS, SPDX, CSV)
- **Configure Settings**: Customize SBOM generation with various options
- **Manage Context**: Upload and download context configuration files
- **Instant Results**: See and download generated SBOMs immediately

## Features

### File Upload
- Drag and drop files or click to select
- Support for multiple files and directories
- Visual file list with size information

### SBOM Generation
The demo supports generating SBOMs with the following options:

- **Output Format**: Choose between CyTRICS (default), SPDX, or CSV
- **Skip Gather**: Skip the file gathering phase
- **Skip Relationships**: Don't generate relationship information
- **Skip Install Path**: Exclude install path information
- **Recorded Institution**: Add your organization name to the SBOM

### Context Configuration
Manage context configurations directly in the browser:

- Upload existing context configuration JSON files
- Edit context configurations in the built-in editor
- Download configurations to your computer
- Apply configurations to SBOM generation

### Settings
Customize the SBOM generation process:

- **Include All Files**: Include all files or only recognized types
- **Verbose Output**: Enable detailed output information

## Technology

The demo runs entirely in your browser using:

- **Pyodide**: Python runtime compiled to WebAssembly
- **Modern Web APIs**: File System Access API for file handling
- **Responsive Design**: Works on desktop and mobile devices

## Privacy

All processing happens locally in your browser. No files are uploaded to any server, ensuring your data remains private and secure.

## Limitations

Please note that the browser-based demo has some limitations compared to the full Surfactant installation:

- Not all Python dependencies may be available in the browser environment
- Large files or directories may take longer to process
- Some advanced features may have limited functionality
- For production use, we recommend installing Surfactant locally

## Getting Started

1. Visit the [Interactive Demo](demo.html)
2. Click on "Select Files/Directory to Analyze" or drag and drop files
3. Configure your desired settings
4. Click "Generate SBOM"
5. Download your generated SBOM

For full functionality and production use, please refer to the [Getting Started](getting_started.md) guide for local installation instructions.

## Feedback

If you encounter any issues or have suggestions for the demo, please [open an issue](https://github.com/LLNL/Surfactant/issues) on our GitHub repository.
