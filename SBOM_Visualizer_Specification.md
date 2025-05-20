# SBOM Visualizer Specification

## Overview
The SBOM Visualizer is a web application built with pure HTML, CSS, and JavaScript (no Node.js or other server-side engines) that allows users to upload and visualize Software Bill of Materials (SBOM) files. The key feature is the ability to identify and highlight common dependencies across multiple SBOMs.

## Core Requirements

### Technical Requirements
- Use only HTML, CSS, and JavaScript (no frameworks or libraries requiring Node.js)
- Support for uploading and parsing JSON SBOM files
- Static visualization (no interactive movements of elements)
- Clear highlighting of common dependencies across multiple SBOMs
- Hash validation to identify components with matching names but different hash values
- Ability to rank and sort components by shared dependency prevalence or validation status
- Ability to align components by primary file name across SBOMs, using placeholders for missing items

### User Interface Components

#### File Upload Section
- Multiple file upload capability for SBOMs
- Basic validation to ensure files are valid JSON
- Error handling for invalid files

#### Visualization Area
- Clear, well-organized display of SBOM components
- Static layout with no interactive movement
- Color-coded highlighting of common dependencies
- Visual indicators for hash conflicts (same name, different hash)
- Ability to display multiple SBOMs simultaneously
- Zoom in/out functionality for large SBOMs
- Ranking feature to sort components by shared dependency count or validation status
- Alignment feature to vertically align components by file name, with placeholders

#### Legend/Information Panel
- Display of color codes and what they represent
- Indicator for hash conflicts and validated files
- Indicator for aligned placeholders
- Count of common dependencies and hash conflicts
- Basic statistics about the uploaded SBOMs

## Data Structure and Processing

Based on the sample SBOMs provided, the application should:

1. Parse the JSON files to extract:
   - Software components (from the "software" array)
   - Dependencies (from "elfDependencies" or similar fields in metadata)
   - File names, versions, and other identifying information
   - Primary file name for each component (for alignment)
   - Cryptographic hash values (SHA256, SHA1, MD5) for components

2. Process the data to:
   - Create a unified graph of all components
   - Identify common dependencies across SBOMs
   - Compare hash values for components with the same name
   - Assign colors to dependencies based on commonality
   - Calculate dependency sharing scores for ranking
   - Calculate validation scores for ranking
   - Flag components with hash conflicts and validated files
   - Generate a master list of all unique primary file names for alignment

3. Render the visualization:
   - Group components by SBOM
   - Connect related components
   - Highlight common dependencies with distinct colors
   - Apply special styling for hash conflicts and validated files
   - Apply sorting when ranking is enabled
   - Apply alignment and render placeholders when alignment mode is active

## Visual Design

### Layout
- Each SBOM displayed as a separate column or section
- Dependencies shown as blocks or nodes within each SBOM
- Common dependencies visually highlighted
- Hash conflicts indicated with dotted borders and warning icons
- Validated files indicated with green borders and checkmark icons
- Aligned placeholders styled with dashed borders and italicized text

### Color Scheme
- Base color for standard components
- Gradient of highlight colors for dependencies based on how many SBOMs share them:
  - Unique dependencies: Light blue
  - Shared by 2 SBOMs: Yellow
  - Shared by 3+ SBOMs: Bright red
- Dotted borders in a contrasting color for hash conflicts
- Green borders for validated files
- Light grey dashed borders for placeholders

### Visual Elements
- Rectangular blocks for software components
- Nested blocks for hierarchical relationships
- Lines or connections between related components
- Color-coded borders or backgrounds for highlighting
- Dotted borders and warning icons for hash conflicts
- Green borders and checkmark icons for validated files
- Placeholder blocks for alignment

## Example Dependencies to Track

Based on the sample files, the application should focus on tracking:

1. Shared libraries (e.g., "libzmq.so.5", "libhelics.so.3")
2. System dependencies (e.g., "librt.so.1", "libc.so.6")
3. Package relationships and containment hierarchies

## Implementation Details

### HTML Structure
- Simple, responsive layout
- Form for file uploads
- Canvas or SVG for visualization
- Informational panels and legends
- Toolbar with ranking, alignment, and zoom controls

### CSS Styling
- Clean, modern aesthetic
- Responsive design (works on both desktop and tablets)
- Clear visual hierarchy of elements
- Effective use of color for highlighting common dependencies
- Visual indicators for active controls (like the ranking and alignment buttons)
- Distinct styling for hash conflicts (dotted borders, warning icons)
- Distinct styling for validated files (green borders, checkmark icons)
- Styling for component placeholders (dashed borders, italic text)

### JavaScript Functions
- File parsing and validation
- Data structure creation and manipulation
- Dependency identification algorithm
- Hash value comparison and conflict detection
- Component ranking and sorting algorithm (shared dependencies, validated files)
- Component alignment logic (master file list, placeholder generation)
- Rendering and visualization logic
- Export functionality (optional)

## Ranking Feature

The ranking feature allows users to sort components based on their dependency sharing patterns:

1. Component Ranking:
   - Calculate a "shared score" for each component based on its dependencies
   - Sort components with highest shared scores at the top
   - Update visualization dynamically when ranking is toggled

2. Dependency Ranking:
   - Within each component, sort dependencies by their prevalence across SBOMs
   - Display count indicators for shared dependencies when ranking is active
   - Maintain color coding for quick visual identification

## Hash Validation Feature

The hash validation feature helps identify files that have the same name but different content across SBOMs:

1. Hash Comparison:
   - Extract cryptographic hashes (SHA256, SHA1, MD5) from SBOM components
   - Compare hashes for components with matching names across different SBOMs
   - Flag components with conflicting hashes for visual highlighting

2. Conflict Visualization:
   - Apply dotted borders and warning indicators to components with hash conflicts
   - Provide tooltips with detailed information about the conflict
   - Display abbreviated hash values in component details
   - Track and display the total number of hash conflicts in statistics

## Validated Files Ranking Feature

Allows users to rank components based on the validation status of their dependencies.

1. Scoring:
   - Assign scores to dependencies: high positive for validated, negative for conflicts, small positive for shared but not validated.
   - Calculate a total validation score for each component.
2. Sorting:
   - Sort components by their total validation score (highest first).
   - Within components, sort dependencies to show validated ones first.
3. Visualization:
   - Display validation score in component details.
   - Use specific prefixes ([✓], [!], [N]) for dependencies.

## Alignment Feature

Allows users to vertically align components with the same primary file name across different SBOMs for easier visual comparison.

1. Primary File Name: 
   - Determined from the first entry in a component's `fileName` array, or its `name` as a fallback.
2. Master List Generation:
   - A sorted master list of all unique primary file names across all loaded SBOMs is created.
3. Rendering with Alignment:
   - Each SBOM column iterates through the master list.
   - If a component with the master file name exists in the current SBOM, it is rendered.
   - If not, a placeholder element is rendered in its position to maintain vertical alignment.
4. Placeholder Styling:
   - Placeholders are visually distinct (e.g., dashed border, italicized text indicating the missing component name).
5. Mode Exclusivity:
   - The alignment mode is mutually exclusive with the ranking modes. Activating alignment deactivates ranking, and vice-versa.

## Performance Considerations
- Efficient parsing of large JSON files (>5MB)
- Optimized rendering for complex visualizations
- Efficient hash comparison for conflict detection
- Efficient generation of master file list and lookup for alignment
- Progressive loading for large SBOMs
- Efficient sorting algorithms for the ranking feature

## Future Enhancements (Optional)
- Export visualization as image
- Filtering options for dependencies
- Detailed drill-down views of hash conflicts
- Simple search functionality
- Custom ranking criteria
- Hash conflict resolution suggestions 