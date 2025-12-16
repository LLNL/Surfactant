## [1.0.1] - 2025-08-15
### 1. Schema Formatting Updates
- **Schema Version**: Altered regex to not allow for tags like alpha or the git hash
- **refs**:  Removed schema version from refs
- **countryOfOrigin**: Fixed issue where countryOfOrigin was missing the items

## [1.0.0] - 2025-07-16
### 1. Schema Metadata Updates

- **Schema Version**: Updated from V0.02 to 1.0.0
- **$id**: Changed from "CyTRICS_Schema_JSON_V0.02" to "CyTRICS_Schema_JSON_1.0.0"
- **Title**: Updated from "CyTRICS JSON Schema V0.02" to "CyTRICS JSON Schema 1.0.0"

### 2. Top-level Structure Changes

  #### 2.1 Removed Properties
  - "systems"
  - "analysisData"
  - "observations"
  - "starRelationships"
  - "annotations"

  #### 2.2 Added Properties
  - **bomUUID**: Reference to a new definition for Bill of Materials UUID
  - **bomFormat**: String, must be "cytrics"
  - **bomDescription**: String for describing the context of the BOM
  - **specVersion**: String, must be a valid semantic version
  - **tools**: Reference to a new definition for tools used in BOM creation
  - **authors**: Reference to a new definition for BOM authors

  #### 2.3 Required Fields
  - Added "bomFormat" and "specVersion" as required fields

### 3. Definitions Section Changes

  #### 3.1 Hardware Definition Updates

  - **UUID**: Now a required field
  - **captureTime**:
    - Old: number (UNIX epoch in seconds)
    - New: string with date-time format (RFC 3339)
    - Example: "2024-12-10T19:39:10Z"
  - **name**:
    - Old: single string
    - New: array of name objects with "nameValue" and "nameType"
    - Example:
      ```json
      {
        "nameValue": "LM2585S-12/NOPB",
        "nameType": "manufacturer part number (MPN)"
      }
      ```
  - **identifiers**: Now allows for unreadable characters represented by '?'
  - **comments**: Changed from string to array of comment objects
  - **packageType**: Updated examples
  - **Removed**: "provenance" field

  #### 3.2 Software Definition Updates

  - **UUID**: Now a required field
  - **captureTime**: Changed to string with date-time format (similar to hardware)
  - **name**: Now an array of name objects (similar to hardware)
  - **comments**: Changed from string to array of comment objects
  - **New fields**:
    - "notHashable": boolean flag
  - **Removed**: "components" field
  - **Hash fields** (sha1, sha256, md5):
    - Updated validation rules
    - At least one hash required unless "notHashable" is true

  #### 3.3 Relationships Definition Updates

  - Added "comments" field as an array of comment objects

  #### 3.4 New Definitions

  - **bomUUID**: Specifies UUID for Bill of Materials
  - **tools**: Array of objects describing tools used in BOM creation
  - **authors**: Array of objects describing BOM authors

  #### 3.5 Removed Definitions

  - "system"
  - "analysisData"
  - "observations"
  - "starRelationships"
  - "annotations"

### 4. Nested Definitions Changes

  #### 4.1 Removed Nested Definitions
  - All previous nested definitions have been removed

### 5. Shared Definitions Changes

  #### 5.1 File Object Updates
  - Modified structure to include more metadata
  - Added fields: "description", "category", "capturedBy", "captureTime", "source", "methodOfAcquisition"

  #### 5.2 New Shared Definitions
  - **commentEntry**:
    - Structure for comments including "fieldName", "comment", "author", "timestamp"
    - Example:
      ```json
      {
        "fieldName": "sha256",
        "comment": "hash was calculated from the primary binary only",
        "author": "Com M. Ent",
        "timestamp": "2024-12-10T19:39:10+00:00"
      }
      ```

### 6. General Improvements

- Enhanced descriptions for many fields, providing more context and examples
- Updated examples throughout the schema to reflect current best practices
- Added more specific enumerations for certain fields (e.g., hardware types, relationship types)
- Increased use of nested objects for better data organization and flexibility
- Standardized date-time fields to use RFC 3339 format instead of UNIX epoch
- Improved consistency in field naming and structure across different parts of the schema
