/**
 * SBOM Parser module
 * Handles parsing of SBOM JSON files
 */
class SBOMParser {
    constructor() {
        this.sboms = [];
        this.dependencies = {};
        this.dependencyCounts = {};
        this.hashConflicts = {}; // Track dependencies with same name but different hashes
        this.validatedFiles = {}; // Track dependencies with same name and matching hashes
        this.allPrimaryFileNames = new Set(); // For alignment feature
    }

    /**
     * Parse an SBOM JSON file
     * @param {Object} jsonData - Parsed JSON data
     * @param {String} fileName - Name of the file
     * @returns {Object} Processed SBOM data
     */
    parseSBOM(jsonData, fileName) {
        const sbomData = {
            fileName: fileName,
            id: this.sboms.length + 1,
            components: [],
            dependencies: []
        };

        // Check if the JSON has the expected structure
        if (!jsonData.software || !Array.isArray(jsonData.software)) {
            throw new Error("Invalid SBOM format: 'software' array not found");
        }

        // Process software components
        jsonData.software.forEach(component => {
            const componentName = this._getComponentName(component);
            const primaryFileName = this._getPrimaryFileName(component, componentName);
            
            const processedComponent = {
                uuid: component.UUID || 'unknown',
                name: componentName,
                primaryFileName: primaryFileName, // For alignment
                fileName: component.fileName ? component.fileName.join(', ') : 'unknown',
                version: component.version || 'unknown',
                dependencies: this._extractDependencies(component),
                // Store hash values for validation
                sha1: component.sha1 || null,
                sha256: component.sha256 || null,
                md5: component.md5 || null
            };

            this.allPrimaryFileNames.add(primaryFileName); // Add to global set
            sbomData.components.push(processedComponent);
            
            // Add dependencies to the SBOM's dependency list and track hash info
            processedComponent.dependencies.forEach(dep => {
                if (!sbomData.dependencies.includes(dep)) {
                    sbomData.dependencies.push(dep);
                }
                
                // Track global dependency counts
                if (!this.dependencyCounts[dep]) {
                    this.dependencyCounts[dep] = { count: 0, sboms: [], hashes: [] };
                }
                
                if (!this.dependencyCounts[dep].sboms.includes(sbomData.id)) {
                    this.dependencyCounts[dep].count++;
                    this.dependencyCounts[dep].sboms.push(sbomData.id);
                    
                    // Track hash information for this dependency
                    if (processedComponent.sha256 || processedComponent.sha1 || processedComponent.md5) {
                        const hashInfo = {
                            sbomId: sbomData.id,
                            name: processedComponent.name,
                            sha256: processedComponent.sha256,
                            sha1: processedComponent.sha1,
                            md5: processedComponent.md5
                        };
                        this.dependencyCounts[dep].hashes.push(hashInfo);
                        
                        // Check for hash conflicts and validated files
                        this._checkHashConflicts(dep);
                    }
                }
            });
        });

        return sbomData;
    }

    /**
     * Add a parsed SBOM to the collection
     * @param {Object} sbomData - Processed SBOM data
     */
    addSBOM(sbomData) {
        this.sboms.push(sbomData);
    }

    /**
     * Clear all parsed SBOMs
     */
    clearSBOMs() {
        this.sboms = [];
        this.dependencies = {};
        this.dependencyCounts = {};
        this.hashConflicts = {};
        this.validatedFiles = {};
        this.allPrimaryFileNames = new Set();
    }

    /**
     * Get all parsed SBOMs
     * @returns {Array} Array of parsed SBOMs
     */
    getSBOMs() {
        return this.sboms;
    }
    
    /** 
     * Get all unique primary file names across all SBOMs for alignment
     * @returns {Array} Sorted array of unique primary file names
     */
    getAllPrimaryFileNamesSorted() {
        // Convert Set to Array
        const fileNames = Array.from(this.allPrimaryFileNames);
        
        // Get dependency scores for each primary file name
        const fileScores = {};
        
        fileNames.forEach(fileName => {
            let totalScore = 0;
            
            // Find all components with this primary file name across all SBOMs
            this.sboms.forEach(sbom => {
                const component = sbom.components.find(c => c.primaryFileName === fileName);
                if (component && component.dependencies) {
                    // Sum up the dependency counts for this component
                    component.dependencies.forEach(dep => {
                        const count = this.dependencyCounts[dep]?.count || 0;
                        totalScore += count;
                    });
                }
            });
            
            fileScores[fileName] = totalScore;
        });
        
        // Sort by dependency score (highest first), then alphabetically as a fallback
        return fileNames.sort((a, b) => {
            const scoreA = fileScores[a] || 0;
            const scoreB = fileScores[b] || 0;
            
            if (scoreB !== scoreA) {
                return scoreB - scoreA; // Sort by score descending
            }
            
            return a.localeCompare(b); // Alphabetical as tiebreaker
        });
    }

    /**
     * Get dependency counts (how many SBOMs each dependency appears in)
     * @returns {Object} Dependency count data
     */
    getDependencyCounts() {
        return this.dependencyCounts;
    }

    /**
     * Get hash conflicts information
     * @returns {Object} Hash conflicts data
     */
    getHashConflicts() {
        return this.hashConflicts;
    }

    /**
     * Get validated files information
     * @returns {Object} Validated files data
     */
    getValidatedFiles() {
        return this.validatedFiles;
    }

    /**
     * Check if a dependency has a hash conflict
     * @param {String} dependency - Dependency name
     * @returns {Boolean} True if the dependency has a hash conflict
     */
    hasHashConflict(dependency) {
        return this.hashConflicts[dependency] === true;
    }

    /**
     * Check if a dependency is a validated file (same name, matching hash)
     * @param {String} dependency - Dependency name
     * @returns {Boolean} True if the dependency is validated
     */
    isValidatedFile(dependency) {
        return this.validatedFiles[dependency] === true;
    }

    /**
     * Extract a meaningful name for the component
     * @param {Object} component - SBOM component object
     * @returns {String} Component name
     * @private
     */
    _getComponentName(component) {
        if (component.name) {
            return component.name;
        } else if (component.fileName && component.fileName.length > 0) {
            // Use the first filename if name is not present
            return component.fileName[0];
        } else {
            return component.UUID || 'Unnamed Component';
        }
    }
    
    /**
     * Extract the primary file name for alignment.
     * This is typically the first entry in the component.fileName array, 
     * or the component's name if fileName is not available or empty.
     * @param {Object} component - SBOM component object
     * @param {String} componentName - The determined name of the component
     * @returns {String} Primary file name for the component
     * @private
     */
    _getPrimaryFileName(component, componentName) {
        if (component.fileName && component.fileName.length > 0) {
            return component.fileName[0];
        }
        return componentName; // Fallback to component name if no fileName
    }

    /**
     * Extract dependencies from a component
     * @param {Object} component - SBOM component object
     * @returns {Array} List of dependencies
     * @private
     */
    _extractDependencies(component) {
        const dependencies = [];
        
        // Check for ELF dependencies in metadata
        if (component.metadata && Array.isArray(component.metadata)) {
            component.metadata.forEach(meta => {
                if (meta.elfDependencies && Array.isArray(meta.elfDependencies)) {
                    meta.elfDependencies.forEach(dep => {
                        if (!dependencies.includes(dep)) {
                            dependencies.push(dep);
                        }
                    });
                }
            });
        }
        
        // Check for library names in fileName (for library files)
        if (component.fileName && Array.isArray(component.fileName)) {
            component.fileName.forEach(name => {
                if (name.startsWith('lib') && !dependencies.includes(name)) {
                    dependencies.push(name);
                }
            });
        }
        
        return dependencies;
    }

    /**
     * Check for hash conflicts in a dependency
     * @param {String} dependency - Dependency name
     * @private
     */
    _checkHashConflicts(dependency) {
        const hashes = this.dependencyCounts[dependency].hashes;
        if (hashes.length <= 1) {
            // Single instance, so it's neither a conflict nor validated
            this.hashConflicts[dependency] = false;
            this.validatedFiles[dependency] = false;
            return;
        }
        
        // Compare each hash to others
        let hasConflict = false;
        let isValidated = true; // Assume valid until we find a conflict
        
        // Function to compare two hash objects
        const hashesMatch = (hash1, hash2) => {
            // If we have SHA256, prefer that for comparison
            if (hash1.sha256 && hash2.sha256) {
                return hash1.sha256 === hash2.sha256;
            }
            // Otherwise try SHA1
            else if (hash1.sha1 && hash2.sha1) {
                return hash1.sha1 === hash2.sha1;
            }
            // Otherwise use MD5
            else if (hash1.md5 && hash2.md5) {
                return hash1.md5 === hash2.md5;
            }
            // If no comparable hashes, assume they don't match
            return false;
        };
        
        // Compare first hash with all others
        for (let i = 1; i < hashes.length; i++) {
            if (!hashesMatch(hashes[0], hashes[i])) {
                hasConflict = true;
                isValidated = false;
                break;
            }
        }
        
        // Mark this dependency as having a hash conflict or being validated
        this.hashConflicts[dependency] = hasConflict;
        this.validatedFiles[dependency] = isValidated && hashes.length > 1;
    }

    /**
     * Get dependency class based on how many SBOMs it appears in and its validation status
     * @param {String} dependency - Dependency name
     * @returns {String} CSS class name
     */
    getDependencyClass(dependency) {
        const count = this.dependencyCounts[dependency]?.count || 0;
        let cssClass = '';
        
        if (count >= 3) {
            cssClass = 'shared-dependency-3plus';
        } else if (count === 2) {
            cssClass = 'shared-dependency-2';
        } else {
            cssClass = 'unique-dependency';
        }
        
        // Add hash conflict or validated class if applicable
        if (this.hasHashConflict(dependency)) {
            cssClass += ' hash-conflict';
        } else if (this.isValidatedFile(dependency)) {
            cssClass += ' validated-file';
        }
        
        return cssClass;
    }

    /**
     * Get validation score for a component (for ranking)
     * @param {Object} component - Component data
     * @returns {Number} - Validation score
     */
    getValidationScore(component) {
        if (!component.dependencies || component.dependencies.length === 0) {
            return 0;
        }
        
        let score = 0;
        component.dependencies.forEach(dep => {
            if (this.isValidatedFile(dep)) {
                // Validated files get a high score
                score += 10;
            } else if (this.hasHashConflict(dep)) {
                // Hash conflicts get a negative score
                score -= 5;
            } else if (this.dependencyCounts[dep]?.count > 1) {
                // Common dependencies without validation get a small boost
                score += 1;
            }
        });
        
        return score;
    }
}

// Export the parser
window.SBOMParser = SBOMParser; 