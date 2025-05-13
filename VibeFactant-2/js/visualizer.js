/**
 * SBOM Visualizer module
 * Renders SBOM data in the visualization container
 */
class SBOMVisualizer {
    constructor(containerId, parser) {
        this.container = document.getElementById(containerId);
        this.parser = parser;
        this.zoom = 1;
        this.isRanked = false;
        this.isValidatedRanked = false;
        this.isAligned = false;
        this.alignmentMap = new Map(); // Maps dependency names to their aligned positions
    }

    /**
     * Render the visualization of SBOMs
     */
    render() {
        const sboms = this.parser.getSBOMs();
        const dependencyCounts = this.parser.getDependencyCounts();
        const hashConflicts = this.parser.getHashConflicts();
        const validatedFiles = this.parser.getValidatedFiles();
        
        if (sboms.length === 0) {
            this.container.innerHTML = '<div class="no-data">No SBOMs to visualize. Please upload SBOM files first.</div>';
            return;
        }
        
        // Debug: Log alignment state before processing
        console.log("Rendering with alignment:", this.isAligned);
        
        // Create alignment map if alignment is enabled
        if (this.isAligned) {
            this._createAlignmentMap(sboms, dependencyCounts);
        } else {
            this.alignmentMap.clear();
        }
        
        // Debug: Log alignment map size
        console.log("Alignment map size:", this.alignmentMap.size);
        
        // Create container for SBOM columns
        const sbomContainer = document.createElement('div');
        sbomContainer.className = 'sbom-container';
        sbomContainer.style.transform = `scale(${this.zoom})`;
        sbomContainer.style.transformOrigin = 'top left';
        
        // Render each SBOM as a column
        const columnRefs = [];
        sboms.forEach(sbom => {
            const sbomColumn = this._createSBOMColumn(sbom, dependencyCounts, hashConflicts, validatedFiles);
            sbomContainer.appendChild(sbomColumn);
            columnRefs.push(sbomColumn);
        });
        
        // Clear and update container
        this.container.innerHTML = '';
        this.container.appendChild(sbomContainer);
        
        // Add alignment lines if alignment is enabled
        if (this.isAligned && sboms.length > 1) {
            this._addAlignmentLines(sbomContainer, columnRefs);
        }
        
        // Update statistics
        this._updateStatistics(sboms, dependencyCounts, hashConflicts, validatedFiles);
    }

    /**
     * Toggle alignment of matching files across SBOMs
     */
    toggleAlignment() {
        // If other rankings are active, turn them off
        if (this.isRanked) {
            this.isRanked = false;
            document.getElementById('rankBtn').classList.remove('active');
            document.getElementById('rankBtn').textContent = 'Rank by Shared Dependencies';
        }
        
        if (this.isValidatedRanked) {
            this.isValidatedRanked = false;
            document.getElementById('rankValidatedBtn').classList.remove('active');
            document.getElementById('rankValidatedBtn').textContent = 'Rank by Validated Files';
        }
        
        // Toggle alignment
        this.isAligned = !this.isAligned;
        
        // Update button UI state
        const alignBtn = document.getElementById('alignBtn');
        if (alignBtn) {
            if (this.isAligned) {
                alignBtn.classList.add('active');
                alignBtn.textContent = 'Disable Component Alignment';
            } else {
                alignBtn.classList.remove('active');
                alignBtn.textContent = 'Align Matching Components';
            }
        }
        
        // Recalculate alignments and re-render
        this.render();
        
        // Log alignment state to console for debugging
        console.log("Alignment toggled, current state:", this.isAligned);
    }

    /**
     * Toggle ranking of components by shared dependencies
     */
    toggleRanking() {
        // If validated ranking or alignment is active, turn them off
        if (this.isValidatedRanked) {
            this.isValidatedRanked = false;
            document.getElementById('rankValidatedBtn').classList.remove('active');
            document.getElementById('rankValidatedBtn').textContent = 'Rank by Validated Files';
        }
        
        if (this.isAligned) {
            this.isAligned = false;
            document.getElementById('alignBtn').classList.remove('active');
            document.getElementById('alignBtn').textContent = 'Align Matching Components';
        }
        
        // Toggle standard ranking
        this.isRanked = !this.isRanked;
        this.render();
        
        // Update button UI state
        const rankBtn = document.getElementById('rankBtn');
        if (rankBtn) {
            if (this.isRanked) {
                rankBtn.classList.add('active');
                rankBtn.textContent = 'Default Order';
            } else {
                rankBtn.classList.remove('active');
                rankBtn.textContent = 'Rank by Shared Dependencies';
            }
        }
    }

    /**
     * Toggle ranking of components by validated files
     */
    toggleValidatedRanking() {
        // If standard ranking or alignment is active, turn it off
        if (this.isRanked) {
            this.isRanked = false;
            document.getElementById('rankBtn').classList.remove('active');
            document.getElementById('rankBtn').textContent = 'Rank by Shared Dependencies';
        }
        
        if (this.isAligned) {
            this.isAligned = false;
            document.getElementById('alignBtn').classList.remove('active');
            document.getElementById('alignBtn').textContent = 'Align Matching Components';
        }
        
        // Toggle validated ranking
        this.isValidatedRanked = !this.isValidatedRanked;
        this.render();
        
        // Update button UI state
        const rankValidatedBtn = document.getElementById('rankValidatedBtn');
        if (rankValidatedBtn) {
            if (this.isValidatedRanked) {
                rankValidatedBtn.classList.add('active');
                rankValidatedBtn.textContent = 'Default Order';
            } else {
                rankValidatedBtn.classList.remove('active');
                rankValidatedBtn.textContent = 'Rank by Validated Files';
            }
        }
    }

    /**
     * Create an alignment map for common components across all SBOMs
     * @param {Array} sboms - Array of SBOM data
     * @param {Object} dependencyCounts - Dependency counts
     * @private
     */
    _createAlignmentMap(sboms, dependencyCounts) {
        if (!this.isAligned) {
            this.alignmentMap.clear();
            return;
        }
        
        this.alignmentMap.clear();
        
        // Create a master list of all component names across all SBOMs
        const allComponentNames = new Set();
        const componentSbomCounts = {};
        
        // First pass: collect all unique component names
        sboms.forEach(sbom => {
            if (!sbom || !sbom.components) return;
            
            sbom.components.forEach(component => {
                if (!component || !component.name) return;
                
                const name = component.name;
                allComponentNames.add(name);
                
                if (!componentSbomCounts[name]) {
                    componentSbomCounts[name] = new Set();
                }
                componentSbomCounts[name].add(sbom.fileName);
            });
        });
        
        // Convert to array and sort components
        const sortedComponents = Array.from(allComponentNames).map(name => {
            return {
                name: name,
                sbomCount: componentSbomCounts[name]?.size || 0,
                isShared: (componentSbomCounts[name]?.size || 0) > 1
            };
        });
        
        // Sort components: shared components first (ordered by SBOM count), then alphabetically
        sortedComponents.sort((a, b) => {
            // First criterion: shared vs. not shared
            if (a.isShared && !b.isShared) return -1;
            if (!a.isShared && b.isShared) return 1;
            
            // Second criterion: number of SBOMs (for shared components)
            if (a.isShared && b.isShared) {
                if (a.sbomCount !== b.sbomCount) {
                    return b.sbomCount - a.sbomCount;
                }
            }
            
            // Final criterion: alphabetical order
            return a.name.localeCompare(b.name);
        });
        
        // Assign positions to all components in the sorted order
        sortedComponents.forEach((comp, index) => {
            this.alignmentMap.set(comp.name, index);
        });
        
        console.log("Created alignment map with", this.alignmentMap.size, "components");
    }

    /**
     * Add visual alignment lines between aligned components
     * @param {HTMLElement} container - SBOM container
     * @param {Array} columns - Array of column elements
     * @private
     */
    _addAlignmentLines(container, columns) {
        if (!this.isAligned) return;
        
        // Delay to ensure DOM is ready
        setTimeout(() => {
            try {
                // Find all aligned components
                const alignedComponents = container.querySelectorAll('.aligned-component');
                
                // Group by component name
                const componentsByName = new Map();
                
                alignedComponents.forEach(comp => {
                    const compName = comp.dataset.componentName;
                    if (!compName) return;
                    
                    if (!componentsByName.has(compName)) {
                        componentsByName.set(compName, []);
                    }
                    componentsByName.get(compName).push(comp);
                });
                
                // Add alignment lines for each set of matching components
                componentsByName.forEach((components, compName) => {
                    if (components.length > 1) {
                        try {
                            // Find the y-position of each component
                            const positions = components.map(comp => {
                                const rect = comp.getBoundingClientRect();
                                const containerRect = container.getBoundingClientRect();
                                return {
                                    component: comp,
                                    top: rect.top - containerRect.top + container.scrollTop + rect.height / 2,
                                    left: rect.left - containerRect.left + container.scrollLeft
                                };
                            });
                            
                            // Calculate leftmost and rightmost positions
                            positions.sort((a, b) => a.left - b.left);
                            const leftmost = positions[0];
                            const rightmost = positions[positions.length - 1];
                            
                            // Create alignment line
                            const line = document.createElement('div');
                            line.className = 'alignment-line';
                            line.style.top = `${leftmost.top}px`;
                            line.style.left = `${leftmost.left}px`;
                            line.style.width = `${rightmost.left - leftmost.left}px`;
                            
                            container.appendChild(line);
                        } catch (err) {
                            console.error("Error creating alignment line for", compName, err);
                        }
                    }
                });
                
                console.log("Added alignment lines for", componentsByName.size, "component types");
            } catch (err) {
                console.error("Error in adding alignment lines:", err);
            }
        }, 200); // Increased delay to ensure DOM is fully rendered
    }

    /**
     * Update zoom level
     * @param {Number} delta - Amount to change zoom by
     */
    updateZoom(delta) {
        this.zoom += delta;
        
        // Limit zoom range
        if (this.zoom < 0.5) this.zoom = 0.5;
        if (this.zoom > 2) this.zoom = 2;
        
        const sbomContainer = this.container.querySelector('.sbom-container');
        if (sbomContainer) {
            sbomContainer.style.transform = `scale(${this.zoom})`;
        }
    }

    /**
     * Reset zoom to default level
     */
    resetZoom() {
        this.zoom = 1;
        const sbomContainer = this.container.querySelector('.sbom-container');
        if (sbomContainer) {
            sbomContainer.style.transform = `scale(${this.zoom})`;
        }
    }

    /**
     * Create a column for an SBOM
     * @param {Object} sbom - SBOM data
     * @param {Object} dependencyCounts - Global dependency counts
     * @param {Object} hashConflicts - Hash conflicts data
     * @param {Object} validatedFiles - Validated files data
     * @returns {HTMLElement} - SBOM column element
     * @private
     */
    _createSBOMColumn(sbom, dependencyCounts, hashConflicts, validatedFiles) {
        const column = document.createElement('div');
        column.className = 'sbom-column';
        
        // Add SBOM title
        const title = document.createElement('div');
        title.className = 'sbom-title';
        title.textContent = sbom.fileName;
        column.appendChild(title);
        
        // Get components and organize them based on active mode
        let components = [...sbom.components];
        
        if (this.isRanked) {
            // Calculate the total shared dependency score for each component
            components.forEach(component => {
                let sharedScore = 0;
                component.dependencies.forEach(dep => {
                    const count = dependencyCounts[dep]?.count || 0;
                    sharedScore += count;
                });
                component.sharedScore = sharedScore;
            });
            
            // Sort components by their shared dependency score (highest first)
            components.sort((a, b) => b.sharedScore - a.sharedScore);
        } else if (this.isValidatedRanked) {
            // Calculate the validation score for each component
            components.forEach(component => {
                component.validationScore = this.parser.getValidationScore(component);
            });
            
            // Sort components by their validation score (highest first)
            components.sort((a, b) => b.validationScore - a.validationScore);
        } else if (this.isAligned) {
            // Create a map of existing component names in this SBOM
            const existingComponentNames = new Map();
            components.forEach(component => {
                existingComponentNames.set(component.name, component);
            });
            
            // Create a new array with placeholders for all positions
            const newComponents = [];
            
            // Get maximum position from alignment map
            const maxPosition = Math.max(...Array.from(this.alignmentMap.values()));
            
            // For each position in the alignment map
            for (let position = 0; position <= maxPosition; position++) {
                // Find if any component should be at this position
                let found = false;
                
                // Check all component names in the alignment map
                for (const [name, pos] of this.alignmentMap.entries()) {
                    if (pos === position) {
                        // If this component should be at this position
                        if (existingComponentNames.has(name)) {
                            // This SBOM has this component
                            const component = existingComponentNames.get(name);
                            component.isAligned = true;
                            component.alignmentPosition = position;
                            newComponents.push(component);
                        } else {
                            // This SBOM doesn't have this component, add a placeholder
                            newComponents.push({
                                isPlaceholder: true,
                                name: `placeholder-${name}`,
                                displayName: name,
                                alignmentPosition: position
                            });
                        }
                        found = true;
                        break;
                    }
                }
                
                // If no component should be at this position, add an empty placeholder
                if (!found) {
                    newComponents.push({
                        isPlaceholder: true,
                        name: `placeholder-empty-${position}`,
                        alignmentPosition: position
                    });
                }
            }
            
            // Get components that don't have positions in alignment map
            const unmappedComponents = components.filter(comp => 
                !this.alignmentMap.has(comp.name) || 
                this.alignmentMap.get(comp.name) === undefined
            );
            
            // Use the new components array
            components = [...newComponents, ...unmappedComponents];
        }
        
        // Add components
        components.forEach(component => {
            // Skip rendering placeholder for empty slots (just add spacing div)
            if (component.isPlaceholder) {
                const placeholderEl = document.createElement('div');
                placeholderEl.className = 'component placeholder';
                placeholderEl.style.opacity = '0.3';
                placeholderEl.style.pointerEvents = 'none';
                
                // If it's a named placeholder (for a component not in this SBOM)
                if (component.displayName) {
                    placeholderEl.innerHTML = `<div class="placeholder-label">${component.displayName}</div>`;
                    placeholderEl.style.borderStyle = 'dashed';
                    placeholderEl.style.borderColor = '#aaa';
                    placeholderEl.style.opacity = '0.3';
                    placeholderEl.title = `${component.displayName} (not present in this SBOM)`;
                } else {
                    placeholderEl.innerHTML = '&nbsp;';
                }
                
                column.appendChild(placeholderEl);
                return;
            }
            
            const componentEl = this._createComponentElement(component, dependencyCounts, hashConflicts, validatedFiles);
            
            // Apply special alignment styles if needed
            if (this.isAligned && component.isAligned) {
                componentEl.classList.add('aligned-component');
                
                // Store component name for alignment lines
                componentEl.dataset.componentName = component.name;
                componentEl.dataset.alignmentPosition = component.alignmentPosition;
                
                // Add alignment indicator
                const indicator = document.createElement('div');
                indicator.className = 'alignment-indicator';
                componentEl.appendChild(indicator);
            }
            
            column.appendChild(componentEl);
        });
        
        return column;
    }

    /**
     * Create an element for a component
     * @param {Object} component - Component data
     * @param {Object} dependencyCounts - Global dependency counts
     * @param {Object} hashConflicts - Hash conflicts data
     * @param {Object} validatedFiles - Validated files data
     * @returns {HTMLElement} - Component element
     * @private
     */
    _createComponentElement(component, dependencyCounts, hashConflicts, validatedFiles) {
        const componentEl = document.createElement('div');
        componentEl.className = 'component';
        
        // Component name
        const name = document.createElement('div');
        name.className = 'component-name';
        name.textContent = component.name;
        componentEl.appendChild(name);
        
        // Component details
        const details = document.createElement('div');
        details.className = 'component-details';
        
        // Show version if available
        if (component.version && component.version !== 'unknown') {
            details.textContent = `Version: ${component.version}`;
        }
        
        // Show hash values if available (abbreviated)
        if (component.sha256) {
            const shortHash = component.sha256.substring(0, 8) + '...';
            details.textContent += (details.textContent ? ' | ' : '') + `SHA256: ${shortHash}`;
        } else if (component.sha1) {
            const shortHash = component.sha1.substring(0, 8) + '...';
            details.textContent += (details.textContent ? ' | ' : '') + `SHA1: ${shortHash}`;
        } else if (component.md5) {
            const shortHash = component.md5.substring(0, 8) + '...';
            details.textContent += (details.textContent ? ' | ' : '') + `MD5: ${shortHash}`;
        }
        
        // Show ranking score if applicable
        if (this.isRanked && component.sharedScore > 0) {
            details.textContent += (details.textContent ? ' | ' : '') + `Score: ${component.sharedScore}`;
        } else if (this.isValidatedRanked) {
            details.textContent += (details.textContent ? ' | ' : '') + `Validation: ${component.validationScore}`;
        } else if (this.isAligned && component.isAligned) {
            details.textContent += (details.textContent ? ' | ' : '') + `Aligned: ${component.name}`;
        }
        
        componentEl.appendChild(details);
        
        // Dependencies
        if (component.dependencies && component.dependencies.length > 0) {
            // Sort dependencies based on the active mode
            let dependencies = [...component.dependencies];
            
            if (this.isRanked) {
                // Sort by shared count
                dependencies.sort((a, b) => {
                    const countA = dependencyCounts[a]?.count || 0;
                    const countB = dependencyCounts[b]?.count || 0;
                    return countB - countA;
                });
            } else if (this.isValidatedRanked) {
                // Sort validated files first, then by shared count
                dependencies.sort((a, b) => {
                    const isValidatedA = this.parser.isValidatedFile(a);
                    const isValidatedB = this.parser.isValidatedFile(b);
                    
                    if (isValidatedA && !isValidatedB) return -1;
                    if (!isValidatedA && isValidatedB) return 1;
                    
                    // If both have same validation status, sort by count
                    const countA = dependencyCounts[a]?.count || 0;
                    const countB = dependencyCounts[b]?.count || 0;
                    return countB - countA;
                });
            } else if (this.isAligned) {
                // Sort aligned dependencies first
                dependencies.sort((a, b) => {
                    const isAlignedA = this.alignmentMap.has(a);
                    const isAlignedB = this.alignmentMap.has(b);
                    
                    if (isAlignedA && !isAlignedB) return -1;
                    if (!isAlignedA && isAlignedB) return 1;
                    
                    // If both are aligned, sort by alignment position
                    if (isAlignedA && isAlignedB) {
                        return this.alignmentMap.get(a) - this.alignmentMap.get(b);
                    }
                    
                    // Otherwise sort by count
                    const countA = dependencyCounts[a]?.count || 0;
                    const countB = dependencyCounts[b]?.count || 0;
                    return countB - countA;
                });
            }
            
            dependencies.forEach(dep => {
                const depEl = document.createElement('div');
                
                // Add appropriate classes
                let cssClass = this.parser.getDependencyClass(dep);
                if (this.isAligned && this.alignmentMap.has(dep)) {
                    cssClass += ' aligned-component';
                }
                depEl.className = `dependency ${cssClass}`;
                
                // Build appropriate prefix based on active mode
                let prefix = '';
                const count = dependencyCounts[dep]?.count || 0;
                
                if (this.isRanked && count > 1) {
                    prefix = `[${count}] `;
                } else if (this.isValidatedRanked) {
                    if (this.parser.isValidatedFile(dep)) {
                        prefix = `[✓] `;
                    } else if (this.parser.hasHashConflict(dep)) {
                        prefix = `[!] `;
                    } else if (count > 1) {
                        prefix = `[${count}] `;
                    }
                } else if (this.isAligned && this.alignmentMap.has(dep)) {
                    prefix = `[⟺] `;
                }
                
                depEl.textContent = prefix + dep;
                
                // Add tooltip information
                let title = `Found in ${count} SBOM${count !== 1 ? 's' : ''}`;
                
                // Add validation or alignment information to tooltip
                if (this.parser.isValidatedFile(dep)) {
                    title += ' | VALIDATED: Hash values match across all SBOMs';
                } else if (this.parser.hasHashConflict(dep)) {
                    title += ' | WARNING: Hash values do not match across SBOMs';
                }
                
                if (this.isAligned && this.alignmentMap.has(dep)) {
                    title += ' | ALIGNED: Positioned to match across SBOMs';
                }
                
                depEl.setAttribute('title', title);
                
                componentEl.appendChild(depEl);
            });
        }
        
        return componentEl;
    }

    /**
     * Update statistics in the UI
     * @param {Array} sboms - Array of SBOM data
     * @param {Object} dependencyCounts - Dependency counts
     * @param {Object} hashConflicts - Hash conflicts data
     * @param {Object} validatedFiles - Validated files data
     * @private
     */
    _updateStatistics(sboms, dependencyCounts, hashConflicts, validatedFiles) {
        // Count components across all SBOMs
        const totalComponents = sboms.reduce((sum, sbom) => sum + sbom.components.length, 0);
        
        // Count common dependencies (appear in more than 1 SBOM)
        const commonDepsCount = Object.values(dependencyCounts).filter(dep => dep.count > 1).length;
        
        // Count hash conflicts
        const hashConflictsCount = Object.values(hashConflicts).filter(conflict => conflict === true).length;
        
        // Count validated files
        const validatedFilesCount = Object.values(validatedFiles).filter(validated => validated === true).length;
        
        // Count aligned files
        const alignedFilesCount = this.isAligned ? this.alignmentMap.size : 0;
        
        // Update UI
        document.getElementById('totalSboms').textContent = sboms.length;
        document.getElementById('totalComponents').textContent = totalComponents;
        document.getElementById('commonDependencies').textContent = commonDepsCount;
        document.getElementById('hashConflicts').textContent = hashConflictsCount;
        document.getElementById('validatedFiles').textContent = validatedFilesCount;
        document.getElementById('alignedFiles').textContent = alignedFilesCount;
    }
}

// Export the visualizer
window.SBOMVisualizer = SBOMVisualizer; 