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
        this.isAligned = false; // For alignment feature
        this.isGraphView = false; // New property for graph view
        this.isFullscreen = false; // Track fullscreen state
        
        // Add window resize handler
        window.addEventListener('resize', this._handleResize.bind(this));
    }

    /**
     * Handle window resize event, particularly useful for fullscreen mode
     * @private
     */
    _handleResize() {
        if (this.isFullscreen && this.isGraphView) {
            const container = this.container.querySelector('.graph-container');
            if (container) {
                const svg = container.querySelector('svg');
                if (svg) {
                    // Adjust SVG dimensions to fit viewport
                    svg.setAttribute("width", "95vw");
                    svg.setAttribute("height", "90vh");
                }
            }
        } else if (!this.isFullscreen) {
            // Handle normal view sizing
            const columnContainer = this.container.querySelector('.sbom-container');
            if (columnContainer) {
                // For column view, ensure vertical scrollbar with proper sizing
                columnContainer.style.overflow = 'auto';
                columnContainer.style.overflowX = 'auto';
                columnContainer.style.overflowY = 'scroll';
                columnContainer.style.maxHeight = '700px';
            }
            
            const graphContainer = this.container.querySelector('.graph-container');
            if (graphContainer) {
                // For graph view in normal mode
                graphContainer.style.overflow = 'auto';
                graphContainer.style.maxHeight = '100%';
            }
        }
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
        
        // Create container for visualization
        const visualizationContainer = document.createElement('div');
        visualizationContainer.style.transform = `scale(${this.zoom})`;
        visualizationContainer.style.transformOrigin = 'top left';
        
        if (this.isGraphView) {
            // Use graph view
            visualizationContainer.className = 'graph-container';
            // For graph view, handle scrolling within the container
            visualizationContainer.style.overflow = 'auto';
            visualizationContainer.style.maxHeight = '100%';
            this._renderGraphView(visualizationContainer, sboms, dependencyCounts);
        } else {
            // Use standard column view
            visualizationContainer.className = 'sbom-container';
            
            // For column view, ensure vertical scrollbar is present
            visualizationContainer.style.overflow = 'auto';
            visualizationContainer.style.overflowX = 'auto';
            visualizationContainer.style.overflowY = 'scroll';
            visualizationContainer.style.maxHeight = '700px'; // Set a fixed height to ensure scrollbar appears
            
            // Get master list of file names if alignment is active
            const masterFileNames = this.isAligned ? this.parser.getAllPrimaryFileNamesSorted() : null;

            // Render each SBOM as a column
            sboms.forEach(sbom => {
                const sbomColumn = this._createSBOMColumn(sbom, dependencyCounts, hashConflicts, validatedFiles, masterFileNames);
                visualizationContainer.appendChild(sbomColumn);
            });
        }
        
        // Clear and update container
        this.container.innerHTML = '';
        this.container.appendChild(visualizationContainer);
        
        // Update statistics
        this._updateStatistics(sboms, dependencyCounts, hashConflicts, validatedFiles);
    }

    /**
     * Toggle between standard view and graph view
     */
    toggleGraphView() {
        this._deactivateOtherModes('graph');
        this.isGraphView = !this.isGraphView;
        this.render();
        this._updateButtonState('graphViewBtn', this.isGraphView, 'Show Graph View', 'Show Column View');
    }

    /**
     * Toggle ranking of components by shared dependencies
     */
    toggleRanking() {
        this._deactivateOtherModes('rank');
        this.isRanked = !this.isRanked;
        this.render();
        this._updateButtonState('rankBtn', this.isRanked, 'Rank by Shared Dependencies', 'Default Order');
    }

    /**
     * Toggle ranking of components by validated files
     */
    toggleValidatedRanking() {
        this._deactivateOtherModes('validatedRank');
        this.isValidatedRanked = !this.isValidatedRanked;
        this.render();
        this._updateButtonState('rankValidatedBtn', this.isValidatedRanked, 'Rank by Validated Files', 'Default Order');
    }

    /**
     * Toggle alignment of components by primary file name
     */
    toggleAlignment() {
        this._deactivateOtherModes('align');
        this.isAligned = !this.isAligned;
        this.render();
        this._updateButtonState('alignBtn', this.isAligned, 'Align by Shared Dependencies', 'Default Layout');
    }

    /**
     * Deactivate other ranking/alignment modes
     * @param {string} currentMode - The mode being activated (e.g., 'rank', 'validatedRank', 'align', 'graph')
     * @private
     */
    _deactivateOtherModes(currentMode) {
        if (currentMode !== 'rank' && this.isRanked) {
            this.isRanked = false;
            this._updateButtonState('rankBtn', false, 'Rank by Shared Dependencies', 'Default Order');
        }
        if (currentMode !== 'validatedRank' && this.isValidatedRanked) {
            this.isValidatedRanked = false;
            this._updateButtonState('rankValidatedBtn', false, 'Rank by Validated Files', 'Default Order');
        }
        if (currentMode !== 'align' && this.isAligned) {
            this.isAligned = false;
            this._updateButtonState('alignBtn', false, 'Align by Shared Dependencies', 'Default Layout');
        }
        if (currentMode !== 'graph' && this.isGraphView) {
            this.isGraphView = false;
            this._updateButtonState('graphViewBtn', false, 'Show Graph View', 'Show Column View');
        }
    }

    /**
     * Update the UI state of a toolbar button
     * @param {string} buttonId - The ID of the button
     * @param {boolean} isActive - Whether the mode is active
     * @param {string} defaultText - Text when inactive
     * @param {string} activeText - Text when active
     * @private
     */
    _updateButtonState(buttonId, isActive, defaultText, activeText) {
        const button = document.getElementById(buttonId);
        if (button) {
            if (isActive) {
                button.classList.add('active');
                button.textContent = activeText;
            } else {
                button.classList.remove('active');
                button.textContent = defaultText;
            }
        }
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
     * @param {Array|null} masterFileNames - Sorted list of all primary file names (for alignment)
     * @returns {HTMLElement} - SBOM column element
     * @private
     */
    _createSBOMColumn(sbom, dependencyCounts, hashConflicts, validatedFiles, masterFileNames) {
        const column = document.createElement('div');
        column.className = 'sbom-column';
        
        // Add SBOM title
        const title = document.createElement('div');
        title.className = 'sbom-title';
        title.textContent = sbom.fileName;
        column.appendChild(title);
        
        if (this.isAligned && masterFileNames) {
            // Alignment mode: iterate master list and find/create components
            masterFileNames.forEach(masterName => {
                const component = sbom.components.find(c => c.primaryFileName === masterName);
                if (component) {
                    const componentEl = this._createComponentElement(component, dependencyCounts, hashConflicts, validatedFiles);
                    column.appendChild(componentEl);
                } else {
                    const placeholderEl = this._createPlaceholderElement(masterName);
                    column.appendChild(placeholderEl);
                }
            });
        } else {
            // Standard or Ranking mode: iterate SBOM components
            let components = [...sbom.components];
            
            if (this.isRanked) {
                // Calculate the total shared dependency score for each component
                components.forEach(component => {
                    let sharedScore = 0;
                    if (component.dependencies) {
                        component.dependencies.forEach(dep => {
                            const count = dependencyCounts[dep]?.count || 0;
                            sharedScore += count;
                        });
                    }
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
            }
            
            // Add components
            components.forEach(component => {
                const componentEl = this._createComponentElement(component, dependencyCounts, hashConflicts, validatedFiles);
                column.appendChild(componentEl);
            });
        }
        
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
        if (this.isRanked && typeof component.sharedScore !== 'undefined') {
            details.textContent += (details.textContent ? ' | ' : '') + `Score: ${component.sharedScore}`;
        } else if (this.isValidatedRanked && typeof component.validationScore !== 'undefined') {
            details.textContent += (details.textContent ? ' | ' : '') + `Validation: ${component.validationScore}`;
        }
        
        componentEl.appendChild(details);
        
        // Dependencies
        if (component.dependencies && component.dependencies.length > 0) {
            // Sort dependencies based on the active ranking mode
            let dependencies = [...component.dependencies];
            
            if (this.isRanked || this.isAligned) { // Also sort dependencies when aligned, for consistency
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
            }
            
            dependencies.forEach(dep => {
                const depEl = document.createElement('div');
                depEl.className = `dependency ${this.parser.getDependencyClass(dep)}`;
                
                // Build appropriate prefix based on ranking mode
                let prefix = '';
                const count = dependencyCounts[dep]?.count || 0;
                
                if ((this.isRanked || this.isAligned) && count > 1) { // Show count for shared rank and alignment
                    prefix = `[${count}] `;
                } else if (this.isValidatedRanked) {
                    if (this.parser.isValidatedFile(dep)) {
                        prefix = `[✓] `;
                    } else if (this.parser.hasHashConflict(dep)) {
                        prefix = `[!] `;
                    } else if (count > 1) {
                        prefix = `[${count}] `;
                    }
                }
                
                depEl.textContent = prefix + dep;
                
                // Add tooltip information
                let title = `Found in ${count} SBOM${count !== 1 ? 's' : ''}`;
                
                // Add validation or conflict information to tooltip
                if (this.parser.isValidatedFile(dep)) {
                    title += ' | VALIDATED: Hash values match across all SBOMs';
                } else if (this.parser.hasHashConflict(dep)) {
                    title += ' | WARNING: Hash values do not match across SBOMs';
                }
                
                depEl.setAttribute('title', title);
                
                componentEl.appendChild(depEl);
            });
        }
        
        return componentEl;
    }
    
    /**
     * Create a placeholder element for alignment mode
     * @param {string} masterName - The file name this placeholder is for
     * @returns {HTMLElement} - Placeholder element
     * @private
     */
    _createPlaceholderElement(masterName) {
        const placeholderEl = document.createElement('div');
        placeholderEl.className = 'component-placeholder';
        placeholderEl.textContent = `(No ${masterName})`;
        return placeholderEl;
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
        
        // Update UI
        document.getElementById('totalSboms').textContent = sboms.length;
        document.getElementById('totalComponents').textContent = totalComponents;
        document.getElementById('commonDependencies').textContent = commonDepsCount;
        document.getElementById('hashConflicts').textContent = hashConflictsCount;
        document.getElementById('validatedFiles').textContent = validatedFilesCount;
    }

    /**
     * Render graph view showing shared dependencies between SBOMs
     * @param {HTMLElement} container - Container element to render the graph in
     * @param {Array} sboms - Array of SBOM data
     * @param {Object} dependencyCounts - Object containing dependency count data
     * @private
     */
    _renderGraphView(container, sboms, dependencyCounts) {
        // Create SVG element for the graph with larger dimensions
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("width", "1800px");
        svg.setAttribute("height", "1500px");
        svg.classList.add("sbom-graph");
        
        // Create inspection box for detailed component info (static position)
        const inspectionBox = document.createElement("div");
        inspectionBox.className = "inspection-box";
        container.appendChild(inspectionBox);
        
        // Add fullscreen button
        const fullscreenBtn = document.createElement('button');
        fullscreenBtn.className = 'fullscreen-btn';
        fullscreenBtn.innerHTML = `
            <span class="fullscreen-icon">⛶</span>
            <span>Fullscreen</span>
        `;
        fullscreenBtn.addEventListener('click', () => this._toggleFullscreen(container));
        container.appendChild(fullscreenBtn);
        
        // Generate colors for each SBOM
        const sbomColors = this._generateSBOMColors(sboms.length);
        
        // Create a map of all shared dependencies
        const sharedDependencies = Object.entries(dependencyCounts)
            .filter(([_, data]) => data.count > 1)
            .map(([dependency, data]) => ({
                name: dependency,
                count: data.count,
                sboms: data.sboms
            }))
            .sort((a, b) => b.count - a.count);
        
        // Limit the number of dependencies to display based on SBOM count
        // For larger SBOM collections, show more significant dependencies
        const maxDependencies = Math.min(20, Math.max(10, Math.floor(sboms.length * 3)));
        const filteredDependencies = sharedDependencies.slice(0, maxDependencies);
        
        // Calculate positions for SBOMs (circular layout with more spacing)
        // Use larger center values to position the graph in the middle of the expanded SVG
        const centerX = 900;
        const centerY = 750;
        const sbomNodes = this._calculateSBOMPositions(sboms, centerX, centerY, 450);
        
        // Draw SBOM nodes
        sbomNodes.forEach((node, index) => {
            // Create a group for the SBOM node and its elements
            const sbomGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            sbomGroup.classList.add("sbom-node-group");
            sbomGroup.setAttribute("data-sbom-id", node.id);
            sbomGroup.setAttribute("data-name", node.name);
            sbomGroup.setAttribute("data-type", "sbom");
            
            // Add larger invisible clickable area first (so it's behind the visible node)
            const clickArea = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            clickArea.setAttribute("cx", node.x);
            clickArea.setAttribute("cy", node.y);
            clickArea.setAttribute("r", 55); // Even larger target area for better usability
            clickArea.setAttribute("fill", "transparent");
            clickArea.setAttribute("stroke", "transparent");
            clickArea.classList.add("node-click-area");
            sbomGroup.appendChild(clickArea);
            
            // Visual highlight for hover state (initially invisible)
            const hoverHighlight = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            hoverHighlight.setAttribute("cx", node.x);
            hoverHighlight.setAttribute("cy", node.y);
            hoverHighlight.setAttribute("r", 45); // Slightly larger than the node
            hoverHighlight.setAttribute("fill", "rgba(255, 255, 255, 0.2)");
            hoverHighlight.setAttribute("stroke", "#fff");
            hoverHighlight.setAttribute("stroke-width", "2");
            hoverHighlight.setAttribute("stroke-dasharray", "4,2");
            hoverHighlight.classList.add("node-hover-highlight");
            hoverHighlight.style.opacity = "0";
            sbomGroup.appendChild(hoverHighlight);
            
            // Visible node circle
            const sbomNode = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            sbomNode.setAttribute("cx", node.x);
            sbomNode.setAttribute("cy", node.y);
            sbomNode.setAttribute("r", 35); // Standard size
            sbomNode.setAttribute("fill", sbomColors[index]);
            sbomNode.setAttribute("stroke", "#333");
            sbomNode.setAttribute("stroke-width", "2");
            sbomNode.classList.add("sbom-node");
            sbomGroup.appendChild(sbomNode);
            
            // Add event listeners for inspection box to the group
            sbomGroup.addEventListener("mouseenter", (e) => {
                // Show hover effect
                hoverHighlight.style.opacity = "1";
                
                // Only show inspection box if not already pinned
                if (!inspectionBox.classList.contains("pinned")) {
                    this._showInspectionBox(inspectionBox, {
                        type: "sbom",
                        sbom: sboms.find(s => s.id === node.id),
                        sbomColors
                    });
                }
            });
            
            sbomGroup.addEventListener("mouseleave", () => {
                // Hide hover effect
                hoverHighlight.style.opacity = "0";
                
                // Only hide inspection box if not pinned
                if (!inspectionBox.classList.contains("pinned")) {
                    inspectionBox.classList.remove("visible");
                }
            });
            
            // Pin inspection box on click
            sbomGroup.addEventListener("click", (e) => {
                // Toggle pinned state
                const isPinned = inspectionBox.classList.contains("pinned");
                
                if (!isPinned) {
                    // Pin new content
                    this._showInspectionBox(inspectionBox, {
                        type: "sbom",
                        sbom: sboms.find(s => s.id === node.id),
                        sbomColors
                    });
                    inspectionBox.classList.add("pinned");
                } else {
                    // Unpin if clicking on the same node, otherwise change pinned content
                    const currentSbomId = inspectionBox.getAttribute("data-current-sbom-id");
                    if (currentSbomId === node.id.toString()) {
                        inspectionBox.classList.remove("pinned");
                    } else {
                        this._showInspectionBox(inspectionBox, {
                            type: "sbom",
                            sbom: sboms.find(s => s.id === node.id),
                            sbomColors
                        });
                    }
                }
            });
            
            // Add SBOM label (inside the group so it's part of the clickable area)
            const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
            label.setAttribute("x", node.x);
            label.setAttribute("y", node.y + 55); // Move further down
            label.setAttribute("text-anchor", "middle");
            label.setAttribute("fill", "#333");
            label.classList.add("sbom-label");
            label.textContent = this._truncateText(node.name, 20);
            
            // Add text background for better visibility and click handling
            const textBg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            const textWidth = label.textContent.length * 7; // Approximate width based on character count
            textBg.setAttribute("x", node.x - textWidth/2 - 3);
            textBg.setAttribute("y", node.y + 43);
            textBg.setAttribute("width", textWidth + 6);
            textBg.setAttribute("height", 18);
            textBg.setAttribute("fill", "white");
            textBg.setAttribute("fill-opacity", "0.7");
            textBg.setAttribute("rx", "3");
            
            // Add text elements to the group so they're part of the clickable area
            sbomGroup.appendChild(textBg);
            sbomGroup.appendChild(label);
            
            svg.appendChild(sbomGroup);
        });
        
        // Draw connections for shared dependencies (reduced to prevent clutter)
        filteredDependencies.forEach(dependency => {
            // Only draw lines between the first pair of SBOMs that share this dependency
            // This reduces visual clutter while still showing connections
            if (dependency.sboms.length >= 2) {
                const sbom1 = sbomNodes.find(node => node.id === dependency.sboms[0]);
                const sbom2 = sbomNodes.find(node => node.id === dependency.sboms[1]);
                
                if (sbom1 && sbom2) {
                    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                    line.setAttribute("x1", sbom1.x);
                    line.setAttribute("y1", sbom1.y);
                    line.setAttribute("x2", sbom2.x);
                    line.setAttribute("y2", sbom2.y);
                    line.setAttribute("stroke", "#999");
                    line.setAttribute("stroke-width", Math.min(4, dependency.count / 2));
                    line.setAttribute("stroke-opacity", "0.4");
                    line.classList.add("dependency-line");
                    line.setAttribute("data-dependency", dependency.name);
                    
                    svg.appendChild(line);
                }
            }
        });
        
        // Calculate better positions for dependency nodes based on SBOM relationships
        const depNodePositions = this._calculateDependencyPositions(filteredDependencies, sbomNodes, centerX, centerY);
        
        // Draw shared dependency nodes with better distribution
        filteredDependencies.forEach((dependency, index) => {
            const x = depNodePositions[index].x;
            const y = depNodePositions[index].y;
            
            // Create a group for the dependency node and its segments
            const depGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
            depGroup.classList.add("dependency-node-group");
            
            // Add data attributes for inspection
            depGroup.setAttribute("data-dependency", dependency.name);
            depGroup.setAttribute("data-count", dependency.count);
            depGroup.setAttribute("data-type", "dependency");
            
            // Calculate node size based on dependency count and number of SBOMs it's in
            // Ensure minimum visibility while avoiding excessive size
            const nodeRadius = Math.max(20, Math.min(30, 15 + dependency.count));
            
            // Instead of a single circle, create pie segments for each SBOM this dependency belongs to
            if (dependency.sboms.length > 1) {
                const segmentAngle = (2 * Math.PI) / dependency.sboms.length;
                
                dependency.sboms.forEach((sbomId, segmentIndex) => {
                    const startAngle = segmentIndex * segmentAngle;
                    const endAngle = (segmentIndex + 1) * segmentAngle;
                    
                    const startX = x + nodeRadius * Math.cos(startAngle);
                    const startY = y + nodeRadius * Math.sin(startAngle);
                    const endX = x + nodeRadius * Math.cos(endAngle);
                    const endY = y + nodeRadius * Math.sin(endAngle);
                    
                    // Create a path for the pie segment
                    const segmentPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
                    
                    // Path data: move to center, line to start point, arc to end point, close
                    const largeArcFlag = endAngle - startAngle > Math.PI ? 1 : 0;
                    const pathData = [
                        `M ${x} ${y}`,
                        `L ${startX} ${startY}`,
                        `A ${nodeRadius} ${nodeRadius} 0 ${largeArcFlag} 1 ${endX} ${endY}`,
                        'Z'
                    ].join(' ');
                    
                    segmentPath.setAttribute('d', pathData);
                    
                    // Get the SBOM color for this segment
                    const sbomIndex = sbomNodes.findIndex(node => node.id === sbomId);
                    const segmentColor = sbomColors[sbomIndex];
                    
                    segmentPath.setAttribute('fill', segmentColor);
                    segmentPath.setAttribute('stroke', '#333');
                    segmentPath.setAttribute('stroke-width', '0.5');
                    
                    depGroup.appendChild(segmentPath);
                });
            } else {
                // Fallback for any case where we don't have multiple SBOMs (shouldn't happen for shared deps)
                const depNode = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                depNode.setAttribute("cx", x);
                depNode.setAttribute("cy", y);
                depNode.setAttribute("r", nodeRadius);
                depNode.setAttribute("fill", "#eee");
                depNode.setAttribute("stroke", "#666");
                depNode.setAttribute("stroke-width", "1");
                
                depGroup.appendChild(depNode);
            }
            
            // Add larger transparent circle first for better click target
            const clickArea = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            clickArea.setAttribute("cx", x);
            clickArea.setAttribute("cy", y);
            clickArea.setAttribute("r", nodeRadius + 25); // Even larger target area
            clickArea.setAttribute("fill", "transparent");
            clickArea.setAttribute("stroke", "transparent");
            clickArea.classList.add("node-click-area");
            depGroup.appendChild(clickArea);
            
            // Visual highlight for hover state (initially invisible)
            const hoverHighlight = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            hoverHighlight.setAttribute("cx", x);
            hoverHighlight.setAttribute("cy", y);
            hoverHighlight.setAttribute("r", nodeRadius + 15);
            hoverHighlight.setAttribute("fill", "rgba(255, 255, 255, 0.2)");
            hoverHighlight.setAttribute("stroke", "#fff");
            hoverHighlight.setAttribute("stroke-width", "2");
            hoverHighlight.setAttribute("stroke-dasharray", "4,2");
            hoverHighlight.classList.add("node-hover-highlight");
            hoverHighlight.style.opacity = "0";
            depGroup.appendChild(hoverHighlight);
            
            // Add a smaller white circle in the center for better text visibility
            const centerCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            centerCircle.setAttribute("cx", x);
            centerCircle.setAttribute("cy", y);
            centerCircle.setAttribute("r", nodeRadius * 0.6);
            centerCircle.setAttribute("fill", "rgba(255, 255, 255, 0.7)");
            centerCircle.setAttribute("stroke", "#666");
            centerCircle.setAttribute("stroke-width", "0.5");
            depGroup.appendChild(centerCircle);
            
            // Add event listeners for inspection box
            depGroup.addEventListener("mouseenter", (e) => {
                // Show hover effect
                hoverHighlight.style.opacity = "1";
                
                // Only show if not already pinned
                if (!inspectionBox.classList.contains("pinned")) {
                    // Get detailed information about this dependency from all SBOMs it appears in
                    const detailedInfo = this._getDetailedDependencyInfo(dependency.name, dependency.sboms.map(id => sboms.find(s => s.id === id)));
                    
                    this._showInspectionBox(inspectionBox, {
                        type: "dependency",
                        dependency: dependency.name,
                        sboms: dependency.sboms.map(id => sboms.find(s => s.id === id)),
                        hashConflict: this.parser.hasHashConflict(dependency.name),
                        validated: this.parser.isValidatedFile(dependency.name),
                        sbomColors,
                        detailedInfo
                    });
                }
            });
            
            depGroup.addEventListener("mouseleave", () => {
                // Hide hover effect
                hoverHighlight.style.opacity = "0";
                
                // Only hide if not pinned
                if (!inspectionBox.classList.contains("pinned")) {
                    inspectionBox.classList.remove("visible");
                }
            });
            
            // Pin inspection box on click
            depGroup.addEventListener("click", (e) => {
                // Toggle pinned state
                const isPinned = inspectionBox.classList.contains("pinned");
                
                if (!isPinned) {
                    // Pin new content
                    const detailedInfo = this._getDetailedDependencyInfo(dependency.name, dependency.sboms.map(id => sboms.find(s => s.id === id)));
                    
                    this._showInspectionBox(inspectionBox, {
                        type: "dependency",
                        dependency: dependency.name,
                        sboms: dependency.sboms.map(id => sboms.find(s => s.id === id)),
                        hashConflict: this.parser.hasHashConflict(dependency.name),
                        validated: this.parser.isValidatedFile(dependency.name),
                        sbomColors,
                        detailedInfo
                    });
                    inspectionBox.classList.add("pinned");
                } else {
                    // Unpin if clicking on the same dependency, otherwise change pinned content
                    const currentDependency = inspectionBox.getAttribute("data-current-dependency");
                    if (currentDependency === dependency.name) {
                        inspectionBox.classList.remove("pinned");
                    } else {
                        const detailedInfo = this._getDetailedDependencyInfo(dependency.name, dependency.sboms.map(id => sboms.find(s => s.id === id)));
                        
                        this._showInspectionBox(inspectionBox, {
                            type: "dependency",
                            dependency: dependency.name,
                            sboms: dependency.sboms.map(id => sboms.find(s => s.id === id)),
                            hashConflict: this.parser.hasHashConflict(dependency.name),
                            validated: this.parser.isValidatedFile(dependency.name),
                            sbomColors,
                            detailedInfo
                        });
                    }
                }
            });
            
            // Add dependency label (inside the group so it's part of the clickable area)
            const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
            label.setAttribute("x", x);
            label.setAttribute("y", y + 5);
            label.setAttribute("text-anchor", "middle");
            label.setAttribute("fill", "#333");
            label.setAttribute("font-size", "12px");
            label.setAttribute("font-weight", "bold");
            label.classList.add("dependency-label");
            
            // Add a white background for better readability
            const labelBackground = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            const labelText = this._truncateText(dependency.name, 15);
            label.textContent = labelText;
            
            // Calculate background size based on text length
            const textWidth = labelText.length * 7; // Approximate width based on character count
            labelBackground.setAttribute("x", x - textWidth/2 - 3);
            labelBackground.setAttribute("y", y - 7);
            labelBackground.setAttribute("width", textWidth + 6);
            labelBackground.setAttribute("height", 18);
            labelBackground.setAttribute("fill", "white");
            labelBackground.setAttribute("fill-opacity", "0.85");
            labelBackground.setAttribute("rx", "3");
            
            // Add label elements to the group so they're part of the clickable area
            depGroup.appendChild(labelBackground);
            depGroup.appendChild(label);
            
            svg.appendChild(depGroup);
            
            // Draw ONE connection from this dependency to each SBOM (instead of all connections)
            // This dramatically reduces visual clutter
            dependency.sboms.forEach((sbomId, idx) => {
                // Only draw one connection to each SBOM
                const sbom = sbomNodes.find(node => node.id === sbomId);
                if (sbom) {
                    const sbomIndex = sbomNodes.findIndex(node => node.id === sbomId);
                    const connColor = sbomColors[sbomIndex];
                    
                    const connLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
                    connLine.setAttribute("x1", x);
                    connLine.setAttribute("y1", y);
                    connLine.setAttribute("x2", sbom.x);
                    connLine.setAttribute("y2", sbom.y);
                    connLine.setAttribute("stroke", connColor);
                    connLine.setAttribute("stroke-width", "2");
                    connLine.setAttribute("stroke-opacity", "0.8");
                    connLine.setAttribute("stroke-dasharray", "5,3");
                    connLine.classList.add("sbom-dependency-line");
                    
                    svg.appendChild(connLine);
                }
            });
        });
        
        container.appendChild(svg);
        
        // Add legend for SBOM colors
        const legend = document.createElement("div");
        legend.className = "graph-legend";
        
        sboms.forEach((sbom, index) => {
            const legendItem = document.createElement("div");
            legendItem.className = "graph-legend-item";
            
            const colorBox = document.createElement("div");
            colorBox.className = "color-box";
            colorBox.style.backgroundColor = sbomColors[index];
            
            const text = document.createElement("div");
            text.className = "legend-text";
            text.textContent = sbom.fileName;
            
            legendItem.appendChild(colorBox);
            legendItem.appendChild(text);
            legend.appendChild(legendItem);
        });
        
        container.appendChild(legend);
    }
    
    /**
     * Calculate better positions for dependency nodes based on SBOM relationships
     * @param {Array} dependencies - Dependencies to position
     * @param {Array} sbomNodes - SBOM nodes
     * @param {Number} centerX - X coordinate of the center
     * @param {Number} centerY - Y coordinate of the center
     * @returns {Array} Array of {x, y} position objects
     * @private
     */
    _calculateDependencyPositions(dependencies, sbomNodes, centerX, centerY) {
        const positions = [];
        const occupiedPositions = new Map(); // Track positions to avoid overlap
        const minDistance = 90; // Increased minimum distance between nodes
        
        // Add SBOM nodes to occupied positions first to avoid overlapping with them
        sbomNodes.forEach(node => {
            occupiedPositions.set(`sbom_${node.id}`, {
                x: node.x,
                y: node.y,
                radius: 55 // Match the SBOM click radius
            });
        });
        
        // Helper function to check if a position collides with any occupied positions
        const checkCollision = (x, y, nodeRadius) => {
            for (const [key, pos] of occupiedPositions.entries()) {
                const distance = Math.sqrt(Math.pow(x - pos.x, 2) + Math.pow(y - pos.y, 2));
                const requiredDistance = (nodeRadius || minDistance/2) + (pos.radius || minDistance/2);
                
                if (distance < requiredDistance) {
                    return {
                        collision: true,
                        angle: Math.atan2(y - pos.y, x - pos.x),
                        distance: distance,
                        required: requiredDistance
                    };
                }
            }
            return { collision: false };
        };
        
        // Position each dependency based on the SBOMs it's related to
        dependencies.forEach(dependency => {
            // Calculate node radius based on dependency count
            const nodeRadius = Math.max(20, Math.min(30, 15 + dependency.count));
            
            // Find all related SBOMs
            const relatedSBOMs = dependency.sboms.map(sbomId => 
                sbomNodes.find(node => node.id === sbomId)
            ).filter(Boolean);
            
            if (relatedSBOMs.length > 0) {
                // Calculate the center point between all related SBOMs
                let sumX = 0, sumY = 0;
                relatedSBOMs.forEach(sbom => {
                    sumX += sbom.x;
                    sumY += sbom.y;
                });
                
                // Initial position calculation based on number of related SBOMs
                let avgX, avgY;
                
                if (relatedSBOMs.length === 1) {
                    // For dependencies related to only one SBOM, position them closer to that SBOM
                    // but slightly pulled toward the center to avoid overlap
                    const sbom = relatedSBOMs[0];
                    const fromCenterX = sbom.x - centerX;
                    const fromCenterY = sbom.y - centerY;
                    const distanceFromCenter = Math.sqrt(fromCenterX * fromCenterX + fromCenterY * fromCenterY);
                    const pullFactor = 0.3; // How much to pull toward the SBOM (0 = at center, 1 = at SBOM)
                    
                    avgX = centerX + (fromCenterX / distanceFromCenter) * (distanceFromCenter * pullFactor);
                    avgY = centerY + (fromCenterY / distanceFromCenter) * (distanceFromCenter * pullFactor);
                } else if (relatedSBOMs.length === 2) {
                    // For dependencies shared by exactly 2 SBOMs, position them between the two SBOMs
                    // but slightly toward the center to prevent overlapping connection lines
                    const sbom1 = relatedSBOMs[0];
                    const sbom2 = relatedSBOMs[1];
                    
                    // Position between the two SBOMs with slight center bias
                    avgX = (sbom1.x + sbom2.x) / 2 * 0.8 + centerX * 0.2;
                    avgY = (sbom1.y + sbom2.y) / 2 * 0.8 + centerY * 0.2;
                } else {
                    // For dependencies related to 3+ SBOMs, position them closer to the center
                    // with a weighted average based on the SBOMs
                    const centerWeight = 0.4 + (Math.min(relatedSBOMs.length, 5) / 10); // 0.5 to 0.9
                    avgX = (sumX / relatedSBOMs.length) * (1 - centerWeight) + centerX * centerWeight;
                    avgY = (sumY / relatedSBOMs.length) * (1 - centerWeight) + centerY * centerWeight;
                }
                
                // Check for collisions with existing nodes
                let attempts = 0;
                let collision = checkCollision(avgX, avgY, nodeRadius);
                
                // Improved collision resolution with increasing force
                while (collision.collision && attempts < 30) { // Increased max attempts
                    // Move away from collision with increasing force on each attempt
                    const forceFactor = 1 + (attempts / 10); // Increases with attempts
                    const pushDistance = (collision.required - collision.distance) + 10;
                    
                    avgX += Math.cos(collision.angle) * pushDistance * forceFactor;
                    avgY += Math.sin(collision.angle) * pushDistance * forceFactor;
                    
                    // Add small random variation to prevent getting stuck
                    avgX += (Math.random() - 0.5) * 5 * attempts;
                    avgY += (Math.random() - 0.5) * 5 * attempts;
                    
                    // Check again
                    collision = checkCollision(avgX, avgY, nodeRadius);
                    attempts++;
                }
                
                // If we still have collisions after max attempts, try a different approach
                if (collision.collision) {
                    // Try positioning in a wider circle around the center
                    const radius = 200 + (Math.random() * 100);
                    const angle = Math.random() * 2 * Math.PI;
                    avgX = centerX + radius * Math.cos(angle);
                    avgY = centerY + radius * Math.sin(angle);
                    
                    // Try one more time to check for collisions
                    collision = checkCollision(avgX, avgY, nodeRadius);
                    if (collision.collision) {
                        // Final attempt - place it within safe boundaries
                        const safeX = Math.min(svgWidth - 150, Math.max(150, centerX + (Math.random() - 0.5) * 500));
                        const safeY = Math.min(svgHeight - 150, Math.max(150, centerY + (Math.random() - 0.5) * 400));
                        avgX = safeX;
                        avgY = safeY;
                    }
                }
                
                // Final safety check - ensure node is within SVG boundaries
                const svgWidth = 1800;
                const svgHeight = 1500;
                const margin = 100; // Margin from edge of SVG
                avgX = Math.min(svgWidth - margin, Math.max(margin, avgX));
                avgY = Math.min(svgHeight - margin, Math.max(margin, avgY));
                
                // Store final position
                positions.push({
                    x: avgX,
                    y: avgY
                });
                
                // Mark this position as occupied
                occupiedPositions.set(dependency.name, {
                    x: avgX,
                    y: avgY,
                    radius: nodeRadius + 25 // Match the dependency click radius
                });
                
            } else {
                // Fallback for dependencies not linked to any SBOMs (shouldn't happen)
                let finalX = centerX + (Math.random() - 0.5) * 300;
                let finalY = centerY + (Math.random() - 0.5) * 300;
                
                // Make sure even the fallback positions don't collide and stay within bounds
                const svgWidth = 1800;
                const svgHeight = 1500;
                const margin = 100; // Margin from edge of SVG
                
                let collision = checkCollision(finalX, finalY, nodeRadius);
                let attempts = 0;
                
                while (collision.collision && attempts < 20) {
                    // Create random position within safe bounds
                    finalX = Math.min(svgWidth - margin, Math.max(margin, centerX + (Math.random() - 0.5) * 400));
                    finalY = Math.min(svgHeight - margin, Math.max(margin, centerY + (Math.random() - 0.5) * 400));
                    collision = checkCollision(finalX, finalY, nodeRadius);
                    attempts++;
                }
                
                // Final safety check - ensure node is within SVG boundaries
                finalX = Math.min(svgWidth - margin, Math.max(margin, finalX));
                finalY = Math.min(svgHeight - margin, Math.max(margin, finalY));
                
                positions.push({
                    x: finalX,
                    y: finalY
                });
                
                // Mark position as occupied
                occupiedPositions.set(`fallback_${positions.length}`, {
                    x: finalX,
                    y: finalY,
                    radius: nodeRadius + 15
                });
            }
        });
        
        return positions;
    }

    /**
     * Get detailed information about a dependency from all SBOMs it appears in
     * @param {String} dependencyName - Name of the dependency
     * @param {Array} sboms - Array of SBOMs containing this dependency
     * @returns {Object} Detailed dependency information
     * @private
     */
    _getDetailedDependencyInfo(dependencyName, sboms) {
        const info = {
            files: new Set(),
            operatingSystems: new Set(),
            versions: new Set(),
            hashes: []
        };
        
        sboms.forEach(sbom => {
            // Look through all components in each SBOM to find this dependency
            sbom.components.forEach(component => {
                if (component.dependencies && component.dependencies.includes(dependencyName)) {
                    // Collect file names
                    if (component.fileName) {
                        component.fileName.split(',').forEach(file => {
                            info.files.add(file.trim());
                        });
                    }
                    
                    // Collect version info
                    if (component.version) {
                        info.versions.add(component.version);
                    }
                    
                    // Collect hash information
                    if (component.sha256 || component.sha1 || component.md5) {
                        info.hashes.push({
                            sbom: sbom.fileName,
                            sha256: component.sha256,
                            sha1: component.sha1,
                            md5: component.md5
                        });
                    }
                    
                    // Extract OS information from metadata if available
                    if (component.metadata) {
                        const osInfo = this._extractOSInfo(component.metadata);
                        if (osInfo) {
                            info.operatingSystems.add(osInfo);
                        }
                    }
                }
            });
        });
        
        return {
            files: Array.from(info.files),
            operatingSystems: Array.from(info.operatingSystems),
            versions: Array.from(info.versions),
            hashes: info.hashes
        };
    }
    
    /**
     * Extract operating system information from component metadata
     * @param {Array|Object} metadata - Component metadata
     * @returns {String|null} Operating system information if available
     * @private
     */
    _extractOSInfo(metadata) {
        // This is a simplified version - in a real app, you'd parse the actual metadata format
        if (Array.isArray(metadata)) {
            for (const meta of metadata) {
                if (meta.os || meta.operatingSystem || meta.platform) {
                    return meta.os || meta.operatingSystem || meta.platform;
                }
            }
        } else if (typeof metadata === 'object' && metadata !== null) {
            return metadata.os || metadata.operatingSystem || metadata.platform || null;
        }
        return null;
    }

    /**
     * Calculate positions for SBOM nodes in a circular layout
     * @param {Array} sboms - Array of SBOM data
     * @param {Number} centerX - X coordinate of the center
     * @param {Number} centerY - Y coordinate of the center
     * @param {Number} radius - Radius of the circle
     * @returns {Array} Array of node objects with x, y coordinates
     * @private
     */
    _calculateSBOMPositions(sboms, centerX, centerY, radius) {
        // Calculate a radius that ensures SBOMs are appropriately spaced
        // but still comfortably within the graph boundaries
        const svgWidth = 1800; // Match SVG width
        const svgHeight = 1500; // Match SVG height
        const nodeSize = 60; // Account for node size and some padding
        
        // Calculate the maximum safe radius to stay within boundaries
        const maxRadiusX = (svgWidth / 2) - nodeSize - 50; // 50px padding
        const maxRadiusY = (svgHeight / 2) - nodeSize - 50; // 50px padding
        const maxRadius = Math.min(maxRadiusX, maxRadiusY);
        
        // Calculate the ideal radius based on SBOM count, but cap it
        const idealRadius = radius * Math.min(1.2, Math.sqrt(sboms.length / 4));
        const adjustedRadius = Math.min(idealRadius, maxRadius * 0.9); // 90% of max for safety
        
        // Calculate positions in a standard circular layout with evenly distributed angles
        return sboms.map((sbom, index) => {
            // Regular circular distribution with 2*PI divided by the number of SBOMs
            const angle = (2 * Math.PI * index) / sboms.length;
            
            // Calculate position based on angle and the adjusted radius
            return {
                id: sbom.id,
                name: sbom.fileName,
                x: centerX + adjustedRadius * Math.cos(angle),
                y: centerY + adjustedRadius * Math.sin(angle)
            };
        });
    }
    
    /**
     * Generate an array of distinct colors for SBOMs
     * @param {Number} count - Number of colors to generate
     * @returns {Array} Array of color strings
     * @private
     */
    _generateSBOMColors(count) {
        const colors = [];
        const baseHues = [0, 60, 120, 180, 240, 300]; // Red, Yellow, Green, Cyan, Blue, Magenta
        
        for (let i = 0; i < count; i++) {
            const hue = baseHues[i % baseHues.length];
            const lightness = 50 + (Math.floor(i / baseHues.length) * 10);
            colors.push(`hsl(${hue}, 70%, ${lightness}%)`);
        }
        
        return colors;
    }
    
    /**
     * Truncate text to a maximum length
     * @param {String} text - Text to truncate
     * @param {Number} maxLength - Maximum length
     * @returns {String} Truncated text
     * @private
     */
    _truncateText(text, maxLength) {
        if (text.length <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength - 3) + '...';
    }

    /**
     * Display an inspection box with detailed information about an SBOM or dependency
     * @param {HTMLElement} inspectionBox - The inspection box element
     * @param {Object} data - Data for the inspection box
     * @private
     */
    _showInspectionBox(inspectionBox, data) {
        // Clear previous content
        inspectionBox.innerHTML = '';
        
        // Add a close button for pinned state
        const closeButton = document.createElement('div');
        closeButton.className = 'close-button';
        closeButton.innerHTML = '×';
        closeButton.addEventListener('click', (e) => {
            e.stopPropagation();
            inspectionBox.classList.remove('pinned');
            inspectionBox.classList.remove('visible');
        });
        inspectionBox.appendChild(closeButton);
        
        // Store current item data for reference
        if (data.type === 'sbom') {
            inspectionBox.setAttribute('data-current-sbom-id', data.sbom.id);
            inspectionBox.removeAttribute('data-current-dependency');
        } else if (data.type === 'dependency') {
            inspectionBox.setAttribute('data-current-dependency', data.dependency);
            inspectionBox.removeAttribute('data-current-sbom-id');
        }
        
        // Render appropriate content based on data type
        if (data.type === 'sbom') {
            // SBOM node inspection
            const sbom = data.sbom;
            
            const header = document.createElement('div');
            header.className = 'inspection-header';
            
            const title = document.createElement('h3');
            title.textContent = sbom.fileName;
            
            const colorDot = document.createElement('span');
            colorDot.className = 'color-indicator';
            colorDot.style.backgroundColor = data.sbomColors[sbom.id - 1]; // sbom ids are 1-indexed
            
            header.appendChild(colorDot);
            header.appendChild(title);
            inspectionBox.appendChild(header);
            
            const details = document.createElement('div');
            details.className = 'inspection-details';
            
            details.innerHTML = `
                <p><strong>Components:</strong> ${sbom.components.length}</p>
                <p><strong>Dependencies:</strong> ${sbom.dependencies.length}</p>
                <p><strong>UUID:</strong> ${sbom.id || 'N/A'}</p>
            `;
            
            inspectionBox.appendChild(details);
            
            if (sbom.components.length > 0) {
                const componentsList = document.createElement('div');
                componentsList.className = 'inspection-list';
                
                const topComponents = sbom.components.slice(0, 5); // Show only top 5
                
                const componentsTitle = document.createElement('div');
                componentsTitle.className = 'inspection-subtitle';
                componentsTitle.textContent = 'Top Components:';
                componentsList.appendChild(componentsTitle);
                
                topComponents.forEach(comp => {
                    const item = document.createElement('div');
                    item.className = 'inspection-item';
                    item.innerHTML = `
                        <span class="component-name">${comp.name}</span>
                        <span class="component-version">${comp.version !== 'unknown' ? comp.version : ''}</span>
                    `;
                    componentsList.appendChild(item);
                });
                
                if (sbom.components.length > 5) {
                    const more = document.createElement('div');
                    more.className = 'inspection-more';
                    more.textContent = `+${sbom.components.length - 5} more`;
                    componentsList.appendChild(more);
                }
                
                inspectionBox.appendChild(componentsList);
            }
        } else if (data.type === 'dependency') {
            // Dependency node inspection
            const header = document.createElement('div');
            header.className = 'inspection-header';
            
            // Add status indicator (validation/conflict)
            let statusIcon = '';
            if (data.validated) {
                statusIcon = '<span class="status-icon validated">✓</span>';
            } else if (data.hashConflict) {
                statusIcon = '<span class="status-icon conflict">⚠️</span>';
            }
            
            header.innerHTML = `
                <h3>${statusIcon}${data.dependency}</h3>
            `;
            inspectionBox.appendChild(header);
            
            const details = document.createElement('div');
            details.className = 'inspection-details';
            
            let statusText = '';
            if (data.validated) {
                statusText = '<p class="validation-status validated">Validated: Hash values match across all SBOMs</p>';
            } else if (data.hashConflict) {
                statusText = '<p class="validation-status conflict">Hash Conflict: Hash values do not match across SBOMs</p>';
            }
            
            details.innerHTML = `
                <p><strong>Found in:</strong> ${data.sboms.length} SBOMs</p>
                ${statusText}
            `;
            
            // Add the detailed information if available
            if (data.detailedInfo) {
                const detailedInfo = data.detailedInfo;
                
                // Files
                if (detailedInfo.files && detailedInfo.files.length > 0) {
                    details.innerHTML += `<p><strong>Files:</strong></p>`;
                    const filesList = document.createElement('ol');
                    filesList.style.marginLeft = '20px';
                    filesList.style.marginBottom = '8px';
                    
                    detailedInfo.files.forEach(file => {
                        const fileItem = document.createElement('li');
                        fileItem.textContent = file;
                        fileItem.style.wordBreak = 'break-all';
                        fileItem.style.fontSize = '12px';
                        fileItem.style.marginBottom = '4px';
                        filesList.appendChild(fileItem);
                    });
                    
                    details.appendChild(filesList);
                }
                
                // Versions
                if (detailedInfo.versions && detailedInfo.versions.length > 0) {
                    details.innerHTML += `<p><strong>Versions:</strong> ${detailedInfo.versions.join(', ')}</p>`;
                }
                
                // Operating Systems
                if (detailedInfo.operatingSystems && detailedInfo.operatingSystems.length > 0) {
                    details.innerHTML += `<p><strong>OS:</strong> ${detailedInfo.operatingSystems.join(', ')}</p>`;
                }
            }
            
            inspectionBox.appendChild(details);
            
            // List of SBOMs containing this dependency
            const sbomsList = document.createElement('div');
            sbomsList.className = 'inspection-list';
            
            const sbomsTitle = document.createElement('div');
            sbomsTitle.className = 'inspection-subtitle';
            sbomsTitle.textContent = 'Present in:';
            sbomsList.appendChild(sbomsTitle);
            
            data.sboms.forEach(sbom => {
                const sbomIndex = sbom.id - 1; // sbom ids are 1-indexed
                const item = document.createElement('div');
                item.className = 'inspection-item';
                
                const colorDot = document.createElement('span');
                colorDot.className = 'color-indicator';
                colorDot.style.backgroundColor = data.sbomColors[sbomIndex];
                
                const text = document.createElement('span');
                text.textContent = sbom.fileName;
                
                item.appendChild(colorDot);
                item.appendChild(text);
                sbomsList.appendChild(item);
            });
            
            inspectionBox.appendChild(sbomsList);
            
            // Hash information section
            if (data.detailedInfo && data.detailedInfo.hashes && data.detailedInfo.hashes.length > 0) {
                const hashesSection = document.createElement('div');
                hashesSection.className = 'inspection-list hashes-list';
                
                const hashesTitle = document.createElement('div');
                hashesTitle.className = 'inspection-subtitle';
                hashesTitle.textContent = 'Hash Information:';
                hashesSection.appendChild(hashesTitle);
                
                data.detailedInfo.hashes.forEach(hashInfo => {
                    const hashItem = document.createElement('div');
                    hashItem.className = 'inspection-item hash-item';
                    
                    let hashText = `<strong>${hashInfo.sbom}</strong>:<br>`;
                    
                    if (hashInfo.sha256) {
                        hashText += `SHA256: ${hashInfo.sha256.substring(0, 10)}...<br>`;
                    }
                    if (hashInfo.sha1) {
                        hashText += `SHA1: ${hashInfo.sha1.substring(0, 10)}...<br>`;
                    }
                    if (hashInfo.md5) {
                        hashText += `MD5: ${hashInfo.md5.substring(0, 10)}...`;
                    }
                    
                    hashItem.innerHTML = hashText;
                    hashesSection.appendChild(hashItem);
                });
                
                inspectionBox.appendChild(hashesSection);
            }
        }
        
        // Make the inspection box visible
        inspectionBox.classList.add("visible");
        inspectionBox.style.width = '350px';
        
        // Make box clickable to toggle pinned state when clicking inside it
        inspectionBox.addEventListener('click', (e) => {
            if (e.target === inspectionBox || e.target.closest('.inspection-header, .inspection-details, .inspection-list')) {
                e.stopPropagation();
                if (!inspectionBox.classList.contains('pinned')) {
                    inspectionBox.classList.add('pinned');
                }
            }
        });
    }

    /**
     * Toggle fullscreen mode for the graph view
     * @param {HTMLElement} container - The graph container element
     * @private
     */
    _toggleFullscreen(container) {
        this.isFullscreen = !container.classList.contains('fullscreen-graph');
        const fullscreenBtn = container.querySelector('.fullscreen-btn');
        const svg = container.querySelector('svg');
        
        if (!this.isFullscreen) {
            // Exit fullscreen
            container.classList.remove('fullscreen-graph');
            if (fullscreenBtn) {
                fullscreenBtn.innerHTML = `
                    <span class="fullscreen-icon">⛶</span>
                    <span>Fullscreen</span>
                `;
            }
            
            // Reset SVG size
            if (svg) {
                svg.setAttribute("width", "1800px");
                svg.setAttribute("height", "1500px");
            }
            
            // When exiting fullscreen, make sure parent container retains original height
            const visualizationContainer = container.parentElement;
            if (visualizationContainer) {
                visualizationContainer.style.height = '700px';
                
                // Restore appropriate scrolling behavior based on view type
                if (visualizationContainer.classList.contains('sbom-container')) {
                    // Column view - ensure vertical scrollbar
                    visualizationContainer.style.overflow = 'auto';
                    visualizationContainer.style.overflowX = 'auto';
                    visualizationContainer.style.overflowY = 'scroll';
                } else {
                    // Graph view - normal overflow behavior
                    visualizationContainer.style.overflow = 'auto';
                }
            }
            
            // Restore normal body scrolling
            document.body.style.overflow = 'auto';
            
        } else {
            // Enter fullscreen
            container.classList.add('fullscreen-graph');
            if (fullscreenBtn) {
                fullscreenBtn.innerHTML = `
                    <span class="fullscreen-icon">⛶</span>
                    <span>Exit Fullscreen</span>
                `;
            }
            
            // Make SVG larger in fullscreen mode
            if (svg) {
                // Use a bit less than viewport dimensions to ensure no unnecessary scrollbars
                svg.setAttribute("width", "95vw");
                svg.setAttribute("height", "90vh");
            }
            
            // Set appropriate fullscreen scrolling
            container.style.overflow = 'auto';
            
            // Prevent body scrolling while in fullscreen
            document.body.style.overflow = 'hidden';
        }
    }
}

// Export the visualizer
window.SBOMVisualizer = SBOMVisualizer; 