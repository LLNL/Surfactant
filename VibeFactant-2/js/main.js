/**
 * Main application logic
 */
document.addEventListener('DOMContentLoaded', () => {
    // Initialize parser and visualizer
    const parser = new SBOMParser();
    const visualizer = new SBOMVisualizer('visualization', parser);
    
    // Get DOM elements
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const uploadedFilesList = document.getElementById('uploadedFiles');
    const visualizeBtn = document.getElementById('visualizeBtn');
    const rankBtn = document.getElementById('rankBtn');
    const rankValidatedBtn = document.getElementById('rankValidatedBtn');
    const zoomInBtn = document.getElementById('zoomIn');
    const zoomOutBtn = document.getElementById('zoomOut');
    const resetZoomBtn = document.getElementById('resetZoom');
    
    // Track uploaded files
    const uploadedFiles = [];
    
    // File upload handlers
    fileInput.addEventListener('change', handleFileSelect);
    
    // Drag and drop handlers
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('active');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('active');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('active');
        
        if (e.dataTransfer.files.length > 0) {
            handleFiles(e.dataTransfer.files);
        }
    });
    
    // Button click handlers
    visualizeBtn.addEventListener('click', visualizeSBOMs);
    rankBtn.addEventListener('click', () => visualizer.toggleRanking());
    rankValidatedBtn.addEventListener('click', () => visualizer.toggleValidatedRanking());
    zoomInBtn.addEventListener('click', () => visualizer.updateZoom(0.1));
    zoomOutBtn.addEventListener('click', () => visualizer.updateZoom(-0.1));
    resetZoomBtn.addEventListener('click', () => visualizer.resetZoom());
    
    /**
     * Handle file input change event
     * @param {Event} e - Change event
     */
    function handleFileSelect(e) {
        handleFiles(e.target.files);
    }
    
    /**
     * Process uploaded files
     * @param {FileList} files - List of uploaded files
     */
    function handleFiles(files) {
        if (files.length === 0) return;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            
            // Only process JSON files
            if (!file.name.endsWith('.json')) {
                showError(`File '${file.name}' is not a JSON file.`);
                continue;
            }
            
            // Check for duplicate files
            if (uploadedFiles.some(f => f.name === file.name)) {
                showError(`File '${file.name}' is already uploaded.`);
                continue;
            }
            
            // Add to uploaded files list
            uploadedFiles.push(file);
            addFileToList(file);
        }
        
        // Enable visualize button if files are uploaded
        visualizeBtn.disabled = uploadedFiles.length === 0;
    }
    
    /**
     * Add a file to the uploaded files list
     * @param {File} file - Uploaded file
     */
    function addFileToList(file) {
        const listItem = document.createElement('li');
        
        const fileName = document.createElement('span');
        fileName.textContent = file.name;
        listItem.appendChild(fileName);
        
        const removeBtn = document.createElement('button');
        removeBtn.textContent = '×';
        removeBtn.className = 'remove-file';
        removeBtn.addEventListener('click', () => removeFile(file, listItem));
        listItem.appendChild(removeBtn);
        
        uploadedFilesList.appendChild(listItem);
    }
    
    /**
     * Remove a file from the uploaded files list
     * @param {File} file - File to remove
     * @param {HTMLElement} listItem - List item element
     */
    function removeFile(file, listItem) {
        const index = uploadedFiles.indexOf(file);
        if (index !== -1) {
            uploadedFiles.splice(index, 1);
        }
        
        listItem.remove();
        
        // Disable visualize button if no files are uploaded
        visualizeBtn.disabled = uploadedFiles.length === 0;
    }
    
    /**
     * Visualize uploaded SBOMs
     */
    function visualizeSBOMs() {
        if (uploadedFiles.length === 0) {
            showError('Please upload at least one SBOM file.');
            return;
        }
        
        // Clear previous data
        parser.clearSBOMs();
        
        // Process each file
        let processedCount = 0;
        uploadedFiles.forEach(file => {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                try {
                    const jsonData = JSON.parse(e.target.result);
                    const sbomData = parser.parseSBOM(jsonData, file.name);
                    parser.addSBOM(sbomData);
                    
                    processedCount++;
                    
                    // When all files are processed, render the visualization
                    if (processedCount === uploadedFiles.length) {
                        visualizer.render();
                    }
                } catch (error) {
                    showError(`Error processing file '${file.name}': ${error.message}`);
                }
            };
            
            reader.onerror = () => {
                showError(`Error reading file '${file.name}'.`);
            };
            
            reader.readAsText(file);
        });
    }
    
    /**
     * Show an error message
     * @param {String} message - Error message
     */
    function showError(message) {
        console.error(message);
        alert(message);
    }
}); 