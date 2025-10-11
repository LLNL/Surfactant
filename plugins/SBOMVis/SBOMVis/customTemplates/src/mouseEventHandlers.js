import { toggleSidebar } from "#buttonEventHandlersModule";
import { buildNodeSelectionSidebar } from "#sidebarModule";
import {
	getCursor,
	isNodePinned,
	setNodeColors,
	toggleNodePin,
} from "#utilsModule";

/**
 * Event handler when the user single clicks on the network canvas
 * @param {object} params
 */
export function clickEventHandler(params) {
	const nodeID = params.nodes[0];

	if (params.nodes.length !== 0) {
		// Reset selection highlight if user clicks away from search results
		const searchIsActive = !!document
			.getElementById("sidebar")
			.querySelector("#resultsSection");
		if (searchIsActive) setNodeColors(nodes.getIds());

		document
			.getElementById("sidebar")
			.replaceChildren(buildNodeSelectionSidebar(nodeID));
	}

	const sidebar = document.getElementById("sidebar");
	if (params.nodes.length !== 0 && !sidebar.classList.contains("open"))
		// Click on node to open sidebar
		toggleSidebar();

	if (params.nodes.length === 0 && sidebar.classList.contains("open"))
		// Click on canvas to close sidebar
		toggleSidebar();
}

/**
 * Event handler when the user double clicks on the network canvas
 * @param {object} params
 */
export function doubleClickEventHandler(params) {
	if (params.nodes.length > 0) {
		const nodeID = params.nodes[0];
		const clickedNode = nodes.get(nodeID);

		// Expand / retract child nodes of container when double clicked
		if (network.isCluster(nodeID)) network.openCluster(nodeID);
		else {
			if (clickedNode.nodeMetadata.type === "Container") {
				const childNodes = network.getConnectedNodes(nodeID, "from");

				const clusterOptions = {
					joinCondition: (_parentNodeOptions, childNodeOptions) => {
						return childNodes.includes(childNodeOptions.id); // Only cluster if ID matches
					},
					clusterNodeProperties: {
						id: `cluster:${nodeID}`,
						label: clickedNode.nodeMetadata.nodeFileName,
						surfactantSoftwareStruct: clickedNode.surfactantSoftwareStruct,
						nodeMetadata: clickedNode.nodeMetadata,
						shape: "dot",
						icon: {
							face: "'Font Awesome 6 Free'",
							weight: "900",
							code: "\uf1c6", // fa-file-zipper
							size: clickedNode.icon.size,
							color: clickedNode.icon.color,
						},
						font: {
							color: "white",
						},
						title: document.getElementById("tooltip"),
						fixed: { x: false, y: false },
					},
				};
				network.clusterByConnection(nodeID, clusterOptions); // Only clusters immediate child nodes
			}
		}
	}
}

/**
 * Adds or replaces the content of the #contextMenu element
 * @param {string} nodeID
 * @param {number} xPos X Position in the window
 * @param {number} yPos Y Position in the window
 */
function createContextMenu(nodeID, xPos, yPos) {
	const contextMenu = document.getElementById("contextMenu");
	contextMenu.style.left = `${xPos}px`;
	contextMenu.style.top = `${yPos}px`;
	contextMenu.style.visibility = "visible";

	contextMenu.addEventListener(
		"click",
		(e) => {
			e.stopPropagation();
		},
		{ once: true },
	);

	const frag = document.createDocumentFragment();

	// Pinned node toggle
	const nodePinned = isNodePinned(nodeID);
	const togglePinEntry = document.createElement("div");
	togglePinEntry.className = "contextMenuItem";
	togglePinEntry.addEventListener("click", () => {
		toggleNodePin(nodeID);
		createContextMenu(nodeID, xPos, yPos);
	});

	const togglePinIcon = document.createElement("i");
	togglePinIcon.className = nodePinned
		? "fa-solid fa-thumbtack-slash"
		: "fa-solid fa-thumbtack";
	togglePinEntry.appendChild(togglePinIcon);

	const togglePinText = document.createElement("span");
	togglePinText.textContent = nodePinned ? "Unpin node" : "Pin node";
	togglePinEntry.appendChild(togglePinText);

	frag.appendChild(togglePinEntry);

	// Delete node button
	const deleteNodeEntry = document.createElement("div");
	deleteNodeEntry.className = "contextMenuItem";
	deleteNodeEntry.addEventListener("click", () => {
		if (
			window.confirm(
				"Are you sure you want to delete this node?\nIt will not affect the underlying SBOM",
			)
		) {
			network.selectNodes([nodeID]);
			network.deleteSelected();
		}

		contextMenu.style.visibility = "hidden";
	});

	const deleteNodeIcon = document.createElement("i");
	deleteNodeIcon.className = "fa-solid fa-trash";
	deleteNodeEntry.appendChild(deleteNodeIcon);

	const deleteNodeText = document.createElement("span");
	deleteNodeText.textContent = "Delete node";
	deleteNodeEntry.appendChild(deleteNodeText);

	frag.appendChild(deleteNodeEntry);

	contextMenu.replaceChildren(frag);
}

/**
 * Event handler when the user right clicks on the network canvas
 * @param {object} params
 */
export function contextMenuEventHandler(params) {
	if (getCursor() === "grabbing") return; // Don't try to show menu if grabbing node

	const nodeID = this.getNodeAt(params.pointer.DOM);
	if (nodeID === undefined) return; // Didn't click on a node

	document.getElementsByClassName("vis-tooltip")[0].style.opacity = "0%"; // Hide tooltip

	createContextMenu(nodeID, params.pointer.DOM.x, params.pointer.DOM.y);
}
