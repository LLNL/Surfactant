import { toggleSidebar } from "#buttonEventHandlersModule";
import { buildNodeSelectionSidebar } from "#sidebarModule";
import { getCursor, setNodeColors, toggleNodePin } from "#utilsModule";

/**
 * Event handler when the user single clicks on the network canvas
 * @param {object} params
 */
export function clickEventHandler(params) {
	const nodeID = params.nodes[0];

	if (params.nodes.length !== 0) {
		// Reset selection highlight if use clicks away from search results
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
 * Event handler when the user right clicks on the network canvas
 * @param {object} params
 */
export function contextMenuEventHandler(params) {
	if (getCursor() === "grabbing") return; // Don't try to show menu if grabbing node

	const nodeID = this.getNodeAt(params.pointer.DOM);
	if (nodeID === undefined) return; // Didn't click on a node

	toggleNodePin(nodeID);
}
