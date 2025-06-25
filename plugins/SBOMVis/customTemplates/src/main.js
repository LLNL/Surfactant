import {
	setButtonEventHandlers,
	toggleSidebar,
} from "#buttonEventHandlersModule";
import { buildNodeSelectionSidebar, buildSearchSidebar } from "#sidebarModule";

// This method is responsible for drawing the graph, returns the drawn network
function drawGraph() {
	const container = document.getElementById("mynetwork");

	// Insert tooltip element into nodes (title can be a string or element)
	for (const nodeID in nodes.get({ returnType: "Object" })) {
		nodes.update({ id: nodeID, title: document.getElementById("tooltip") });
	}

	const data = { nodes: nodes, edges: edges };

	options.interaction.hover = true;

	network = new vis.Network(container, data, options);

	if (options.physics.enabled === false)
		document.getElementById("physicsToggle").querySelector("i").classList =
			"fa-solid fa-circle-play";
	else if (nodes.length > 100) {
		network.on("stabilizationProgress", (params) => {
			document.getElementById("loadingBar").removeAttribute("style");
			const maxWidth = 496;
			const minWidth = 20;
			const widthFactor = params.iterations / params.total;
			const width = Math.max(minWidth, maxWidth * widthFactor);
			document.getElementById("bar").style.width = `${width}px`;
			document.getElementById("text").innerHTML =
				`${Math.round(widthFactor * 100)}%`;
		});
		network.once("stabilizationIterationsDone", () => {
			document.getElementById("text").innerHTML = "100%";
			document.getElementById("bar").style.width = "496px";
			document.getElementById("loadingBar").style.opacity = 0;
			// really clean the dom element
			setTimeout(() => {
				document.getElementById("loadingBar").style.display = "none";
			}, 500);
		});
	}

	function registerClickHandlers(onClick, onDoubleClick) {
		const clickThreshold = 250;
		let lastClickTime = 0;

		function clickHandler(e) {
			const newClickTime = new Date();
			if (newClickTime - lastClickTime > clickThreshold) {
				setTimeout(() => {
					if (newClickTime - lastClickTime > clickThreshold) onClick(e);
				}, clickThreshold);
			}
		}

		function doubleClickHandler(e) {
			lastClickTime = new Date();
			onDoubleClick(e);
		}

		network.on("click", clickHandler); // Vis.js doesn't distinguish between single clicks and double clicks: https://github.com/almende/vis/issues/203
		network.on("doubleClick", doubleClickHandler);
	}

	function onClick(params) {
		const nodeID = params.nodes[0];

		if (params.nodes.length !== 0) buildNodeSelectionSidebar(nodeID);

		const sidebar = document.getElementById("sidebar");
		if (params.nodes.length !== 0 && !sidebar.classList.contains("open"))
			// Click on node to open sidebar
			toggleSidebar();

		if (params.nodes.length === 0 && sidebar.classList.contains("open"))
			// Click on canvas to close sidebar
			toggleSidebar();

		//neighbourhoodHighlight(params);
	}
	function onDoubleClick(params) {
		if (params.nodes.length > 0) {
			const nodeID = params.nodes[0];
			const clickedNode = nodes.get(nodeID);

			// Expand / retract child nodes of container when double clicked
			if (network.isCluster(nodeID)) network.openCluster(nodeID);
			else {
				if (clickedNode.nodeMetadata.type === "Container") {
					const childNodes = network.getConnectedNodes(nodeID, "to");

					const clusterOptions = {
						joinCondition: (parentNodeOptions, childNodeOptions) => {
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
	registerClickHandlers(onClick, onDoubleClick);

	const networkCanvas = document
		.getElementById("mynetwork")
		.getElementsByTagName("canvas")[0];

	function changeCursor(newCursorStyle) {
		networkCanvas.style.cursor = newCursorStyle;
	}
	function getCursor() {
		return networkCanvas.style.cursor;
	}

	network.on("hoverNode", () => {
		changeCursor("grab");
	});
	network.on("blurNode", () => {
		changeCursor("default");
	});

	network.on("dragging", () => {
		changeCursor("grabbing");
	});
	network.on("dragEnd", () => {
		changeCursor("grab");
	});

	function createPopupElement(nodeID) {
		function insertOrUpdateInfoTable(data) {
			function createRow(leftColumnName, rightColumnName) {
				const row = document.createElement("tr");

				const leftColumn = document.createElement("td");
				leftColumn.innerText = leftColumnName;
				row.appendChild(leftColumn);

				const rightColumn = document.createElement("td");
				rightColumn.innerText = rightColumnName;
				row.appendChild(rightColumn);

				return row;
			}

			const infoTable = document.createElement("table");

			for (const r of data) infoTable.appendChild(createRow(r[0], r[1]));

			document.getElementById("tooltip-body").replaceChildren(infoTable);
		}

		function createNote(msg) {
			const containerNote = document.createElement("span");
			containerNote.classList = "footer";
			containerNote.innerText = msg;

			return containerNote;
		}

		if (network.isCluster(nodeID)) {
			const node = network.body.nodes[nodeID]; // Operates on newly created cluster:AAAA-BBBB node instead of the original
			document.getElementById("tooltip-header").innerText = node.options.label;

			insertOrUpdateInfoTable([
				["Contains", `${network.getNodesInCluster(nodeID).length - 1} Nodes`],
			]);

			const note = createNote("Double click to expand");
			document.getElementById("tooltip-infoTable").appendChild(note);
		} else {
			const node = nodes.get(nodeID);

			switch (node.nodeMetadata.type) {
				case "Container": {
					document.getElementById("tooltip-header").innerText = node.label; // Use label instead of file name to show pinning status

					insertOrUpdateInfoTable([
						[
							"Contains",
							`${network.getConnectedNodes(nodeID, "to").length} Nodes`,
						],
					]);

					const note = createNote("Double click to cluster");
					document.getElementById("tooltip-body").appendChild(note);

					break;
				}

				case "File": {
					document.getElementById("tooltip-header").innerText = node.label;

					insertOrUpdateInfoTable([
						["Uses", network.getConnectedNodes(nodeID, "from").length],
						["Is Used By", network.getConnectedNodes(nodeID, "to").length],
						["Vendor", node.surfactantSoftwareStruct.vendor[0] || "<N/A>"],
						[
							"Description",
							node.surfactantSoftwareStruct.description || "<N/A>",
						],
					]);

					break;
				}

				default: {
					console.error("Unknown type ${node.nodeMetadata.type} encountered");
				}
			}
		}

		if (document.getElementById("tooltip-header").innerText.includes("📌")) {
			const note = createNote("Right click to unpin");
			document.getElementById("tooltip-body").appendChild(note);
		}
	}
	network.on("showPopup", createPopupElement);

	// Right click to pin a node
	network.on("oncontext", function (params) {
		if (getCursor() === "grabbing") return; // Don't try to pin if a node is grabbed

		const nodeID = this.getNodeAt(params.pointer.DOM);
		if (nodeID === undefined) return; // Didn't click on a node

		if (network.isCluster(nodeID)) {
			const node = network.body.nodes[nodeID];
			const fixed = node.options.fixed;
			const shouldBeFixed = !(fixed.x === true && fixed.y === true);

			network.clustering.updateClusteredNode(nodeID, { fixed: shouldBeFixed });
			if (shouldBeFixed)
				network.clustering.updateClusteredNode(nodeID, {
					label: `📌 ${node.options.nodeMetadata.nodeFileName}`,
				});
			else
				network.clustering.updateClusteredNode(nodeID, {
					label: node.options.nodeMetadata.nodeFileName,
				});

			return;
		}

		const node = nodes.get(nodeID);
		const isFixed = node.fixed;

		if (isFixed === undefined || isFixed === false) {
			nodes.update({ id: nodeID, fixed: true });
			nodes.update({
				id: nodeID,
				label: `📌 ${node.nodeMetadata.nodeFileName}`,
			});
		} else {
			nodes.update({ id: nodeID, fixed: false });
			nodes.update({ id: nodeID, label: node.nodeMetadata.nodeFileName });
		}

		// Update popup if it's visible
		if (
			document.getElementsByClassName("vis-tooltip")[0].style.visibility ===
			"visible"
		)
			createPopupElement(nodeID);
	});

	return network;
}

document.addEventListener("DOMContentLoaded", () => {
	if (document.fonts) {
		document.fonts
			.load('normal normal 900 24px/1 "Font Awesome 6 Free"')
			.catch(console.error("Failed to load Font Awesome 6"))
			.then(() => {
				setButtonEventHandlers();
				drawGraph();
			})
			.catch(console.error("Failed to render the network with Font Awesome 6"));
	}
});
