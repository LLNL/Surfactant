let nodeColors;
let network;

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

		function buildSidebar(nodeID) {
			let clickedNode = null;

			const sidebarTitleHeaderIcon = document.getElementById(
				"sidebar-title-header-icon",
			);
			if (network.isCluster(nodeID)) {
				sidebarTitleHeaderIcon.className = "fa-solid fa-file-zipper";
				clickedNode = nodes.get(nodeID.split(":")[1]);
			} else {
				clickedNode = nodes.get(nodeID);
				sidebarTitleHeaderIcon.className = getIconClassForFileType(
					clickedNode.nodeMetadata.type,
				);
			}

			document.getElementById("sidebar-title-header-name").innerText =
				clickedNode.nodeMetadata.nodeFileName; // Update name

			function createRow(
				leftColumnValue,
				middleColumnValue,
				middleColumnAttributes,
				middleColumnOnClick,
				iconClass,
			) {
				const row = document.createElement("tr");

				const leftColumn = document.createElement("td");
				leftColumn.classList.add("label");
				leftColumn.innerText = leftColumnValue;

				const middleColumn = document.createElement("td");
				middleColumn.classList.add("value");

				if (Array.isArray(middleColumnAttributes))
					for (const e of middleColumnAttributes)
						middleColumn.setAttribute(e.key, e.value);

				if (Array.isArray(middleColumnValue)) {
					middleColumn.innerText = middleColumnValue
						.map((i) => (i < middleColumnValue.length - 1 ? "${i};" : i))
						.join("");
				} else middleColumn.innerText = middleColumnValue;

				middleColumn.setAttribute("title", middleColumn.innerText);
				if (middleColumn.offsetWidth < middleColumn.scrollWidth)
					bootstrap.Tooltip.getOrCreateInstance(middleColumn);

				if (typeof middleColumnOnClick === "function")
					middleColumn.addEventListener("click", middleColumnOnClick);

				const iconColumn = document.createElement("td");
				iconColumn.classList.add("icon");

				const icon = document.createElement("i");
				icon.classList = iconClass;

				// Icon copy when clicked
				icon.addEventListener("click", () => {
					const row = icon.closest("tr");
					const valueCell = row.querySelector(".value");

					let textToCopy = "";
					if (valueCell.children.length > 0) {
						textToCopy = Array.from(valueCell.children)
							.map((child) => child.textContent.trim())
							.join("\n");
					} else {
						textToCopy = valueCell.textContent.trim();
					}

					navigator.clipboard
						.writeText(textToCopy)
						.then(() => {
							icon.classList = "fa fa-check text-success";
							setTimeout(() => {
								icon.classList = "fa-solid fa-copy";
							}, 1000);
						})
						.catch((err) => console.error("Copy failed:", err));
				});

				iconColumn.appendChild(icon);

				if (leftColumnValue !== undefined) row.appendChild(leftColumn);
				if (middleColumnValue !== undefined) row.appendChild(middleColumn);
				if (iconClass !== undefined) row.appendChild(iconColumn);

				return row;
			}

			function createSectionInfoTable(infoItems) {
				const newInfoTable = document.createElement("table");
				newInfoTable.classList = "section-table";

				for (const i of infoItems) {
					const newRow = createRow(
						i.displayName,
						i.value,
						i.attributes,
						i.onClick,
						"fa-solid fa-copy",
					);
					newInfoTable.appendChild(newRow);
				}

				return newInfoTable;
			}

			function createFoldableSectionInfoTable(headerText, infoItems) {
				const detailsTag = document.createElement("details");

				const subsectionHeader = document.createElement("summary");
				subsectionHeader.classList = "foldable-subsection-header";
				subsectionHeader.innerText = headerText;
				if (infoItems.length === 0) subsectionHeader.style.listStyle = "none"; // Don't show arrow when there aren't any items to display

				detailsTag.appendChild(subsectionHeader);

				const foldableSubsectionBody = document.createElement("div");
				foldableSubsectionBody.classList = "foldable-subsection-body";
				foldableSubsectionBody.appendChild(createSectionInfoTable(infoItems)); // Insert table into details tag

				detailsTag.appendChild(foldableSubsectionBody);

				return detailsTag;
			}

			function createNestedFoldedSectionFromJSON(obj, keyLabel = null) {
				function createMonospaceEntry(key, value) {
					const entry = document.createElement("div");
					entry.classList = "entry";

					const label = document.createElement("span");

					const labelText = document.createElement("strong");
					labelText.innerText = `${key}: `;
					label.appendChild(labelText);

					entry.appendChild(label);

					const valueSpan = document.createElement("span");
					valueSpan.style.fontFamily = "monospace";
					valueSpan.innerText = value;
					entry.appendChild(valueSpan);

					return entry;
				}

				const details = document.createElement("details");
				details.open = true;

				if (keyLabel !== null) {
					const summary = document.createElement("summary");
					summary.innerText = keyLabel;
					details.appendChild(summary);
				}

				const container = document.createElement("div");

				for (const [key, value] of Object.entries(obj)) {
					if (Array.isArray(value)) {
						if (value.length === 0) {
							const entry = createMonospaceEntry(key, "[]"); // Display [] instead of an empty <details> tag
							container.appendChild(entry);
						} else {
							const subDetails = document.createElement("details");
							subDetails.open = true;

							const summary = document.createElement("summary");
							summary.innerText = key;
							subDetails.appendChild(summary);

							const list = document.createElement("div");

							for (const i of value) {
								if (typeof i === "object" && i !== null) {
									list.appendChild(createNestedFoldedSectionFromJSON(i, "-")); // Recursively handle array
								} else {
									const ul = document.createElement("ul");
									const li = document.createElement("li");
									li.innerText = i;
									ul.appendChild(li);
									list.appendChild(ul);
								}
							}

							subDetails.appendChild(list);
							container.appendChild(subDetails);
						}
					} else if (value !== null && typeof value === "object") {
						container.appendChild(
							createNestedFoldedSectionFromJSON(value, key),
						); // Recurse on nested object
					} else {
						const entry = createMonospaceEntry(
							key,
							value !== "" ? value : `""`,
						);

						container.appendChild(entry);
					}
				}

				details.appendChild(container);
				return details;
			}

			function convertNodeIDsToFileNames(nodeIDs) {
				return nodeIDs.map((id) => ({
					value:
						network.body.nodes[id]?.options?.nodeMetadata?.nodeFileName ||
						"<Unknown>",
					attributes: [
						{ key: "nodeID", value: id },
						{ key: "style", value: "cursor: pointer" },
					],
					onClick: relationshipsColumnOnClick,
				}));
			}

			function relationshipsColumnOnClick() {
				const nodeID = this.getAttribute("nodeID");

				zoomToView([nodeID]);
				buildSidebar(nodeID);
			}

			const sbom = clickedNode.surfactantSoftwareStruct;

			document
				.querySelector("#sidebar-basic-info-section .section-body")
				.replaceChildren(
					createSectionInfoTable([
						{ displayName: "Install path", value: sbom.installPath },
						{ displayName: "File size (bytes)", value: sbom.size },
						{ displayName: "Version", value: sbom.version },
						{ displayName: "Vendor", value: sbom.vendor },
						{ displayName: "Description", value: sbom.description },
						{ displayName: "Comments", value: sbom.comments },
					]),
				);

			document
				.querySelector("#sidebar-hashes-section .section-body")
				.replaceChildren(
					createSectionInfoTable([
						{ displayName: "SHA1", value: sbom.sha1 },
						{ displayName: "SHA256", value: sbom.sha256 },
						{ displayName: "MD5", value: sbom.md5 },
					]),
				);

			const usesNodeIDs = network.getConnectedNodes(nodeID, "from");
			const usedByNodeIDs = network.getConnectedNodes(nodeID, "to");
			document
				.querySelector("#sidebar-relationships-section .section-body")
				.replaceChildren(
					createFoldableSectionInfoTable(
						`Uses (${usesNodeIDs.length})`,
						convertNodeIDsToFileNames(usesNodeIDs),
					),
					createFoldableSectionInfoTable(
						`Used By (${usedByNodeIDs.length})`,
						convertNodeIDsToFileNames(usedByNodeIDs),
					),
				);

			const metadataSectionDiv = document.createElement("div");
			metadataSectionDiv.classList = "nested-foldable-subsection-body";
			const foldedSection = createNestedFoldedSectionFromJSON(sbom, "Root");
			foldedSection.open = false;
			metadataSectionDiv.appendChild(foldedSection);
			document
				.querySelector("#sidebar-metadata-section .section-body")
				.replaceChildren(metadataSectionDiv);

			for (const i of document.querySelectorAll("#sidebar .section"))
				i.style.visibility = "visible";
		}

		if (params.nodes.length !== 0) buildSidebar(nodeID);

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
				drawGraph();
			})
			.catch(console.error("Failed to render the network with Font Awesome 6"));
	}
});

function getIconClassForFileType(type) {
	switch (type) {
		case "File":
			return "fa-solid fa-file";
		case "Container":
			return "fa-solid fa-file";

		default:
			console.error("Node type not implemented");
			return "fa-solid fa-question";
	}
}

function toggleSidebar() {
	const sidebar = document.getElementById("sidebar");
	const toggle = document.getElementById("sidebarButtons");
	const icon = document.getElementById("sidebarToggle").querySelector("i");

	sidebar.classList.toggle("open");
	toggle.classList.toggle("open");

	if (sidebar.classList.contains("open")) {
		icon.classList.remove("fa-circle-chevron-right");
		icon.classList.add("fa-circle-chevron-left");
	} else {
		icon.classList.remove("fa-circle-chevron-left");
		icon.classList.add("fa-circle-chevron-right");
	}
}

function togglePhysics() {
	const toggle = document.getElementById("physicsToggle");
	const icon = toggle.querySelector("i");

	const isPhysicsEnabled = network.physics.physicsEnabled;

	network.setOptions({
		physics: {
			enabled: !isPhysicsEnabled,
		},
	});

	icon.classList = network.physics.physicsEnabled
		? "fa-solid fa-circle-pause"
		: "fa-solid fa-circle-play";
}

function zoomToView(nodes) {
	const options = { animation: true };

	if (Array.isArray(nodes)) options.nodes = nodes;

	network.fit(options);
}
