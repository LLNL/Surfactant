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

export function createPopupElement(nodeID) {
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
						`${network.getConnectedNodes(nodeID, "from").length} Nodes`,
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
					["Description", node.surfactantSoftwareStruct.description || "<N/A>"],
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
