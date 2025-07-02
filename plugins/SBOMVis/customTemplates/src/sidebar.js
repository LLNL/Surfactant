import { zoomToView } from "#buttonEventHandlersModule";

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

function createNestedFoldedSectionFromJSON(obj, keyLabel = null) {
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
			container.appendChild(createNestedFoldedSectionFromJSON(value, key)); // Recurse on nested object
		} else {
			const entry = createMonospaceEntry(key, value !== "" ? value : `""`);

			container.appendChild(entry);
		}
	}

	details.appendChild(container);
	return details;
}

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

function jumpToNodeOnClick() {
	const nodeID = this.getAttribute("nodeID");

	zoomToView([nodeID]);
	buildNodeSelectionSidebar(nodeID);
}

function createSection({ title, icon = null, body = [] }) {
	const section = document.createElement("div");
	section.classList = "section";

	const header = document.createElement("div");
	header.classList = "section-header";

	if (icon !== null) {
		const iconElement = document.createElement("i");
		iconElement.classList = icon;
		header.appendChild(iconElement);
	}

	const headerText = document.createElement("h4");
	headerText.textContent = title;
	header.appendChild(headerText);

	section.append(header);

	if (body.length !== 0) {
		const bodyElement = document.createElement("div");
		bodyElement.classList = "section-body";
		for (const e of body) bodyElement.appendChild(e);

		section.appendChild(bodyElement);
	}

	return section;
}

export function buildSBOMOverviewSidebar() {
	const fragment = document.createDocumentFragment();

	fragment.appendChild(
		createSection({
			title: "Click on a node to get started",
		}),
	);
}

export function buildNodeSelectionSidebar(nodeID) {
	const fragment = document.createDocumentFragment();

	let clickedNode = null;

	let titleIcon = null;
	if (network.isCluster(nodeID)) {
		titleIcon = "fa-solid fa-file-zipper";
		clickedNode = nodes.get(nodeID.split(":")[1]);
	} else {
		clickedNode = nodes.get(nodeID);
		titleIcon = getIconClassForFileType(clickedNode.nodeMetadata.type);
	}

	// Title section
	fragment.appendChild(
		createSection({
			title: clickedNode.nodeMetadata.nodeFileName,
			icon: titleIcon,
		}),
	);

	function convertNodeIDsToFileNames(nodeIDs) {
		return nodeIDs.map((id) => ({
			value:
				network.body.nodes[id]?.options?.nodeMetadata?.nodeFileName ||
				"<Unknown>",
			attributes: [
				{ key: "nodeID", value: id },
				{ key: "style", value: "cursor: pointer" },
			],
			onClick: jumpToNodeOnClick,
		}));
	}

	const sbom = clickedNode.surfactantSoftwareStruct;

	fragment.appendChild(
		createSection({
			title: "Basic Info",
			body: [
				createSectionInfoTable([
					{ displayName: "Install path", value: sbom.installPath },
					{ displayName: "File size (bytes)", value: sbom.size },
					{ displayName: "Version", value: sbom.version },
					{ displayName: "Vendor", value: sbom.vendor },
					{ displayName: "Description", value: sbom.description },
					{ displayName: "Comments", value: sbom.comments },
				]),
			],
		}),
	);

	fragment.appendChild(
		createSection({
			title: "Hashes",
			body: [
				createSectionInfoTable([
					{ displayName: "SHA1", value: sbom.sha1 },
					{ displayName: "SHA256", value: sbom.sha256 },
					{ displayName: "MD5", value: sbom.md5 },
				]),
			],
		}),
	);

	const usesNodeIDs = network.getConnectedNodes(nodeID, "from");
	const usedByNodeIDs = network.getConnectedNodes(nodeID, "to");
	fragment.appendChild(
		createSection({
			title: "Relationships",
			body: [
				createFoldableSectionInfoTable(
					`Uses (${usesNodeIDs.length})`,
					convertNodeIDsToFileNames(usesNodeIDs),
				),
				createFoldableSectionInfoTable(
					`Used By (${usedByNodeIDs.length})`,
					convertNodeIDsToFileNames(usedByNodeIDs),
				),
			],
		}),
	);

	const metadataSectionDiv = document.createElement("div");
	metadataSectionDiv.classList = "nested-foldable-subsection-body";
	const foldedSection = createNestedFoldedSectionFromJSON(sbom, "Root");
	foldedSection.open = false;
	metadataSectionDiv.appendChild(foldedSection);
	fragment.appendChild(
		createSection({
			title: "Metadata",
			body: [metadataSectionDiv],
		}),
	);

	return fragment;
}

export function insertSearchSidebar(id) {
	const rootNode = document.getElementById(id);
	const fragment = document.createDocumentFragment();

	const searchBarSection = document.createElement("div");
	searchBarSection.className = "section";

	const searchBox = document.createElement("select");
	searchBox.id = "searchBox";
	searchBox.setAttribute("placeholder", "Start typing to search...");
	searchBarSection.appendChild(searchBox);

	fragment.appendChild(searchBarSection);

	const resultsSection = document.createElement("div");
	resultsSection.className = "section";
	resultsSection.id = "resultsSection";
	fragment.appendChild(resultsSection);

	rootNode.replaceChildren(fragment);

	function generateSearchData() {
		const options = []; // [ { 'UUID': <UUID>, 'data': [name, sha, ...] }, ... ]
		for (const [nodeID, n] of Object.entries(network.body.nodes)) {
			if (nodeID.includes("edgeId")) continue; // Skip edges

			const sbom = n.options.surfactantSoftwareStruct;
			const entry = {
				UUID: nodeID,
				data: [],
				label: n.options.nodeMetadata.nodeFileName,
			};

			for (const [sbomK, sbomV] of Object.entries(sbom)) {
				if (Array.isArray(sbomV))
					entry.data.push(
						...sbomV.filter(
							(x) =>
								typeof x !== "function" && typeof x !== "object" && x !== "",
						),
					);
				if (
					typeof sbomV !== "function" &&
					typeof sbomV !== "object" &&
					sbomV !== ""
				)
					entry.data.push(sbomV);
			}

			options.push(entry);
		}
		return options;
	}

	function setGraphColor(color) {
		const nodesDataset = nodes.get({ returnType: "Object" });

		for (const nID in nodesDataset) {
			nodesDataset[nID].color = color;
		}

		const tmp = [];
		for (const nID in nodesDataset)
			if (Object.hasOwn(nodesDataset, nID)) tmp.push(nodesDataset[nID]);

		nodes.update(tmp);
	}

	function appendNodeToResults(nodeID, ...args) {
		if (this.items.length === 1) {
			const inactiveColor = getComputedStyle(document.body).getPropertyValue(
				"--graphInactiveColor",
			);
			setGraphColor(inactiveColor);

			network.unselectAll();
		}

		nodes.update({ id: nodeID, color: null }); // Use default graph color for highlight

		const node = network.body.nodes[nodeID];

		const resultsCard = document.createElement("div");
		resultsCard.className = "search-results-card";

		resultsCard.setAttribute("nodeID", nodeID);
		resultsCard.addEventListener("click", jumpToNodeOnClick);

		const header = document.createElement("div");
		header.classList = "section-header";

		const iconElement = document.createElement("i");
		iconElement.classList = getIconClassForFileType(
			node.options.nodeMetadata.type,
		);
		header.appendChild(iconElement);

		const headerText = document.createElement("h5");
		headerText.textContent = node.options.nodeMetadata.nodeFileName;
		header.appendChild(headerText);

		resultsCard.append(header);

		document.getElementById("resultsSection").appendChild(resultsCard);

		this.setTextboxValue("");
		this.refreshOptions();
	}

	function removeNodes(nodes) {
		for (const nodeID of nodes) {
			for (const c of document
				.getElementById("resultsSection")
				.querySelectorAll(".search-results-card")) {
				const cardNodeID = c.getAttribute("nodeID");
				if (cardNodeID === nodeID) {
					if (this.items.length === 1) setGraphColor(null); // Revert to default

					c.remove();
				}
			}
		}
	}

	const searchData = generateSearchData();

	new TomSelect(searchBox, {
		maxItems: null,
		maxOptions: 100,

		valueField: "UUID",
		labelField: "label",
		searchField: ["data"],

		plugins: {
			remove_button: {
				title: "Remove",
			},
			caret_position: {},
		},
		options: searchData,

		onItemAdd: appendNodeToResults,
		onDelete: removeNodes,
	});
}
