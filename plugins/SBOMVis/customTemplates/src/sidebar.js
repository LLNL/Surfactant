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

export function buildNodeSelectionSidebar(nodeID) {
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
		buildNodeSelectionSidebar(nodeID);
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

export function buildSearchSidebar() {}
