import { zoomToView } from "#buttonEventHandlersModule";
import { insert, isLeaf, resolvePath } from "#kvGraph";
import { setNodeColors } from "#utilsModule";

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
			i.value !== "" ? "fa-solid fa-copy" : "", // Don't show a copy icon if the value is blank
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

	return fragment;
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
					clickedNode.nodeMetadata.type !== "Container"
						? `Uses (${usesNodeIDs.length})`
						: `Contains (${usesNodeIDs.length})`,
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

	function createResultsSection(nodeIDs) {
		function createResultsCard(nodeID) {
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

			return resultsCard;
		}

		const frag = document.createDocumentFragment();
		for (const nodeID of nodeIDs) frag.appendChild(createResultsCard(nodeID));

		document.getElementById("resultsSection").replaceChildren(frag);
	}

	function removeNodesFromResults(nodeIDs) {
		for (const nodeID of nodeIDs) {
			for (const c of document
				.getElementById("resultsSection")
				.querySelectorAll(".search-results-card")) {
				const cardNodeID = c.getAttribute("nodeID");
				if (cardNodeID === nodeID) {
					c.remove();
				}
			}
		}
	}

	const tagsGraph = [];
	let matchedIDs = [];

	for (const n of Object.values(network.body.nodes)) {
		const softwareStruct = n.options.surfactantSoftwareStruct;
		if (softwareStruct !== undefined) {
			insert(softwareStruct, tagsGraph, softwareStruct.UUID);
		}
	}

	TomSelect.define("remove_tag_on_backspace", function () {
		const originalDelete = this.deleteSelection;

		this.hook("instead", "deleteSelection", (evt) => {
			const inputText = this.control_input.value;
			const pos = this.control_input.selectionStart;
			const cursorChar = inputText.charAt(pos - 1); // Character behind the cursor

			if (cursorChar === ":" || cursorChar === ".") {
				const slicePos = Math.max(
					inputText.lastIndexOf(".", inputText.length - 2) + 2,
					0,
				); // Delete until the next .
				this.setTextboxValue(inputText.slice(0, slicePos));
				return;
			}

			return originalDelete.call(this, evt);
		});
	});

	function onTypeHandler(str) {
		const input = str.trim();

		const dotSepIndex = input.lastIndexOf(".");
		const colonSepIndex = input.lastIndexOf(":");

		this.clearOptions();

		const sepIndex = colonSepIndex !== -1 ? colonSepIndex : dotSepIndex;
		const searchPath = sepIndex === -1 ? "" : input.slice(0, sepIndex); // Use root path if no '.'
		const node = resolvePath(tagsGraph, searchPath);

		const newOptions = Object.entries(node).map(([k, v]) => {
			const isLeafNode = isLeaf(node);

			const pathDelim = isLeafNode ? ":" : ".";
			const optionPath = searchPath === "" ? "" : searchPath + pathDelim;

			let suggestion = "";

			if (isLeafNode) suggestion = k;
			else suggestion = k + (isLeaf(v) ? ":" : ".");

			return {
				value: optionPath + suggestion,
				label: optionPath + suggestion,
			};
		});

		this.addOptions(newOptions);
		this.refreshOptions();
	}

	function onAddHandler(value) {
		const item = this.options[value];
		const result = resolvePath(tagsGraph, item?.value);

		// Path resolved to a node: autocomplete to selected option
		if (!Array.isArray(result)) {
			this.removeItem(value);

			this.setTextboxValue(value); // Autocomplete value
			onTypeHandler.call(this, value); // Regenerate suggestions
		}

		// Path & value got entered: add selected option & clear box
		else {
			this.setTextboxValue("");

			this.clearOptions();
			this.addOptions(generateRootNodeSuggestions.call(this));
			this.refreshOptions();

			// First time creating/adding results
			if (matchedIDs.length === 0) {
				matchedIDs.push(result);

				// Gray out all nodes
				const inactiveColor = getComputedStyle(document.body).getPropertyValue(
					"--graphInactiveColor",
				);
				setNodeColors(nodes.getIds(), inactiveColor);

				setNodeColors(result); // Highlight selected nodes w/ default color

				network.unselectAll();

				createResultsSection(result);
			} else {
				// The more filter criteria that gets added the more restrictive the search is -> Adding more terms should reduce how many results show up

				const oldMatches = matchedIDs.reduce((acc, arr) =>
					acc.filter((ID) => arr.includes(ID)),
				);

				matchedIDs.push(result);

				const newMatches = matchedIDs.reduce((acc, arr) =>
					acc.filter((ID) => arr.includes(ID)),
				); // Perform AND operation on incoming results

				const IDsToRemove = oldMatches.filter((ID) => !newMatches.includes(ID));
				removeNodesFromResults(IDsToRemove);
			}
		}
	}

	function onDeleteHandler(items) {
		function isArrayEqual(a1, a2) {
			if (a1.length !== a2.length) return false;
			return a1.every((e, i) => e === a2[i]);
		}

		const oldMatches = matchedIDs.reduce((acc, arr) =>
			acc.filter((ID) => arr.includes(ID)),
		);
		for (const path of items) {
			const UUIDs = resolvePath(tagsGraph, path);
			matchedIDs = matchedIDs.filter((IDs) => !isArrayEqual(IDs, UUIDs)); // Remove list of matched UUIDs from the search results
		}

		if (matchedIDs.length === 0) {
			removeNodesFromResults(oldMatches);
			setNodeColors(nodes.getIds()); // Revert graph to default colors
		} else {
			const newMatches = matchedIDs.reduce((acc, arr) =>
				acc.filter((ID) => arr.includes(ID)),
			); // Perform AND operation on incoming results

			setNodeColors(newMatches);
			createResultsSection(newMatches);
		}
	}

	function onTextboxLooseFocus() {
		/*
		Tom-select clears the textbox when it looses focus (there doesn't seem to be an easy way to change this),
		but it doesn't remove the previously suggested results
		*/
		this.clearOptions();
		this.addOptions(generateRootNodeSuggestions.call(this));
	}

	function onClearHandler() {
		document.getElementById("resultsSection").replaceChildren(); // Remove search result cards
		matchedIDs = [];

		setNodeColors(nodes.getIds()); // Reset graph color

		this.clearOptions();
		this.addOptions(generateRootNodeSuggestions.call(this));
	}

	function generateRootNodeSuggestions() {
		return Object.keys(tagsGraph).map((key) => {
			const newLabel = key + (isLeaf(tagsGraph[key]) ? ":" : ".");
			return { label: newLabel, value: newLabel };
		});
	}

	new TomSelect(searchBox, {
		persist: false,
		create: false,
		maxItems: null,
		options: generateRootNodeSuggestions(),
		valueField: "value",
		labelField: "label",
		searchField: ["label"],
		plugins: {
			remove_button: {
				title: "Remove",
			},
			clear_button: {
				title: "Remove all nodes",
			},
			caret_position: {},
			remove_tag_on_backspace: {},
		},

		render: {
			option: (data, esc) => `<div>${esc(data.label)}</div>`,
			item: (data, esc) => `<div>${esc(data.label)}</div>`,
		},

		onType: onTypeHandler,
		onItemAdd: onAddHandler,
		onDelete: onDeleteHandler,
		onClear: onClearHandler,
		onBlur: onTextboxLooseFocus,
	});
}
