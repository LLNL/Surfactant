import { createPopupElement } from "#popupModule";

/**
 * Sets the nodes with the given array of IDs with `color` or it's default color if left undefined
 * @param {Array} nodeIDs
 * @param {(string|undefined)} color
 */
export function setNodeColors(nodeIDs, color) {
	nodes.update(
		nodes.get(nodeIDs).map((n) => ({
			id: n.id,
			color: color !== undefined ? color : n.originalColor,
		})),
	);
}

/**
 * Sets CSS color scheme, dark/light mode toggle icon, and updates node font colors
 * @param {string} mode (dark, light, auto)
 */
export function setColorScheme(mode) {
	const toggle = document.getElementById("themeToggle");
	const icon = toggle.querySelector("i");

	const html = document.querySelector("html");

	// Update icon and CSS color-scheme
	const colorSchemes = {
		dark: {
			icon: "fa-solid fa-sun",
			tooltip: "Toggle light mode",
			CSSColorScheme: "dark",
		},
		light: {
			icon: "fa-solid fa-moon",
			tooltip: "Toggle dark mode",
			CSSColorScheme: "light",
		},
	};

	let preferredColorScheme = mode;
	if (mode === "auto") {
		preferredColorScheme = window.matchMedia("(prefers-color-scheme: dark)")
			.matches
			? "dark"
			: "light"; // Use system preferred color
		html.style.setProperty("color-scheme", "light dark");
	} else html.style.setProperty("color-scheme", mode);

	const { icon: iconClass, tooltip } = colorSchemes[preferredColorScheme];
	icon.classList = iconClass;
	toggle.setAttribute("title", tooltip);

	// Update node font colors
	const styles = getComputedStyle(document.body);

	const newIconColor = styles.getPropertyValue(
		preferredColorScheme === "dark" ? "--darkNodeColor" : "--lightNodeColor",
	);
	const newLabelColor = styles.getPropertyValue(
		preferredColorScheme === "dark" ? "--darkTextColor" : "--lightTextColor",
	);

	nodes.update(
		nodes.get().map((n) => ({
			id: n.id,
			icon: { ...n.icon, color: newIconColor },
			font: { ...n.font, color: newLabelColor },
		})),
	);
}

/**
 * Callback for mouse click events
 * @callback mouseClickCallback
 * @param {Object} params
 */

/**
 * Registers single and double click handlers with Vis.js
 * @param {mouseClickCallback} onClick
 * @param {mouseClickCallback} onDoubleClick
 */
export function registerClickHandlers(onClick, onDoubleClick) {
	const clickThreshold = 250;
	let lastClickTime = 0;

	function clickHandler(e) {
		if (document.getElementById("contextMenu").style.visibility !== "hidden")
			return; // 'Cancel' the click event to the canvas when closing the context menu

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

	// Hide the context menu when clicking anywhere else on the page
	document.addEventListener("click", (e) => {
		const contextMenu = document.getElementById("contextMenu");

		if (contextMenu && !contextMenu.contains(e.target)) {
			document.getElementsByClassName("vis-tooltip")[0].style.opacity = "100%"; // Re-enable tooltip
			document.getElementById("contextMenu").style.visibility = "hidden";
		}
	});
}

/**
 * Sets the new mouse cursor style while over the network canvas
 * @param {string} newCursorStyle
 */
export function changeCursor(newCursorStyle) {
	const networkCanvas = document
		.getElementById("mynetwork")
		.getElementsByTagName("canvas")[0];
	networkCanvas.style.cursor = newCursorStyle;
}

/**
 * Returns the current mouse cursor
 * @returns {string}
 */
export function getCursor() {
	const networkCanvas = document
		.getElementById("mynetwork")
		.getElementsByTagName("canvas")[0];
	return networkCanvas.style.cursor;
}

/**
 * Returns true if the node is pinned regardless if regular node or cluster
 * @param {string} nodeID
 * @returns {boolean}
 */
export function isNodePinned(nodeID) {
	if (network.isCluster(nodeID)) {
		const node = network.body.nodes[nodeID];
		const fixed = node.options.fixed;
		return fixed.x === true && fixed.y === true;
	}

	const node = nodes.get(nodeID);
	return !!node.fixed; // Can be false or undefined (if the node wasn't previously pinned)
}

/**
 * Pins/unpins node with given ID in-place
 * @param {string} nodeID
 */
export function toggleNodePin(nodeID) {
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
		nodes.update({
			id: nodeID,
			fixed: true,
			label: `📌 ${node.nodeMetadata.nodeFileName}`,
		});
	} else {
		nodes.update({
			id: nodeID,
			fixed: false,
			label: node.nodeMetadata.nodeFileName,
		});
	}

	// Update popup if it's visible
	if (
		document.getElementsByClassName("vis-tooltip")[0].style.visibility ===
			"visible" &&
		document.getElementById("tooltip").style.opacity !== "0%"
	)
		createPopupElement(nodeID);
}
