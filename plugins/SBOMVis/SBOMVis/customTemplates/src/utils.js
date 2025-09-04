/**
 * Sets the nodes with the given array of IDs with `color` or it's default color if left undefined
 * @param {Array} nodeIDs
 * @param {(String|undefined)} color
 */
export function setNodeColors(nodeIDs, color) {
	const nodesDataset = nodes.get(nodeIDs, { returnType: "Object" });

	for (const nID in nodesDataset) {
		if (color !== undefined) nodesDataset[nID].color = color;
		else {
			nodesDataset[nID].color = nodesDataset[nID].originalColor;
		}
	}

	const tmp = [];
	for (const nID in nodesDataset)
		if (Object.hasOwn(nodesDataset, nID)) tmp.push(nodesDataset[nID]);

	nodes.update(tmp);
}

/**
 * Sets color scheme and dark/light mode toggle icon
 * @param {String} mode (dark, light, auto)
 */
export function setColorScheme(mode) {
	const toggle = document.getElementById("themeToggle");
	const icon = toggle.querySelector("i");

	const html = document.querySelector("html");

	switch (mode) {
		case "dark": {
			icon.classList = "fa-solid fa-sun";
			html.style.setProperty("color-scheme", "dark");
			break;
		}

		case "light": {
			icon.classList = "fa-solid fa-moon";
			html.style.setProperty("color-scheme", "light");
			break;
		}

		case "auto": {
			icon.classList = window.matchMedia("(prefers-color-scheme: dark)").matches
				? "fa-solid fa-sun"
				: "fa-solid fa-moon"; // Set icon based on system color preference
			html.style.setProperty("color-scheme", "light dark"); // Auto change
			break;
		}
	}
}
