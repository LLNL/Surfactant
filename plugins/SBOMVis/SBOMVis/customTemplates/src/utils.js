/**
 * Sets the nodes with the given array of IDs with `color` or it's default color if left undefined
 * @param {Array} nodeIDs
 * @param {(String|undefined)} color
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
 * @param {String} mode (dark, light, auto)
 */
export function setColorScheme(mode) {
	const toggle = document.getElementById("themeToggle");
	const icon = toggle.querySelector("i");

	const html = document.querySelector("html");

	// Update icon and CSS color-scheme
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

	// Update node font colors
	const useDarkTheme = icon.classList.contains("fa-sun");
	const styles = getComputedStyle(document.body);

	const newIconColor = styles.getPropertyValue(
		useDarkTheme ? "--darkNodeColor" : "--lightNodeColor",
	);
	const newLabelColor = styles.getPropertyValue(
		useDarkTheme ? "--darkTextColor" : "--lightTextColor",
	);

	nodes.update(
		nodes.get().map((n) => ({
			id: n.id,
			icon: { ...n.icon, color: newIconColor },
			font: { ...n.font, color: newLabelColor },
		})),
	);
}
