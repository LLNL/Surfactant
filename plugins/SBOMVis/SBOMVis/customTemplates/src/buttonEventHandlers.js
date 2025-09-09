import { insertSearchSidebar } from "#sidebarModule";
import { setColorScheme } from "#utilsModule";

export function toggleSidebar() {
	const sidebar = document.getElementById("sidebar");
	const toggle = document.getElementById("sidebarButtons");
	const icon = document.getElementById("sidebarToggle").querySelector("i");

	sidebar.classList.toggle("open");
	toggle.classList.toggle("open");

	if (sidebar.classList.contains("open")) {
		icon.classList = "fa-solid fa-circle-chevron-left";
	} else {
		icon.classList = "fa-solid fa-circle-chevron-right";
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

export function zoomToView(nodes) {
	const options = { animation: true };

	if (Array.isArray(nodes)) options.nodes = nodes;

	network.fit(options);
}

function exportImage() {
	const canvas = document.getElementById("mynetwork").querySelector("canvas");

	canvas.toBlob((blob) => {
		saveAs(blob, "SBOM.png");
	});
}

function handleSearch() {
	insertSearchSidebar("sidebar");

	if (!document.getElementById("sidebar").classList.contains("open"))
		toggleSidebar();
}

function toggleIsolates() {
	const toggle = document.getElementById("isolatesToggle");
	const icon = toggle.querySelector("i");

	const shouldBeHidden = icon.classList.contains("fa-eye");

	nodes.update(
		nodes
			.get()
			.filter(
				(n) =>
					network.getConnectedNodes(n.id).length === 0 &&
					n.nodeMetadata.hidden === false,
			) // Has no edges (an isolate) and isn't hidden by user choice
			.map((n) => ({ id: n.id, hidden: !n.hidden })),
	);

	if (shouldBeHidden) icon.classList.replace("fa-eye", "fa-eye-slash");
	else icon.classList.replace("fa-eye-slash", "fa-eye");
}

function toggleTheme() {
	const toggle = document.getElementById("themeToggle");
	const icon = toggle.querySelector("i");

	if (icon.classList.contains("fa-sun")) setColorScheme("light");
	else setColorScheme("dark");
}

export function setButtonEventHandlers() {
	document
		.getElementById("sidebarToggle")
		.addEventListener("click", toggleSidebar);

	document
		.getElementById("physicsToggle")
		.addEventListener("click", togglePhysics);

	document
		.getElementById("searchButton")
		.addEventListener("click", handleSearch);

	document.getElementById("zoomToView").addEventListener("click", zoomToView);

	document
		.getElementById("isolatesToggle")
		.addEventListener("click", toggleIsolates);

	document.getElementById("exportImage").addEventListener("click", exportImage);

	document.getElementById("themeToggle").addEventListener("click", toggleTheme);
}
