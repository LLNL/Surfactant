import { insertSearchSidebar } from "#sidebarModule";

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

export function togglePhysics() {
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

export function exportImage() {
	const canvas = document.getElementById("mynetwork").querySelector("canvas");

	canvas.toBlob((blob) => {
		saveAs(blob, "SBOM.png");
	});
}

export function handleSearch() {
	insertSearchSidebar("sidebar");

	if (!document.getElementById("sidebar").classList.contains("open"))
		toggleSidebar();
}

export function toggleIsolates() {
	const toggle = document.getElementById("isolatesToggle");
	const icon = toggle.querySelector("i");

	const shouldBeHidden = icon.className === "fa-solid fa-eye";

	const selectedNodes = [];
	for (const n of nodes.get()) {
		// Has no edges (an isolate) and isn't hidden by user choice
		if (
			network.getConnectedNodes(n.id).length === 0 &&
			n.nodeMetadata.hidden === false
		) {
			n.hidden = !n.hidden;
			selectedNodes.push(n);
		}
	}

	nodes.update(selectedNodes);

	icon.className = shouldBeHidden ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
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
}
