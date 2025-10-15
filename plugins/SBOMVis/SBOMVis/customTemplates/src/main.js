import { setButtonEventHandlers } from "#buttonEventHandlersModule";
import {
	clickEventHandler,
	contextMenuEventHandler,
	doubleClickEventHandler,
} from "#mouseEventHandlersModule";
import { createPopupElement } from "#popupModule";
import { buildSBOMOverviewSidebar } from "#sidebarModule";
import {
	changeCursor,
	registerClickHandlers,
	setColorScheme,
} from "#utilsModule";

function drawGraph() {
	const container = document.getElementById("mynetwork");

	// Add tooltip for each node & record its default color
	nodes.update(
		nodes.get().map((n) => ({
			id: n.id,
			title: document.getElementById("tooltip"),
			originalColor: n.color,
		})),
	);

	const data = { nodes: nodes, edges: edges };

	options.interaction.hover = true;

	options.physics.forceAtlas2Based.avoidOverlap = 0.1; // Used to discourage node overlap

	network = new vis.Network(container, data, options);

	if (options.physics.enabled === false)
		setTimeout(() => network.setOptions({ physics: { enabled: true } }), 250); // Automatically re-enable physics after graph has loaded
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

	registerClickHandlers(clickEventHandler, doubleClickEventHandler);
	network.on("oncontext", contextMenuEventHandler);

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

	network.on("showPopup", createPopupElement);

	return network;
}

document.addEventListener("DOMContentLoaded", () => {
	if (document.fonts) {
		document.fonts
			.load('normal normal 900 24px/1 "Font Awesome 6 Free"')
			.catch(console.error("Failed to load Font Awesome 6"))
			.then(() => {
				setColorScheme("auto"); // Set init color scheme
				window
					.matchMedia("(prefers-color-scheme: dark)")
					.addEventListener("change", () => {
						setColorScheme("auto"); // If the user changes the system color scheme follow that, otherwise use manually set value
					});

				document
					.getElementById("sidebar")
					.replaceChildren(buildSBOMOverviewSidebar());
				setButtonEventHandlers();
				drawGraph();
			})
			.catch(console.error("Failed to render the network with Font Awesome 6"));
	}
});
