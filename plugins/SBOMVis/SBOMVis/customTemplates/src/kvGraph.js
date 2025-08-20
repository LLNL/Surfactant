/** @module kvGraph */

/**
 * Parses a JSON object and inserts into a empty or already populated graph
 * @param {*} obj JSON Object to parse
 * @param {*} graph A graph in the format {path1:[value1, value2], path2}
 * @param {string} UUID A string to associate value of the inserted object with
 */
export function insert(obj, graph, UUID) {
	function updateOrInsert(k, v) {
		graph[k] = graph[k] || {}; // Create new node

		graph[k][v] = graph[k][v] || [];
		graph[k][v].push(UUID); // k: { v:[UUID1, UUID2,...] }
	}

	for (const [k, v] of Object.entries(obj)) {
		if (Array.isArray(v)) {
			if (v.length === 0) {
				updateOrInsert(k, String(null)); // Use "null" to represent empty values for search
				continue;
			}

			for (const i of v) {
				if (typeof i === "object" && i !== null) {
					graph[k] = graph[k] || {};
					insert(i, graph[k], UUID);
				} else updateOrInsert(k, i);
			}
		} else if (typeof v === "object" && v !== null) {
			graph[k] = graph[k] || {};
			insert(v, graph[k], UUID);
		} else if (v !== "") updateOrInsert(k, String(v));
	}

	return graph;
}

/**
 * Returns either the node associated with a given path or the UUIDs associated with a value if included in the path
 * @param {*} graph
 * @param {str} str Path in the format "entry", "entry:", "entry:value", or "entry1.subEntry:value"
 * @returns The node corresponding to the provided path or an array of UUIDs
 */
export function resolvePath(graph, path) {
	const [stem, value] = path.split(":");
	const strippedPath = stem.replace(/\.$/, ""); // Remove trailing . if it exists
	const keys = strippedPath.split(".");
	let node = graph;

	if (stem === "") return node;

	for (const k of keys) {
		node = node[k];

		if (
			value !== undefined &&
			value !== "" &&
			node !== undefined &&
			isLeaf(node)
		)
			return node[value]; // Array of originating UUIDs that match value
	}

	return node;
}

/**
 * Determines if a node does not have any children
 * @param {*} node
 * @returns true if it only contains UUID values, false if contains a child node
 */
export function isLeaf(node) {
	for (const [k, v] of Object.entries(node)) {
		if (!Array.isArray(v)) return false;
	}

	return true;
}
