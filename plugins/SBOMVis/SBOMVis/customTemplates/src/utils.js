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
