export function setGraphColor(color) {
	const nodesDataset = nodes.get({ returnType: "Object" });

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
