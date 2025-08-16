export function setGraphColor(color) {
	const nodesDataset = nodes.get({ returnType: "Object" });

	for (const nID in nodesDataset) {
		nodesDataset[nID].color = color;
	}

	const tmp = [];
	for (const nID in nodesDataset)
		if (Object.hasOwn(nodesDataset, nID)) tmp.push(nodesDataset[nID]);

	nodes.update(tmp);
}
