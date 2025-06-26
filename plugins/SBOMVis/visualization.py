#!/usr/bin/env python3

import dataclasses
import os
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List

import networkx
import pyvis
from dataclasses_json import dataclass_json
from jinja2 import Environment, FileSystemLoader
from loguru import logger

from surfactant.sbomtypes import SBOM


class EdgeType(Enum):
    FileRelationship = (0,)
    MetadataSimilarity = 1


@dataclass
class DisplaySettings:
    fg_color: str = "white"
    bg_color: str = "#222222"
    icon_color: str = "#648fc9"

    node_scale_factor: int = 4  # Increase node size by degree
    icon_scale_factor: int = 4


class NodeType(str, Enum):
    Unknown = ("Unknown",)
    File = ("File",)
    Container = "Container"


@dataclass_json
@dataclass
class NodeMetadata:
    type: NodeType = NodeType.File
    nodeFileName: str = ""
    SBOMFileName: str = ""


def generate_dependency_graph(
    sbomDict: SBOM,
    enableCulling: bool = False,
    edgeType: EdgeType = EdgeType.FileRelationship,
) -> networkx.graph:
    g = networkx.MultiDiGraph()

    sbom = sbomDict["sbom"]
    for i in sbom.software:
        fileName = (i.fileName or [i.UUID])[0]
        metadata = NodeMetadata(
            nodeFileName=fileName,  # Label and file name can differ
            SBOMFileName=sbomDict["sbomFileName"],
        )
        g.add_node(
            i.UUID,
            label=fileName,
            surfactantSoftwareStruct=dataclasses.asdict(i),
            nodeMetadata=dataclasses.asdict(metadata),
        )

    if edgeType == EdgeType.FileRelationship:
        for i in sbom.relationships:
            if i.relationship == "Uses":
                g.add_edge(i.yUUID, i.xUUID, container=False)

            elif i.relationship == "Contains":
                g.add_edge(i.xUUID, i.yUUID, container=True, dashes=True)
                g.nodes[i.xUUID]["nodeMetadata"]["type"] = NodeType.Container

            else:
                logger.warning(f"Unimplemented relationship: {i.relationship}")

    elif edgeType == EdgeType.MetadataSimilarity:
        pass

    if enableCulling:
        g.remove_nodes_from(list(networkx.isolates(g)))  # Cull nodes with no edges
    elif networkx.number_of_isolates(g) > 500:
        logger.info(
            f"Large number of isolate nodes (nodes without any edges) detected. Consider re-running {Path(__file__).name} with --cull to improve performance"
        )

    # Set node size based on connected edges
    updatedValues = {}
    for ID in g.nodes:
        fileType = g.nodes[ID]["nodeMetadata"]["type"]
        if fileType == NodeType.File:
            updatedValues[ID] = DisplaySettings.icon_scale_factor * max(2, g.in_degree(ID))
        elif fileType == NodeType.Container:
            updatedValues[ID] = DisplaySettings.icon_scale_factor * max(1, g.degree(ID))

    networkx.set_node_attributes(g, updatedValues, "size")

    return g


def generate_pyvis_graph(
    graph: networkx.graph, filename: str, use_progress_bar: bool = False
) -> None:
    pv = pyvis.network.Network(
        directed=True,
        height="100vh",
        width="100vw",
        bgcolor=DisplaySettings.bg_color,
        font_color=DisplaySettings.fg_color,
        cdn_resources="remote",
    )

    currentDir = os.path.dirname(os.path.abspath(__file__))
    pv.template_dir = os.path.join(
        currentDir, "./customTemplates/"
    )  # Use custom template to fix CSS issue with not filling page
    pv.templateEnv = Environment(loader=FileSystemLoader(pv.template_dir))

    pv.force_atlas_2based()

    pv.options.interaction.selectConnectedEdges = True

    if graph.number_of_nodes() > 600 and use_progress_bar:
        logger.info(
            f"Large graph detected. Disabling physics to speed up loading time, this can be re-enabled by using the toggle on the left side of the page. Disable this behavior by re-running {__file__} with -pb/--use-progress-bar"
        )
        pv.toggle_physics(False)

    pv.from_nx(graph)

    # Replace node shape with icon if a container
    for n in pv.nodes:
        if n["nodeMetadata"]["type"] == NodeType.Container:
            n["shape"] = "dot"  # Embed icon in shape
            n["icon"] = {
                "face": "'Font Awesome 6 Free'",
                "weight": "bold",
                "code": "\uf07c",  # Folder open icon
                "color": DisplaySettings.fg_color,
            }
        if n["nodeMetadata"]["type"] == NodeType.File:
            n["shape"] = "dot"
            n["icon"] = {
                "face": "'Font Awesome 6 Free'",
                "weight": "bold",
                "code": "\uf15b",  # fa-file
                "color": DisplaySettings.fg_color,
            }

    pv.write_html(filename, notebook=False)


def main():
    parser = ArgumentParser(description="Surfactant SBOM Visualization")
    parser.add_argument(
        "-p",
        "--path",
        nargs="+",
        help="Path(s) to JSON SBOMs",
        required=True,
    )

    parser.add_argument(
        "-c",
        "--cull",
        default=False,
        nargs="?",
        help="Enable culling of isolated nodes (may improve performance on large graphs at the cost of node completeness)",
    )

    parser.add_argument(
        "-pb",
        "--use-progress-bar",
        default=False,
        nargs="?",
        help="Display progress bar while waiting for large graphs to load instead of disabling physics",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)

    args = parser.parse_args()

    sboms: List[dict] = []
    for path in args.path:
        with open(path, "r") as f:
            sboms.append({"sbom": SBOM.from_json(f.read()), "sbomFileName": Path(path).name})

    g = generate_dependency_graph(sboms[0], (args.cull is None))

    filename = Path(args.path[0]).stem + ".html"
    generate_pyvis_graph(g, filename, (args.use_progress_bar is not None))


if __name__ == "__main__":
    main()
