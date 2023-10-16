import json
import uuid as uuid_module
from collections import deque

import click
from loguru import logger

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._relationship import Relationship
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._system import System


@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sboms", type=click.File("r"), required=True, nargs=-1)
@click.option("--config_file", type=click.File("r"), required=False)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=surfactant.output.[cytrics|csv|spdx]_writer",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=surfactant.input_readers.[cytrics|cyclonedx|spdx]_reader",
)
@click.command("merge")
def merge_command(input_sboms, sbom_outfile, config_file, output_format, input_format):
    """Merge two or more INPUT_SBOMS together into SBOM_OUTFILE.

    An optional CONFIG_FILE can be supplied to specify a root system entry
    """
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    sboms = []
    for sbom in input_sboms:
        sboms.append(input_reader.read_sbom(sbom))
    config = None
    if config_file:
        config = json.load(config_file)
    merge(sboms, sbom_outfile, config, output_writer)


def merge(input_sboms, sbom_outfile, config, output_writer):
    """Merge two or more SBOMs."""
    merged_sbom = input_sboms[0]
    for sbom_m in input_sboms[1:]:
        merged_sbom.merge(sbom_m)

    rel_graph = construct_relationship_graph(merged_sbom)
    roots = get_roots_check_cycles(rel_graph)
    system = create_system_object(merged_sbom, config)
    merged_sbom.systems.append(system)

    # Add a system relationship to each root software/systems entry identified
    for r in roots:
        merged_sbom.relationships.append(
            Relationship(xUUID=system["UUID"], yUUID=r, relationship="Includes")
        )

    output_writer.write_sbom(merged_sbom, sbom_outfile)


def construct_relationship_graph(sbom: SBOM):
    """Function to get create a relationship graph of systems and software within an sbom

    Args:
        sbom (SBOM): The sbom to generate relationship graph from.
    """
    # construct a graph for adding a system relationship to all root software entries
    rel_graph = {}
    # add all UUIDs as nodes in the graph
    for system in sbom.systems:
        rel_graph[system.UUID] = []
    for sw in sbom.software:
        rel_graph[sw.UUID] = []
    # iterate through all relationships, adding edges to the adjacency list
    for rel in sbom.relationships:
        # check case where xUUID doesn't exist (and error if yUUID doesn't exist) in the graph
        if rel.xUUID not in rel_graph or rel.yUUID not in rel_graph:
            logger.error("====ERROR xUUID or yUUID doesn't exist====")
            logger.error(f"{rel = }")
            continue
        # consider also including relationship type for the edge
        # treat as directed graph, with inverted edges (pointing to parents) so dfs will eventually lead to the root parent node for a (sub)graph
        rel_graph[rel.yUUID].append(rel.xUUID)
    return rel_graph


def get_roots_check_cycles(rel_graph):
    """Function to get roots of the sbom and check for circular dependencies

    Args:
        rel_graph: The relationship graph for an sbom.
    """
    visited = set()
    roots = set()
    rootFound = set()
    recursionStack = deque()

    def dfs(rel):
        recursionStack.append(rel)
        # if the node is already visited, no revisiting required
        if rel in visited:
            recursionStack.pop()
            return rel in rootFound
        # mark the node as visited
        visited.add(rel)
        # the node has no parents, it is a root
        if not rel_graph[rel]:
            roots.add(rel)
            rootFound.add(rel)
            recursionStack.pop()
            return True
        cycle = False
        # node is not a root, move on to parents
        for parent in rel_graph[rel]:
            # detect cycles
            if parent in recursionStack:
                logger.info(f"CYCLE DETECTED: {parent} {rel}")
                cycle = True
            if dfs(parent):
                rootFound.add(rel)
        # if there was a cycle, and none of the parents led to a definite root node
        if cycle and rel not in rootFound:
            logger.info(f"CYCLE AND NO ROOT FOUND, SETTING {rel} AS THE ROOT")
            roots.add(rel)
            rootFound.add(rel)
        recursionStack.pop()
        return rel in rootFound

    for rel in rel_graph:
        dfs(rel)
    logger.info(f"ROOTS: {roots}")
    return roots


def create_system_object(sbom: SBOM, config=None) -> System:
    """Function to create an accurate system object

    Positional arguments:
        sbom (SBOM): The SBOM the system object is being created for.
        config: The user specified config json (Optional).

    Returns:
        System: The created system object.
    """

    system = {}
    if config:
        system = config["system"]
    # make sure the required fields are present and at least mostly valid
    if ("UUID" not in system) or not sbom.is_valid_uuid4(system["UUID"]):
        system["UUID"] = str(uuid_module.uuid4())
    if "name" not in system:
        system["name"] = ""
    captureStart = -1
    captureEnd = -1
    for sw in sbom.software:
        if captureStart and sw.captureTime:
            if captureStart == -1 or sw.captureTime < captureStart:
                captureStart = sw.captureTime
        if captureEnd and sw.captureTime:
            if captureEnd == -1 or sw.captureTime > captureEnd:
                captureEnd = sw.captureTime
    if "captureStart" not in system or not system["captureStart"]:
        system["captureStart"] = captureStart
    if "captureEnd" not in system or not system["captureEnd"]:
        system["captureEnd"] = captureEnd
    return system
