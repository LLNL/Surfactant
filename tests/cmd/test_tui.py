# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

import pytest

from surfactant.cmd.tui import TUI
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager

import tests.cmd.common as common

testing_data = Path(Path(__file__).parent.parent, "data")


@pytest.mark.asyncio
async def test_generate(tmp_path):
    tui = TUI()
    async with tui.run_test() as pilot:
        # No good way to set files from here via the TUI - just set the path directly
        tui.generate_tab.specimen_context.input_path = str(testing_data / "Windows_dll_test_no1")
        tui.generate_tab.output_dir.input_path = str(tmp_path)
        # Type in the filename
        await pilot.click(tui.generate_tab.output_name)
        await pilot.press(*"out.json")
        # Run it
        await pilot.click("#run")
    common.test_generate_result_no_install_prefix(
        str(tmp_path / "out.json"), str(testing_data / "Windows_dll_test_no1")
    )


@pytest.mark.asyncio
async def test_merge(tmp_path):
    tui = TUI()
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, "cytrics", "write_sbom")
    input_reader = find_io_plugin(pm, "cytrics", "read_sbom")
    assert output_writer is not None
    assert input_reader is not None
    # Write the two SBOM's to files
    for i, sbom in enumerate((common.get_sbom1(), common.get_sbom2())):
        with open(tmp_path / f"sbom{i}.json", "w") as f:
            output_writer.write_sbom(sbom, f)
    async with tui.run_test() as pilot:
        # This is the only way I could figure out how to change tabs
        await pilot.press("right")
        # Add two merge paths (I don't know why the pauses are needed)
        await pilot.click("#add_input_path")
        await pilot.pause(0.1)
        await pilot.click("#add_input_path")
        await pilot.pause(0.1)
        # Set the merge paths
        print(tui.merge_tab.merge_paths.input_paths)
        for i, p in enumerate(tui.merge_tab.merge_paths.input_paths):
            p.path_selector.input_path = str(tmp_path / f"sbom{i}.json")
        tui.merge_tab.output_dir.input_path = str(tmp_path)
        # Set the output name
        await pilot.click(tui.merge_tab.output_name)
        await pilot.press(*"test_out.json")
        # Run it
        await pilot.click(tui.merge_tab.btn)
    with open(tmp_path / "test_out.json") as f:
        merged_sbom = input_reader.read_sbom(f)
    common.test_simple_merge_method(common.get_sbom1(), common.get_sbom2(), merged_sbom)


__context_data = """
[
  {
    "archive": "/home/samples/helics.tar.gz",
    "extractPaths": ["/home/samples/helics"],
    "installPrefix": "/"
  },
  {
    "archive": "/home/samples/helics_plugin.tar.gz",
    "extractPaths": ["/home/samples/helics_plugin"],
    "installPrefix": "/"
  }
]
"""


@pytest.mark.asyncio
async def test_context_roundtrip(tmp_path):
    tui = TUI()
    with open(tmp_path / "test_input.json", "w") as f:
        f.write(__context_data)
    async with tui.run_test() as pilot:
        # Change to context tab
        await pilot.press(*("right", "right"))
        # Load an existing context file
        tui.context_tab.context_input.input_path = str(tmp_path)
        tui.context_tab.context_name.value = "test_input.json"
        await pilot.click(tui.context_tab.load_btn)
        # Save it to a new file
        tui.context_tab.context_name.value = "test_output.json"
        await pilot.click(tui.context_tab.save_btn)
    # Compare the two JSON files
    with open(tmp_path / "test_input.json") as f:
        inp = json.load(f)
    with open(tmp_path / "test_output.json") as f:
        output = json.load(f)

    # There doesn't seem to be any better way of doing this
    def ordered(obj):
        if isinstance(obj, dict):
            return sorted(obj.items())
        return obj

    assert ordered(inp) == ordered(output)
