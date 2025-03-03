# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import os
from typing import Optional
import pathlib

import click
import textual.app
import textual.containers
import textual.css.query
import textual.events
import textual.screen
import textual.types
import textual.widgets
import textual.widgets.button

import surfactant.cmd.generate
import surfactant.cmd.merge


class SelectFileButtons(textual.widgets.Static):
    # pylint: disable=too-few-public-methods
    def __init__(self, allow_folder_selection: bool):
        super().__init__()
        self.allow_folder_selection = allow_folder_selection

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Go up a directory", id="up_dir")
        if self.allow_folder_selection:
            yield textual.widgets.Button("Select directory", id="select_dir")


class SelectFile(textual.screen.ModalScreen[Optional[textual.widgets.DirectoryTree.FileSelected]]):
    """Pop-up to select a file"""

    def __init__(self, allow_folder_selection: bool, start_path: str):
        super().__init__()
        self.allow_folder_selection = allow_folder_selection
        self.dir_selected = start_path

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DirectoryTree(self.dir_selected, id="file_dir")
        yield SelectFileButtons(self.allow_folder_selection)

    @textual.on(textual.widgets.Button.Pressed, "#up_dir")
    def handle_up_dir(self):
        tree = self.get_child_by_id("file_dir", textual.widgets.DirectoryTree)
        tree.path = tree.path.parent.resolve()
        tree.reload()

    @textual.on(textual.widgets.Button.Pressed, "#select_dir")
    def handle_select_dir(self):
        self.dismiss(self.dir_selected)

    def on_directory_tree_directory_selected(
        self, path: textual.widgets.DirectoryTree.DirectorySelected
    ) -> None:
        self.dir_selected = path.path.as_posix()

    def on_directory_tree_file_selected(
        self, path: textual.widgets.DirectoryTree.FileSelected
    ) -> None:
        self.dismiss(path.path.as_posix())

    def on_key(self, event: textual.events.Key):
        if event.key == "escape":
            self.dismiss(None)


class FileInput(textual.widgets.Static):
    def __init__(self, label: str, allow_folder_selection: bool, file_input: Optional[textual.widgets.Input]):
        super().__init__()
        self.label = label
        self.file_input = file_input
        self.allow_folder_selection = allow_folder_selection
        self.input_path = ""

    def compose(self) -> textual.app.ComposeResult:
        if len(self.input_path) == 0:
            yield textual.widgets.Label(f"{self.label} [Click to set]")
        else:
            yield textual.widgets.Label(f"{self.label} {self.input_path}")

    def on_click(self):
        def set_path(path: Optional[pathlib.Path]):
            if path:
                if self.file_input:
                    # Set the directory and the file separately
                    self.input_path = os.path.dirname(path)
                    self.file_input.value = os.path.basename(path)
                else:
                    # Just set the path
                    self.input_path = path
                self.query_one(textual.widgets.Label).update(f"{self.label} {self.input_path}")

        base_dir = "./" if len(self.input_path) == 0 else self.input_path
        self.app.push_screen(
            SelectFile(self.allow_folder_selection, base_dir), set_path
        )


# pylint: disable-next=too-many-instance-attributes
class GenerateTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.file_input = FileInput("Input file:", True, None)
        self.output_name = textual.widgets.Input(placeholder="Output Filename")
        self.output_dir = FileInput("Output directory:", True, self.output_name)
        self.input_sbom = FileInput("Input SBOM:", False, None)
        self.skip_gather = textual.widgets.Checkbox("Skip Gather")
        self.skip_relationships = textual.widgets.Checkbox("Skip Relationships")
        self.input_format = textual.widgets.Select([("CyTRICS", "CyTRICS")], allow_blank=False)
        self.skip_install_path = textual.widgets.Checkbox("Skip Install Path")
        self.recorded_institution = textual.widgets.Input(placeholder="Recorded Institution")
        self.output_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )

    def compose(self) -> textual.app.ComposeResult:
        yield self.file_input
        yield self.output_dir
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Filename: "), self.output_name
        )
        yield textual.widgets.Rule()
        yield textual.widgets.Label("Optional options:")
        yield self.input_sbom
        yield self.skip_gather
        yield self.skip_relationships
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Input Format: "), self.input_format
        )
        yield self.skip_install_path
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Recorded Institution: "), self.recorded_institution
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Format: "), self.output_format
        )
        yield textual.widgets.Button("Run", id="run")

    @textual.on(textual.widgets.Button.Pressed, "#run")
    def handle_run(self) -> None:
        if len(self.file_input.input_path) == 0:
            self.app.notify("No input file selected")
            return
        if len(self.output_dir.input_path) == 0:
            self.app.notify("No output directory selected")
            return
        if len(self.output_name.value) == 0:
            self.app.notify("No output name supplied")
            return
        with self.app.suspend():
            args = [
                self.file_input.input_path,
                f"{self.output_dir.input_path}/{self.output_name.value}",
            ]
            if len(self.input_sbom.input_path) > 0:
                args.append(self.input_sbom.input_path)
            if self.skip_gather.value:
                args.append("--skip_gather")
            if self.skip_relationships.value:
                args.append("--skip_relationships")
            if len(self.input_format.value) > 0:
                args.append("--input_format")
                args.append(self.input_format.value)
            if self.skip_install_path.value:
                args.append("--skip_install_path")
            args.append("--input_format")
            args.append(self.input_format.value)
            args.append("--output_format")
            args.append(self.output_format.value)
            # pylint: disable-next=no-value-for-parameter
            surfactant.cmd.generate.sbom(args, standalone_mode=False)
            print("Press enter to continue")
            _ = input()
        self.app.refresh()


class MergePath(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.path_selector = FileInput("Input file:", False, None)
        self.active = True

    def compose(self) -> textual.app.ComposeResult:
        yield textual.containers.HorizontalGroup(
            textual.widgets.Button("-", id="remove_path"), self.path_selector
        )

    @textual.on(textual.widgets.Button.Pressed, "#remove_path")
    def remove_path(self):
        self.active = False
        self.remove()


class MergePathsHolder(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.merge_paths = []

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("+", id="add_merge_path")
        for m_path in self.merge_paths:
            if m_path.active:
                yield m_path

    @textual.on(textual.widgets.Button.Pressed, "#add_merge_path")
    def add_merge_path(self):
        self.merge_paths.append(MergePath())
        self.mount(self.merge_paths[-1], before="#add_merge_path")


class MergeTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.merge_paths = MergePathsHolder()
        self.output_name = textual.widgets.Input(placeholder="Output Filename")
        self.output_dir = FileInput("Output directory:", True, self.output_name)
        self.input_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )
        self.output_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )
        self.config_file = FileInput("Config File:", False, None)

    def compose(self) -> textual.app.ComposeResult:
        yield self.merge_paths
        yield self.output_dir
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Filename: "), self.output_name
        )
        yield textual.widgets.Rule()
        yield textual.widgets.Label("Optional options:")
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Input Format: "), self.input_format
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Format: "), self.output_format
        )
        yield self.config_file
        yield textual.widgets.Button("Run", id="run")

    @textual.on(textual.widgets.Button.Pressed, "#run")
    def handle_run(self):
        args = []
        if len(self.merge_paths.merge_paths) == 0:
            self.app.notify("No inputs given")
            return
        if len(self.output_dir.input_path) == 0:
            self.app.notify("No output directory given")
            return
        if len(self.output_name.value) == 0:
            self.app.notify("No output filename given")
            return
        for m_path in self.merge_paths.merge_paths:
            if m_path.active:
                path = m_path.path_selector.input_path
                if len(path) == 0:
                    self.app.notify("One or more inputs not given")
                    return
                args.append(path)
        with self.app.suspend():
            args.append(f"{self.output_dir.input_path}/{self.output_name.value}")
            args.append("--input_format")
            args.append(self.input_format.value)
            args.append("--output_format")
            args.append(self.output_format.value)
            config = self.config_file.input_path
            if len(config) > 0:
                args.append("--config_file")
                args.append(config)
            # pylint: disable-next=no-value-for-parameter
            surfactant.cmd.merge.merge_command(args, standalone_mode=False)
            print("Press enter to continue")
            _ = input()
        self.app.refresh()


# TODO: Rewrite to use ContentSwitcher?
class TUI(textual.app.App):
    """An app for running Surfactant commands"""

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit"),
    ]
    TITLE = "Surfactant TUI"
    CSS_PATH = "../web-files/tui.tcss"

    def __init__(self):
        super().__init__()
        self.generate_tab = GenerateTab()
        self.merge_tab = MergeTab()

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Header()
        yield textual.widgets.Footer()
        Tab = textual.widgets.Tab
        yield textual.widgets.Tabs(Tab("Generate", id="Generate"), Tab("Merge", id="Merge"))
        yield textual.containers.ScrollableContainer(id="MainContainer")

    def on_mount(self) -> None:
        self.query_one(textual.widgets.Tabs).focus()

    def on_tabs_tab_activated(self, event: textual.widgets.Tabs.TabActivated) -> None:
        TABS = (("Generate", self.generate_tab), ("Merge", self.merge_tab))
        main_container = self.get_child_by_id(
            "MainContainer", textual.containers.ScrollableContainer
        )
        main_container.query_children().remove()
        for name, tab in TABS:
            if event.tab.id == name:
                main_container.mount(tab)

    def action_toggle_dark(self) -> None:
        """A binding for toggling dark mode"""
        # pylint: disable-next=attribute-defined-outside-init
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"

    def action_quit(self) -> None:
        self.app.exit()


@click.command("tui")
def tui():
    """Create a configuration input file with a TUI"""
    app = TUI()
    app.run()
