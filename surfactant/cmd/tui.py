# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import os
import pathlib
from typing import Optional

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


class YesNoScreen(textual.screen.Screen[bool]):
    """Screen that presents a yes/no question"""

    def __init__(self, question: str) -> None:
        self.question = question
        super().__init__()

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Label(self.question)
        yield textual.widgets.Button("Yes", id="yes", variant="success")
        yield textual.widgets.Button("No", id="no")

    @textual.on(textual.widgets.Button.Pressed, "#yes")
    def handle_yes(self) -> None:
        self.dismiss(True)

    @textual.on(textual.widgets.Button.Pressed, "#no")
    def handle_no(self) -> None:
        self.dismiss(False)


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
    def __init__(
        self, label: str, allow_folder_selection: bool, file_input: Optional[textual.widgets.Input]
    ):
        super().__init__()
        self.label = label
        self.file_input = file_input
        self.allow_folder_selection = allow_folder_selection
        self.input_path = ""

    def compose(self) -> textual.app.ComposeResult:
        if len(self.input_path) == 0:
            yield textual.widgets.Label(f"{self.label} \\[Click to set]")
        else:
            yield textual.widgets.Label(f"{self.label} {self.input_path}")

    def on_click(self):
        def set_path(path: Optional[pathlib.Path]):
            if path:
                if self.file_input and not os.path.isdir(path):
                    # Set the directory and the file separately
                    self.input_path = os.path.dirname(path)
                    self.file_input.value = os.path.basename(path)
                else:
                    # Just set the path
                    self.input_path = path
                self.query_one(textual.widgets.Label).update(f"{self.label} {self.input_path}")

        base_dir = "./"
        if os.path.isfile(self.input_path):
            base_dir = os.path.dirname(self.input_path)
        self.app.push_screen(SelectFile(self.allow_folder_selection, base_dir), set_path)


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


class InputPath(textual.widgets.Static):
    def __init__(self, desc="Input file:", allow_dir_selection=False):
        super().__init__()
        self.path_selector = FileInput(desc, allow_dir_selection, None)
        self.active = True

    def compose(self) -> textual.app.ComposeResult:
        yield textual.containers.HorizontalGroup(
            textual.widgets.Button("-", id="remove_path"), self.path_selector
        )

    @textual.on(textual.widgets.Button.Pressed, "#remove_path")
    def remove_path(self):
        self.active = False
        self.remove()


class InputPathsHolder(textual.widgets.Static):
    def __init__(self, prompt="Input file:", allow_dir_selection=False):
        super().__init__()
        self.input_paths: list[InputPath] = []
        self.prompt = prompt
        self.allow_dir_selection = allow_dir_selection

    def compose(self) -> textual.app.ComposeResult:
        for m_path in self.input_paths:
            if m_path.active:
                yield m_path
        yield textual.widgets.Button("+", id="add_input_path")

    @textual.on(textual.widgets.Button.Pressed, "#add_input_path")
    def add_input_path(self):
        self.input_paths.append(InputPath(self.prompt, self.allow_dir_selection))
        self.mount(self.input_paths[-1], before="#add_input_path")

    def add_path(self, path: str):
        self.input_paths.append(InputPath(self.prompt, self.allow_dir_selection))
        self.input_paths[-1].path_selector.input_path = path


class MergeTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.merge_paths = InputPathsHolder()
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


class ConfigEntry(textual.widgets.Static):
    def __init__(self, header_num):
        super().__init__()
        self.active = True
        self.border_title = str(header_num)
        self.archive = FileInput("Archive:", False, None)
        self.install_prefix = textual.widgets.Input(placeholder="Install Prefix")
        self.container_prefix = textual.widgets.Input(placeholder="Container Prefix")
        self.extract_paths = InputPathsHolder("[Click to set extract path]", True)

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Delete this entry", id="delete_entry")
        yield self.archive
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Install Prefix: "), self.install_prefix
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Container Prefix: "), self.container_prefix
        )
        yield textual.widgets.Label("Extract Paths:")
        yield self.extract_paths

    @textual.on(textual.widgets.Button.Pressed, "#delete_entry")
    def delete_entry(self):
        def delete_self(do_it: Optional[bool]):
            if do_it:
                self.remove()
                self.active = False

        self.app.push_screen(
            YesNoScreen("Are you sure you want to delete this entry?"), delete_self
        )


class ConfigTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.config_name = textual.widgets.Input(placeholder="Config filename")
        self.config_input = FileInput("Config directory:", True, self.config_name)
        self.config_entries: list[ConfigEntry] = []
        self.config_number = 1

    def compose(self) -> textual.app.ComposeResult:
        yield self.config_input
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Config filename: "), self.config_name
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Button("Save", id="save"),
            textual.widgets.Label("   "),
            textual.widgets.Button("Load", id="load"),
        )
        yield textual.widgets.Rule()
        yield from self.config_entries
        yield textual.widgets.Button("+", id="add_config_entry")

    @textual.on(textual.widgets.Button.Pressed, "#add_config_entry")
    def add_config_entry(self):
        self.config_entries.append(ConfigEntry(self.config_number))
        self.mount(self.config_entries[-1], before="#add_config_entry")
        self.config_number += 1

    @textual.on(textual.widgets.Button.Pressed, "#save")
    def save(self):
        to_save = []
        for entry in self.config_entries:
            to_save.append({})
            write_to = to_save[-1]
            archive = entry.archive.input_path
            if len(archive) > 0:
                write_to["archive"] = archive
            install_prefix = entry.install_prefix.value
            if len(install_prefix) > 0:
                write_to["install_prefix"] = install_prefix
            write_to["extractPaths"] = []
            for path in entry.extract_paths.input_paths:
                if path.active:
                    write_to["extractPaths"].append(path.path_selector.input_path)
            container_prefix = entry.container_prefix.value
            if len(container_prefix) > 0:
                write_to["containerPrefix"] = container_prefix
        file_to_save = self.config_input.input_path + "/" + self.config_name.value
        try:
            with open(file_to_save, "w") as f:
                f.write(json.dumps(to_save, indent=2))
        except IsADirectoryError:
            self.app.notify(f"Could not write to {file_to_save}")
            return
        self.app.notify(f"Wrote config to {file_to_save}")

    @textual.on(textual.widgets.Button.Pressed, "#load")
    def load(self):
        file_to_load = self.config_input.input_path + "/" + self.config_name.value
        try:
            with open(file_to_load, "r") as config_file:
                js = json.load(config_file)
        except (FileNotFoundError, IsADirectoryError):
            self.app.notify(f"Could not find file {file_to_load}")
            return
        except json.JSONDecodeError:
            self.app.notify(f"Error when parsing JSON in {file_to_load}")
            return
        # Delete all other entries
        for ce in self.config_entries:
            ce.remove()
        self.config_entries = []
        self.config_number = 1
        for entry in js:
            self.config_entries.append(ConfigEntry(self.config_number))
            self.config_number += 1
            cur_entry = self.config_entries[-1]
            if "archive" in entry:
                cur_entry.archive.input_path = entry["archive"]
            if "extractPaths" in entry:
                for ep in entry["extractPaths"]:
                    cur_entry.extract_paths.add_path(ep)
            if "installPrefix" in entry:
                cur_entry.install_prefix.value = entry["installPrefix"]
            if "containerPrefix" in entry:
                cur_entry.container_prefix.value = entry["containerPrefix"]
        for entry in self.config_entries:
            self.mount(entry, before="#add_config_entry")


# TODO: Rewrite to use ContentSwitcher?
class TUI(textual.app.App):
    """An app for running Surfactant commands"""

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit"),
    ]
    TITLE = "Surfactant TUI"
    CSS_PATH = "../ui-resources/tui.tcss"

    def __init__(self):
        super().__init__()
        self.generate_tab = GenerateTab()
        self.merge_tab = MergeTab()
        self.config_tab = ConfigTab()

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Header()
        yield textual.widgets.Footer()
        Tab = textual.widgets.Tab
        with textual.widgets.TabbedContent():
            with textual.widgets.TabPane("Generate"):
                yield self.generate_tab
            with textual.widgets.TabPane("Merge"):
                yield self.merge_tab
            with textual.widgets.TabPane("Config"):
                yield self.config_tab

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
