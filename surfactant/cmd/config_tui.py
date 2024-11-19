# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import os
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


class SelectFile(textual.screen.ModalScreen[Optional[textual.widgets.DirectoryTree.FileSelected]]):
    """Pop-up to select a file"""

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DirectoryTree("./", id="file_dir")
        yield textual.widgets.Button("Go up a directory", id="up_dir")

    @textual.on(textual.widgets.Button.Pressed, "#up_dir")
    def handle_up_dir(self):
        tree = self.get_child_by_id("file_dir", textual.widgets.DirectoryTree)
        tree.path = tree.path.parent.resolve()
        tree.reload()

    def on_directory_tree_file_selected(
        self, path: textual.widgets.DirectoryTree.FileSelected
    ) -> None:
        self.dismiss(path)

    def on_key(self, event: textual.events.Key):
        if event.key == "escape":
            self.dismiss(None)


class ExtractPathSelector(textual.widgets.Static):
    def __init__(self, path, **kwargs):
        super().__init__(**kwargs)
        self.path = path
        self.alive = True

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Delete Path", id="delete_path")
        yield textual.widgets.Button("Select Path", id="select_path")
        yield textual.widgets.Label(f"Path: {self.path}", id="path")

    @textual.on(textual.widgets.Button.Pressed, "#select_path")
    def on_select_path(self):
        def set_path(path: Optional[textual.widgets.DirectoryTree.FileSelected]):
            if path:
                self.path = path.path.as_posix()
                self.get_child_by_id("path", textual.widgets.Label).update(f"Path: {self.path}")

        self.app.push_screen(SelectFile(), set_path)

    @textual.on(textual.widgets.Button.Pressed, "#delete_path")
    def on_delete_path(self):
        self.remove()
        self.alive = False


class ExtractPathAdder(textual.widgets.Static):
    """A widget for adding extract path selectors"""

    def __init__(self, entry_id):
        super().__init__()
        self.paths = []
        for path in self.app.config_data[entry_id]["extractPaths"]:
            self.paths.append(ExtractPathSelector(path))

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Add Extract Path", id="add_path")
        yield textual.containers.Container(id="extract_path_holder")
        entries = self.app.query_one("#config_entries", textual.containers.ScrollableContainer)
        for path in self.paths:
            if path.alive:
                entries.mount(path)

    @textual.on(textual.widgets.Button.Pressed, "#add_path")
    def on_add_path(self, path=""):
        entries = self.app.query_one("#config_entries", textual.containers.ScrollableContainer)
        self.paths.append(ExtractPathSelector(path))
        entries.mount(self.paths[-1])


class ArchiveEntry(textual.widgets.Static):
    def __init__(self, entry_id):
        super().__init__()
        self.archive_loc = self.app.config_data[entry_id]["archive"]

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Select Archive", id="archive_button")
        yield textual.widgets.Label(f"Archive: {self.archive_loc}", id="archive_label")

    @textual.on(textual.widgets.Button.Pressed, "#archive_button")
    def on_archive_button(self):
        def set_archive(path: Optional[textual.widgets.DirectoryTree.FileSelected]):
            if path:
                loc = path.path.as_posix()
                self.archive_loc = loc
                self.get_child_by_id("archive_label", textual.widgets.Label).update(
                    f"Archive: {loc}"
                )

        self.app.push_screen(SelectFile(), set_archive)


class InstallPrefix(textual.widgets.Static):
    def __init__(self, entry_id):
        super().__init__()
        self.install_prefix = self.app.config_data[entry_id]["installPrefix"]

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Label("Install Prefix:")
        yield textual.widgets.Input(self.install_prefix, id="prefix")

    @textual.on(textual.widgets.Input.Changed, "#prefix")
    def on_prefix_change(self):
        self.install_prefix = self.query_one("#prefix", textual.widgets.Input).value


class ConfigEntry(textual.widgets.Static):
    """A widget for holding a single entry within a config file"""

    def __init__(self, entry_id):
        super().__init__()
        self.entry_id = entry_id
        self.archive_entry = ArchiveEntry(entry_id)
        self.install_prefix = InstallPrefix(entry_id)
        self.extract_path_adder = ExtractPathAdder(entry_id)
        self.alive = True

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Delete this entry", id="delete_entry")
        yield self.archive_entry
        yield self.install_prefix
        yield self.extract_path_adder

    @textual.on(textual.widgets.Button.Pressed, "#delete_entry")
    def on_delete_entry(self):
        def delete_self(do_it: Optional[bool]):
            if do_it:
                self.remove()
                entries = self.app.query_one(
                    "#config_entries", textual.containers.ScrollableContainer
                )
                for child in entries.children:
                    child.remove()
                self.app.query_one(f"#view_entry_{self.entry_id}").remove()
                self.alive = False

        self.app.push_screen(
            YesNoScreen("Are you sure you want to delete this entry?"), delete_self
        )


class AddEntry(textual.widgets.Static):
    """A widget for adding another config entry"""

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("+", id="add_config_entry")

    @textual.on(textual.widgets.Button.Pressed, "#add_config_entry")
    def on_add_config_entry(self):
        if self.app.entry_id not in self.app.config_data:
            self.app.config_data[self.app.entry_id] = {
                "archive": "",
                "extractPaths": [],
                "installPrefix": "",
            }
        add_entries = self.app.query_one("#add_entry_scrollable")
        add_entries.mount(
            textual.widgets.Button(str(self.app.entry_id), id=f"view_entry_{self.app.entry_id}")
        )
        self.app.config_entries[self.app.entry_id] = ConfigEntry(self.app.entry_id)
        self.app.entry_id += 1


class MainBody(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.selected_button_num = 0

    def compose(self) -> textual.app.ComposeResult:
        yield textual.containers.ScrollableContainer(id="config_entries")
        yield textual.containers.ScrollableContainer(
            AddEntry(id="add_entry"), id="add_entry_scrollable"
        )

    def on_button_pressed(self, event: textual.widgets.Button.Pressed) -> None:
        START_BUTTON_TEXT = "view_entry_"
        if button_id := event.button.id:
            if button_id.startswith(START_BUTTON_TEXT):
                button_num = int(button_id[len(START_BUTTON_TEXT) :])
                # Remove old button selection
                try:
                    self.app.query_one(
                        f"#{START_BUTTON_TEXT}{self.selected_button_num}", textual.widgets.Button
                    ).remove_class("selected")
                except textual.css.query.NoMatches:
                    pass
                event.button.add_class("selected")
                entry = self.app.query_one(
                    "#config_entries", textual.containers.ScrollableContainer
                )

                # Only change the panel if a new button was pressed
                if self.selected_button_num != button_num:
                    for child in entry.children:
                        child.remove()
                    entry.mount(self.app.config_entries[button_num])
                self.selected_button_num = button_num


class ConfigTUI(textual.app.App):
    """An app for creating and modifying Surfactant config files"""

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("s", "save_sbom", "Save SBOM"),
        ("q", "quit", "Quit"),
    ]
    TITLE = "Surfactant Config TUI"
    CSS_PATH = "../web-files/config_tui.tcss"

    def __init__(self, config_path: str):
        super().__init__()
        if os.path.exists(config_path):
            with open(config_path, "r") as config_file:
                self.config_json = json.load(config_file)
        else:
            self.config_json = {}

        self.config_path = config_path
        self.sub_title = config_path
        self.config_entries = {}
        self.config_data = {}
        self.entry_id = 1

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Header()
        yield textual.widgets.Footer()
        yield MainBody()

    def on_mount(self):
        for i, entry in enumerate(self.config_json):
            i += 1
            self.config_data[i] = {"archive": "", "extractPaths": [], "installPrefix": ""}
            if "archive" in entry:
                self.config_data[i]["archive"] = entry["archive"]
            if "extractPaths" in entry:
                self.config_data[i]["extractPaths"] = entry["extractPaths"]
            if "installPrefix" in entry:
                self.config_data[i]["installPrefix"] = entry["installPrefix"]
            self.query_one("#add_entry", AddEntry).on_add_config_entry()

    def action_toggle_dark(self) -> None:
        """A binding for toggling dark mode"""
        self.dark = not self.dark

    def action_save_sbom(self) -> None:
        """Saves the current SBOM to file"""
        to_save = []
        for entry in self.config_entries.values():
            to_save.append({})
            write_to = to_save[-1]
            # Load data, ignoring it if empty
            archive = entry.archive_entry.archive_loc
            if len(archive) > 0:
                write_to["archive"] = archive
            install_prefix = entry.install_prefix.install_prefix
            if len(install_prefix) > 0:
                write_to["installPrefix"] = install_prefix
            # Always write extract paths
            write_to["extractPaths"] = []
            extract_path_adder = entry.extract_path_adder
            for selector in extract_path_adder.paths:
                if selector.alive:
                    write_to["extractPaths"].append(selector.path)

        with open(self.config_path, "w") as f:
            f.write(json.dumps(to_save))

    def action_quit(self) -> None:
        self.action_save_sbom()
        self.app.exit()


@click.command("config_tui")
@click.argument("config_file", type=str, required=True)
def config_tui(config_file):
    """Create a configuration input file with a TUI"""
    app = ConfigTUI(config_file)
    app.run()
