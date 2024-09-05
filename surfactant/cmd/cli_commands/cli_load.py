from loguru import logger
from pathlib import Path

from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.cmd.cli_commands.cli_base import Cli

class Load(Cli):
    """
    A class that implements the surfactant cli load functionality

    """
    def __init__(self, *args, input_format, **kwargs):
        """Executes the load class constructor

        param: input_format   The format of the sbom being loaded
        """
        self.input_format = input_format
        super().__init__(*args, **kwargs)

    def execute(self, input_file):
        """Executes the main functionality of the load class
        param: input_file   The sbom load into the cli
        """
        pm = get_plugin_manager()
        input_reader = find_io_plugin(pm, self.input_format, "read_sbom")
        self.sbom = input_reader.read_sbom(input_file)

        serialized_sbom = self.serialize(self.sbom)
        with open(Path(self.data_dir, self.sbom_filename), "wb+") as f:
            f.write(serialized_sbom)
