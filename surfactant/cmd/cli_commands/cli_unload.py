import os
from loguru import logger
from pathlib import Path

from surfactant.cmd.cli_commands.cli_base import Cli


class Unload(Cli):
    """
    A class that implements the surfactant cli unload functionality

    """
    def __init__(self, *args, **kwargs):
        """Executes the unload class constructor
        """
        super().__init__(*args, **kwargs)

    def execute(self):
        """Executes the main functionality of the unload class
        """
        sbom_path = Path(self.data_dir, self.sbom_filename)
        subset_path = Path(self.data_dir, self.subset_filename)
        if not os.path.exists(sbom_path):
            logger.info(f"No sbom loaded, nothing to unload")
        else:
            os.remove(sbom_path)
        if os.path.exists(subset_path):
            os.remove(subset_path)
