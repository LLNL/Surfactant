import os
from pathlib import Path

from loguru import logger

from surfactant.cmd.cli_commands.cli_base import Cli


class Unload(Cli):
    """
    A class that implements the surfactant cli unload functionality

    """

    def execute(self):
        """Executes the main functionality of the unload class"""
        sbom_path = Path(self.data_dir, self.sbom_filename)
        subset_path = Path(self.data_dir, self.subset_filename)
        if not os.path.exists(sbom_path):
            logger.info("No sbom loaded, nothing to unload")
        else:
            os.remove(sbom_path)
        if os.path.exists(subset_path):
            os.remove(subset_path)
