from loguru import logger

from surfactant.cmd.cli_commands.cli_base import Cli

class Merge(Cli):
    """
    A class that implements the surfactant cli merge functionality
    """

    def __init__(self):
        """Initializes the cli_merge class"""
        super(Merge, self).__init__()

    def execute(self, **kwargs):
        """Executes the main functionality of the cli_merge class
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        self.sbom = self.load_current_sbom()
        self.subset = self.load_current_subset()
        if not self.sbom:
            logger.error("No sbom currently loaded. Load an sbom with `surfactant cli load`")
            return False
        if not self.subset:
            logger.warning("No subset to merge into main sbom")
            return False
        
        self.sbom.merge(self.subset)
        self.save_changes()
        self.delete_subset()
        return True
        
        
        
