import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from queue import Queue
from dataclasses import dataclass, asdict

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software
from surfactant import ContextEntry

try:
    from dapper_python.normalize import normalize_file_name, NormalizedFileName
    from dapper_python.dataset_loader import DatasetCatalog
    from dapper_python.databases.linuxDB import LinuxDB
    DAPPER_AVAILABLE = True
except ImportError:
    DAPPER_AVAILABLE = False
    logging.warning("dapper-python not installed. Dapper plugin will be disabled.")

logger = logging.getLogger(__name__)

@dataclass
class DapperPackageInfo:
    package_name: str
    full_package_name: str
    package_dataset: str
    normalized_name: str
    original_name: str
    file_path: str

    @classmethod
    def from_result(cls, result, dataset_name, filename):
        return cls(
            package_name=result.package_name,
            full_package_name=result.full_package_name,
            package_dataset=dataset_name, 
            normalized_name=result.normalized_name,
            original_name=filename,   
            file_path=str(result.file_path)
        )


class DapperPlugin:
    
    def __init__(self):
        """Initialize the Dapper plugin with dataset catalog."""
        self.catalog = None
        self.linux_datasets = []
        self.nuget_dataset = None
        if DAPPER_AVAILABLE:
            self._init_catalog()
    
    def _init_catalog(self):
        """Initialize the dataset catalog and check available datasets."""
        try:
            # Try to load the dataset catalog
            self.catalog = DatasetCatalog(app_name="dapper")
            
            # Check for available datasets
            available = self.catalog.get_available_datasets()
            logger.info(f"Dapper plugin: Found {len(available)} datasets")
            
            # Look for Linux and NuGet datasets
            for dataset in available:
                if any(distro in dataset for distro in ["debian", "ubuntu"]):
                    self.linux_datasets.append(dataset)
                    logger.info(f"Found Linux dataset: {dataset}")
                
            
            if not self.linux_datasets:
                logger.warning("No Linux datasets found for Dapper plugin")
            else:
                logger.info(f"Using {len(self.linux_datasets)} Linux datasets")
                
        except Exception as e:
            logger.warning(f"Failed to initialize Dapper catalog: {e}")
            self.catalog = None
    
    def lookup_package(self, file_path: str, file_types: List[str]) -> Optional[Dict[str, Any]]:
        if not self.catalog or not DAPPER_AVAILABLE:
            return None
        
        # Extract just the filename from the path
        filename = Path(file_path).name
        
        # Determine file type from Surfactant's filetype list
        file_type = None
        for ft in file_types:
            if 'ELF' in ft:
                file_type = 'ELF'
                break
            elif 'PE' in ft or 'PE32' in ft or 'DLL' in ft:
                file_type = 'PE'
                break
        
        # Also check by extension if not detected
        if not file_type:
            ext = Path(filename).suffix.lower()
            if ext in ['.so', '.o'] or (not ext and '.' not in filename):
                file_type = 'ELF'
            elif ext in ['.dll', '.exe', '.sys']:
                file_type = 'PE'
        
        if not file_type:
            return None
        
        all_results = []  # Initialize here!
        
        # Query all Linux datasets for ELF files
        if file_type == "ELF" and self.linux_datasets:  # Check list, not None variable
            for dataset_name in self.linux_datasets:
                try:
                    db_path = self.catalog.get_dataset_path(dataset_name)
                    
                    # Path resolution
                    if db_path and not db_path.is_absolute():
                        app_dir = Path(self.catalog.get_app_data_dir(self.catalog.app_name))
                        db_path = app_dir / db_path
                    
                    if not db_path or not db_path.exists():
                        logger.error(f"Dataset path not found: {db_path}")
                        continue
                    
                    linux_db = LinuxDB(db_path)
                    results = linux_db.query_filename(filename, normalize=True)
                    
                    if results:
                        # Add results from this dataset
                        packages = [
                            asdict(DapperPackageInfo.from_result(r, dataset_name, filename))
                            for r in results
                        ]
                        all_results.extend(packages)
                        logger.debug(f"Found {len(results)} matches in {dataset_name}")
                        
                except Exception as e:
                    logger.error(f"Error querying {dataset_name}: {e}")
        
        if all_results:
            return {"dapper_packages": all_results}
        
        return None
        
       


# Global plugin instance
_plugin_instance = None


def _get_plugin():
    global _plugin_instance
    if _plugin_instance is None:
        _plugin_instance = DapperPlugin()
    return _plugin_instance


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: List[str],
    context_queue: Queue[ContextEntry],
    current_context: Optional[ContextEntry],
    children: List[Software],
    software_field_hints: List[Tuple[str, object, int]],
    omit_unrecognized_types: bool,
) -> Optional[Dict[str, Any]]:
    if not DAPPER_AVAILABLE:
        return None
    
    plugin = _get_plugin()
    
    # Look up package information based on the file
    package_info = plugin.lookup_package(filename, filetype)
    
    if package_info:
        return package_info
    
    return None