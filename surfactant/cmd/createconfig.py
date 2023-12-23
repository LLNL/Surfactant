import json
from pathlib import Path

import click
from loguru import logger


@click.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=str,
    help="Output JSON file name, defaults to end of directory string passed as input",
)
@click.option(
    "--install-prefix",
    type=str,
    default="/",
    help="Install prefix to use in the configuration (default: '/')",
)
def create_config(directory, output, install_prefix):
    """Create surfactant input configuration file based on input directory."""
    extract_paths = [Path(directory).as_posix()]
    config_dict = {"extractPaths": extract_paths, "installPrefix": install_prefix}
    config_out = [config_dict]
    output_file_name = output or Path(directory).stem + ".json"
    with open(output_file_name, "w") as json_file:
        json.dump(config_out, json_file, indent=4)
    logger.info(f"Data written to {output_file_name}")
