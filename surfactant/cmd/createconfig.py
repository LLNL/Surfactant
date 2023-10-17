import json
from pathlib import Path

import click


@click.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=str,
    help="Output JSON file name, defaults to end of directory string passed as input",
)
def create_config(directory, output):
    """Create surfactant input configuration file based on input directory."""
    starting_directory = Path(directory)
    extract_paths = []

    # Check if there are any files in the directory
    if any(item.is_file() for item in starting_directory.iterdir()):
        extract_paths.append(starting_directory.as_posix())
    else:
        # If there are no files, add the immediate subdirectories
        for item in starting_directory.iterdir():
            if item.is_dir():
                extract_paths.append(item.as_posix())

    config_dict = {"extractPaths": extract_paths, "installPrefix": "/"}
    config_out = [config_dict]

    output_file_name = output or starting_directory.with_suffix(".json")

    with open(output_file_name, "w") as json_file:
        json.dump(config_out, json_file, indent=4)

    logger.info(f"Data written to {output_file_name}")
