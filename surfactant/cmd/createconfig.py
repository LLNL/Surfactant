import json
import click
from pathlib import Path


@click.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("-o", "--output", type=str, help="Output JSON file name, defaults to end of directory string passed as input")
def create_config(directory, output):
    """Create surfactant input configuration file based on input directory passed as a command line argument."""

    # Use the provided starting directory path
    starting_directory = Path(directory)

    # Initialize the list to store directory paths
    extract_paths = []

    # Check if there are any files in the directory
    if any(starting_directory.iterdir()):
        # If there are files, use the input directory as one of the extractPaths
        extract_paths.append(str(starting_directory).replace("\\", "/"))  # Replace backslashes with forward slashes
    else:
        # If there are no files, iterate through subdirectories and add them
        for item in starting_directory.iterdir():
            if item.is_dir():
                extract_paths.append(str(item).replace("\\", "/"))  # Replace backslashes with forward slashes

    # Now, extract_paths contains the directory paths
    config_dict = {"extractPaths": extract_paths, "installPrefix": "/"}
    config_out = [config_dict]

    # Determine the output JSON file name
    output_file_name = output or starting_directory.stem + ".json"

    # Write config_dict to the JSON file
    with open(output_file_name, 'w') as json_file:
        json.dump(config_out, json_file, indent=4)

    click.echo(f"Data written to {output_file_name}")


if __name__ == "__main__":
    create_config()
