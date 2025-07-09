#!/usr/bin/env python3
"""
Oneshot utility to generate SBOM from a single input folder and return as string.
"""

import argparse
import datetime
import difflib
import io
import random
import json
import sys
import time
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import click
from loguru import logger

from surfactant.cmd.generate import sbom


def deterministic_uuid4():
    return str(uuid.UUID(bytes=random.randbytes(16), version=4))


def deterministic_time():
    return 1609459200  # Friday, January 1, 2021 12:00:00 AM UTC


class FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls.fromtimestamp(time.time(), tz)

    @classmethod
    def utcnow(cls):
        return cls.fromtimestamp(time.time(), datetime.timezone.utc)


@contextmanager
def deterministic_context(enabled: bool = True):
    """Context manager to optionally patch time-related and random functions for deterministic output.

    Args:
        enabled (bool): If True, applies patches for deterministic behavior. If False, no patches are applied.
    """
    if enabled:
        with (
            patch("uuid.uuid4", side_effect=deterministic_uuid4),
            patch("datetime.datetime", FixedDateTime),
            patch("time.time", side_effect=deterministic_time),
        ):
            # Set the random seed for deterministic random number generation
            random.seed(0xDEADBEEF)
            yield
    else:
        # No patches applied, just yield normally
        yield


def generate_sbom_string(
    input_folder: str,
    install_prefix: Optional[str] = None,
    deterministic: bool = False,
) -> str:
    """
    Generate an SBOM from a single input folder and return it as a string.

    Args:
        input_folder (str): Path to the folder to analyze
        install_prefix (Optional[str]): Install prefix for the software. If None, uses the folder path.
        deterministic (bool): Use deterministic UUIDs and timestamps for reproducible output

    Returns:
        str: The generated SBOM as a string

    Raises:
        FileNotFoundError: If the input folder doesn't exist
        ValueError: If the input folder is not a directory
    """
    # Validate input folder
    folder_path = Path(input_folder)
    if not folder_path.exists():
        raise FileNotFoundError(f"Input folder does not exist: {input_folder}")
    if not folder_path.is_dir():
        raise ValueError(f"Input path is not a directory: {input_folder}")

    # Set install prefix if not provided
    if install_prefix is None:
        install_prefix = folder_path.as_posix() + "/"

    # Create specimen config for the single folder
    specimen_config = [{"extractPaths": [folder_path.as_posix()], "installPrefix": install_prefix}]

    # Create an in-memory file-like object to capture output
    output_buffer = io.StringIO()

    # Create a click context
    with click.Context(sbom) as ctx:
        with deterministic_context(enabled=deterministic):
            try:
                # Use Click's invoke to call the command with the context
                ctx.invoke(
                    sbom,
                    specimen_config=specimen_config,
                    sbom_outfile=output_buffer,
                )
            except Exception as e:
                raise RuntimeError(f"Failed to invoke SBOM generation: {e}") from e

    # Get the output as a string
    return output_buffer.getvalue()

data_path = Path(__file__).parent.parent / "tests" / "data"
data_folders = []
if not data_path.exists():
    logger.error(f"Test data directory does not exist: {data_path}")
else:
    data_folders = [item for item in data_path.iterdir() if item.is_dir()]

def test_all_data_folders():
    """
    Test the generate_sbom_string function with all folders in tests/data.
    """
    if not data_folders:
        logger.warning("No test data folders found")
        return

    logger.info(f"Testing SBOM generation for {len(data_folders)} folders")

    for folder in data_folders:
        logger.info(f"Testing folder: {folder.name}")

        try:
            # Test regular mode
            sbom_string = generate_sbom_string(
                input_folder=str(folder),
                deterministic=False,
            )

            # Test deterministic mode
            sbom_string_det1 = generate_sbom_string(
                input_folder=str(folder),
                deterministic=True,
            )

            # Test deterministic mode
            sbom_string_det2 = generate_sbom_string(
                input_folder=str(folder),
                deterministic=True,
            )

            # Print first few lines of the SBOM to verify it was generated
            if sbom_string and sbom_string_det1 and sbom_string_det2:
                logger.success("SBOM generated successfully")

                # Verify deterministic output is different from regular output
                if sbom_string in (sbom_string_det1, sbom_string_det2):
                    logger.warning("Deterministic and regular output are identical (unexpected)")
                else:
                    logger.success("Deterministic mode produces different output as expected")

                # Check if deterministic outputs are identical
                if sbom_string_det1 == sbom_string_det2:
                    logger.success("Deterministic outputs are identical as expected")
                else:
                    logger.warning("Deterministic outputs are different (unexpected)")
                    # Show differences between the two deterministic runs
                    for line in show_diff(sbom_string_det1, sbom_string_det2).splitlines():
                        logger.info(line)
            else:
                logger.warning("SBOM generated but appears to be empty")

        except (FileNotFoundError, ValueError, RuntimeError) as e:
            logger.error(f"Error generating SBOM for {folder.name}: {e}")

def test_gha(old_folders: dict[str, str], repo_prefix: Optional[str]) -> tuple[str, dict[str, str]]:
    """
    Test function for CI/CD mode.
    
    Args:
        old_folders (dict[str, str]): Dictionary of old folder names and their SBOM strings.
        repo_prefix (Optional[str]): Optional prefix for the repository URL to link to the folders.
    
    Returns:
        str: A github step summary message.
    """
    folders = [folder.name for folder in data_folders]
    created_folders = [folder for folder in folders if folder not in old_folders]
    removed_folders = [folder for folder in old_folders if folder not in folders]
    
    summary = ""
        
    if created_folders:
        logger.info(f"New folders detected: {', '.join(created_folders)}")
        summary += f"## 🆕 New Folders ({len(created_folders)}\n"
        for folder in created_folders:
            summary += f"- {folder}\n"
        summary += "\n"
    if removed_folders:
        logger.info(f"Removed folders: {', '.join(removed_folders)}")
        summary += f"## 🗑️ Removed Folders ({len(removed_folders)})\n"
        for folder in removed_folders:
            summary += f"- {folder}\n"
        summary += "\n"

    logger.info(f"Testing SBOM generation for {len(data_folders)} folders")
    
    if not data_folders:
        summary += "## ❓ No Test Folders Found\n"
    
    new_folders = {}
    diffs = {}
    for folder in data_folders:
        old_string = old_folders.get(folder.name, "")
        new_string = generate_sbom_string(
            input_folder=str(folder),
            deterministic=True,
        )
        new_folders[folder.name] = new_string
        if old_string != new_string:
            logger.info(f"Changes detected in folder: {folder.name}")
            for line in show_diff(old_string, new_string).splitlines():
                logger.info(line)
            diffs[folder.name] = show_diff(old_string, new_string, 100)
            
    if not diffs:
        summary += "## ✅ No SBOM Changes Detected\n"
    else:
        summary += f"## 🧪 SBOM Results ({len(diffs)}/{len(data_folders)})\n\n"
        for folder_name, diff in diffs.items():
            summary += "<details>\n"
            summary += "<summary><h3>"
            if repo_prefix is not None:
                href = f"{repo_prefix}/tests/data/{folder_name}"
                summary += f"<a href=\"{href}\">{folder_name}</a>"
            else:
                summary += folder_name
            summary += "</h3></summary>\n\n"
            summary += f"```diff\n{diff}\n```\n"
            summary += "</details>\n"
    
    return summary.rstrip(), new_folders
    

def show_diff(text1: str, text2: str, max_lines: int = 20) -> str:
    """
    Show differences between two texts.

    Args:
        text1 (str): First text to compare
        text2 (str): Second text to compare
        max_lines (int): Maximum number of diff lines to show
        
    Returns:
        str: Formatted string showing the differences
    """
    lines1 = text1.splitlines(keepends=True)
    lines2 = text2.splitlines(keepends=True)

    diff = list(difflib.unified_diff(lines1, lines2, lineterm=""))

    # Show first max_lines lines of diff
    lines = [line.rstrip() for line in diff[:max_lines]]

    if len(diff) > max_lines:
        lines.append(f"... and {len(diff) - max_lines} more lines")
        
    return "\n".join(lines)

def write_to_output(key: str, value: str):
    """
    Write a key-value pair to the GITHUB_OUTPUT file if it exists.
    If GITHUB_OUTPUT is not set, it prints the key-value pair to stdout.
    
    Args:
        key (str): The key to write
        value (str): The value to write
    """
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            delimeter = str(uuid.uuid4())
            f.write(f"{key}<<{delimeter}\n{value}\n{delimeter}\n")
    else:
        print(f"{key}={value}")


def main():
    """
    Example usage of the generate_sbom_string function.
    """
    parser = argparse.ArgumentParser(description="Generate SBOM from a single folder")
    parser.add_argument("folder", nargs="?", help="Path to the folder to analyze")
    parser.add_argument("--install-prefix", help="Install prefix for the software")
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use deterministic UUIDs and timestamps for reproducible output",
    )
    parser.add_argument(
        "--test-all", action="store_true", help="Test with all folders in tests/data"
    )
    parser.add_argument("--gha", action="store_true", help="CI/CD mode")

    args = parser.parse_args()
    
    if args.gha:
        logger.info("Running in CI/CD mode o/")
        old_folders = {}
        if "DIFF_INPUT" in os.environ:
            with open(os.environ["DIFF_INPUT"], "r") as f:
                old_folders = json.load(f)
        repo_prefix = os.environ.get("REPO_PREFIX", None)
        summary, new_folders = test_gha(old_folders, repo_prefix)
        write_to_output("summary", summary)
        if "DIFF_OUTPUT" in os.environ:
            with open(os.environ["DIFF_OUTPUT"], "w") as f:
                json.dump(new_folders, f, indent=4)
        return

    if args.test_all:
        test_all_data_folders()
        return

    if not args.folder:
        logger.error("folder argument is required unless --test-all is specified")
        parser.print_help()
        sys.exit(1)

    try:
        sbom_string = generate_sbom_string(
            input_folder=args.folder,
            install_prefix=args.install_prefix,
            deterministic=args.deterministic,
        )
        print(sbom_string)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        logger.error(f"Error generating SBOM: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
