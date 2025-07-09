#!/usr/bin/env python3
"""
Oneshot utility to generate SBOM from a single input folder and return as string.
"""

import datetime
import difflib
import io
import random
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import click
from loguru import logger

# Add the parent directory to the path to import surfactant modules
sys.path.insert(0, str(Path(__file__).parent.parent))
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
                raise RuntimeError(f"Failed to invoke SBOM generation: {e}")

    # Get the output as a string
    return output_buffer.getvalue()


def test_all_data_folders():
    """
    Test the generate_sbom_string function with all folders in tests/data.
    """
    # Get the path to the tests/data directory
    test_data_path = Path(__file__).parent.parent / "tests" / "data"

    if not test_data_path.exists():
        logger.error(f"Test data directory does not exist: {test_data_path}")
        return

    # Get all subdirectories in tests/data
    data_folders = [item for item in test_data_path.iterdir() if item.is_dir()]

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
                if sbom_string == sbom_string_det1 or sbom_string == sbom_string_det2:
                    logger.warning("Deterministic and regular output are identical (unexpected)")
                else:
                    logger.success("Deterministic mode produces different output as expected")

                # Check if deterministic outputs are identical
                if sbom_string_det1 == sbom_string_det2:
                    logger.success("Deterministic outputs are identical as expected")
                else:
                    logger.warning("Deterministic outputs are different (unexpected)")
                    # Show differences between the two deterministic runs
                    show_diff(sbom_string_det1, sbom_string_det2)
            else:
                logger.warning("SBOM generated but appears to be empty")

        except Exception as e:
            logger.error(f"Error generating SBOM for {folder.name}: {e}")


def show_diff(text1: str, text2: str, max_lines: int = 20):
    """
    Show differences between two texts.

    Args:
        text1 (str): First text to compare
        text2 (str): Second text to compare
        max_lines (int): Maximum number of diff lines to show
    """
    lines1 = text1.splitlines(keepends=True)
    lines2 = text2.splitlines(keepends=True)

    diff = list(difflib.unified_diff(lines1, lines2, lineterm=""))

    # Show first max_lines lines of diff
    for i, line in enumerate(diff[:max_lines]):
        logger.info(line.rstrip())

    if len(diff) > max_lines:
        logger.info(f"... and {len(diff) - max_lines} more diff lines")


def main():
    """
    Example usage of the generate_sbom_string function.
    """
    import argparse

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

    args = parser.parse_args()

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
    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
