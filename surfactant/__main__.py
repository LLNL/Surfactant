# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats

import argparse
import importlib.metadata
import sys

from surfactant.cmd import generate
from surfactant.plugin.manager import get_plugin_manager


def main():
    pm = get_plugin_manager()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "config_file",
        metavar="CONFIG_FILE",
        nargs="?",
        type=argparse.FileType("r"),
        help="Config file (JSON); make sure keys with paths do not have a trailing /",
    )
    parser.add_argument(
        "sbom_outfile",
        metavar="SBOM_OUTPUT",
        nargs="?",
        type=argparse.FileType("w"),
        help="Output SBOM file",
    )
    parser.add_argument(
        "-i",
        "--input_sbom",
        type=argparse.FileType("r"),
        help="Input SBOM to use as a base for subsequent operations",
    )
    parser.add_argument(
        "--skip_gather",
        action="store_true",
        help="Skip gathering information on files and adding software entries",
    )
    parser.add_argument(
        "--skip_relationships",
        action="store_true",
        help="Skip adding relationships based on Linux/Windows/etc metadata",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--recordedinstitution", help="name of user institution", default="LLNL")
    args = parser.parse_args()

    if args.version:
        print(importlib.metadata.version("surfactant"))
        sys.exit(0)

    if not args.config_file or not args.sbom_outfile:
        parser.print_help()
        sys.exit(1)

    generate.sbom(args, pm)


if __name__ == "__main__":
    main()
