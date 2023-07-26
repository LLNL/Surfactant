# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib
import tempfile

import pytest

from surfactant.cmd.generate import resolve_link

base_dir = pathlib.Path(__file__).parent.absolute()


def symlink(src, dst, target_is_directory):
    try:
        os.symlink(src, dst, target_is_directory)
    except FileExistsError:
        pass


def create_symlinks(temp_dir):
    # Make sure this is always the working directory
    os.chdir(base_dir)
    os.makedirs(os.path.join(temp_dir, "test_dir", "subdir"), exist_ok=True)
    os.chdir(os.path.join(temp_dir, "test_dir"))
    symlink("..", "parent", True)
    symlink("parent", "link_to_parent", True)
    symlink("/none/", "does_not_exist", True)
    symlink("does_not_exist", "link_to_non_existant", False)
    symlink("..", "subdir/parent", True)
    # Revert back to the original working directory
    os.chdir(base_dir)


@pytest.mark.skipif(os.name != "posix", reason="requires posix os")
def test_symlinks():
    with tempfile.TemporaryDirectory() as temp_dir:
        create_symlinks(temp_dir)
        base_path = os.path.realpath(os.path.join(temp_dir, "test_dir"))
        assert resolve_link(os.path.join(base_path, "parent"), base_path, base_path) == base_path
        assert (
            resolve_link(os.path.join(base_path, "link_to_parent"), base_path, base_path)
            == base_path
        )
        assert resolve_link(os.path.join(base_path, "does_not_exist"), base_path, base_path) is None
        assert (
            resolve_link(
                os.path.join(base_path, "subdir", "parent"),
                os.path.join(base_path, "subdir"),
                base_path,
            )
            == base_path
        )
        assert (
            resolve_link(os.path.join(base_path, "link_to_non_existant"), base_path, base_path)
            is None
        )


if __name__ == "__main__":
    test_symlinks()
