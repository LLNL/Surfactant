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
    """
    Validates symlink resolution and exclusion behavior under the new policy.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        create_symlinks(temp_dir)
        base_path = os.path.realpath(os.path.join(temp_dir, "test_dir"))

        # Symlinks pointing outside extraction directory should be excluded
        assert resolve_link(os.path.join(base_path, "parent"), base_path, base_path) is None
        assert resolve_link(os.path.join(base_path, "link_to_parent"), base_path, base_path) is None

        # Nonexistent targets should return None
        assert resolve_link(os.path.join(base_path, "does_not_exist"), base_path, base_path) is None

        # subdir/parent resolves to base_path, which is within extract_dir → included
        assert (
            resolve_link(
                os.path.join(base_path, "subdir", "parent"),
                os.path.join(base_path, "subdir"),
                base_path,
            )
            == base_path
        )

        # link_to_non_existant → broken chain → excluded
        assert resolve_link(os.path.join(base_path, "link_to_non_existant"), base_path, base_path) is None


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX OS")
def test_resolve_link_scope(tmp_path):
    """
    Validates:
      - Inclusion of internal symlinks
      - Exclusion of external /bin/* symlinks
      - Reciprocal linking (dirE ↔ dirF)
    """
    extract_dir = tmp_path / "usr" / "bin"
    extract_dir.mkdir(parents=True)

    dirs = {name: extract_dir / name for name in ["dirA", "dirB", "dirC", "dirD", "dirE", "dirF"]}
    for d in dirs.values():
        d.mkdir()

    os.symlink("../dirB", dirs["dirA"] / "link_to_B")
    os.symlink("../dirA", dirs["dirB"] / "link_to_A")
    os.symlink("../dirD", dirs["dirC"] / "link_to_D")
    os.symlink("../dirC", dirs["dirD"] / "link_to_C")
    os.symlink("../dirF", dirs["dirE"] / "link_to_F")
    os.symlink("../dirE", dirs["dirF"] / "link_to_E")

    # Internal mock executables
    ls_path = extract_dir / "ls"
    echo_path = extract_dir / "echo"
    ls_path.write_text("fake ls binary")
    echo_path.write_text("fake echo binary")

    # External /bin symlinks (excluded)
    os.symlink("/bin/ls", dirs["dirA"] / "runme")
    os.symlink("/bin/ls", dirs["dirC"] / "runme")
    os.symlink("/bin/echo", dirs["dirD"] / "runyou")

    # Internal relative symlinks (stay inside extract_dir)
    os.symlink("../ls", dirs["dirE"] / "runthis")
    os.symlink("../echo", dirs["dirF"] / "runthat")

    results = {
        "dirA": resolve_link(dirs["dirA"] / "runme", dirs["dirA"], extract_dir),
        "dirC": resolve_link(dirs["dirC"] / "runme", dirs["dirC"], extract_dir),
        "dirD": resolve_link(dirs["dirD"] / "runyou", dirs["dirD"], extract_dir),
        "dirE": resolve_link(dirs["dirE"] / "runthis", dirs["dirE"], extract_dir),
        "dirF": resolve_link(dirs["dirF"] / "runthat", dirs["dirF"], extract_dir),
    }

    # External symlinks excluded
    assert results["dirA"] is None
    assert results["dirC"] is None
    assert results["dirD"] is None

    # Internal ones included
    assert results["dirE"] == str(ls_path.resolve(strict=False))
    assert results["dirF"] == str(echo_path.resolve(strict=False))


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX OS")
def test_resolve_link_cycle_detection(tmp_path):
    """
    Ensures resolve_link() detects cyclic symlinks and returns None.
    """

    extract_dir = tmp_path / "usr" / "bin"
    extract_dir.mkdir(parents=True)

    # Create two symlinks that point to each other (true cycle)
    a = extract_dir / "a"
    b = extract_dir / "b"
    os.symlink("b", a)
    os.symlink("a", b)

    result_a = resolve_link(a, extract_dir, extract_dir)
    result_b = resolve_link(b, extract_dir, extract_dir)

    assert result_a is None, "Cyclic symlink a↔b should be detected"
    assert result_b is None, "Cyclic symlink b↔a should be detected"



if __name__ == "__main__":
    test_symlinks()
