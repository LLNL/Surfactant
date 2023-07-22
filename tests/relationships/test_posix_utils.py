# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pathlib

from surfactant.relationships._internal.posix_utils import posix_normpath


def test_posix_normpath():
    assert posix_normpath("") == pathlib.PurePosixPath(".")
    assert posix_normpath("..") == pathlib.PurePosixPath(".")
    assert posix_normpath("../") == pathlib.PurePosixPath(".")
    assert posix_normpath("../..") == pathlib.PurePosixPath(".")

    assert posix_normpath("ab/../xy") == pathlib.PurePosixPath("xy")
    assert posix_normpath("/a/b//..///c") == pathlib.PurePosixPath("/a/c")

    assert posix_normpath("//..") == pathlib.PurePosixPath("//")
    assert posix_normpath("//../") == pathlib.PurePosixPath("//")
    assert posix_normpath("//../a") == pathlib.PurePosixPath("//a")
    assert posix_normpath("//./") == pathlib.PurePosixPath("//")
    assert posix_normpath("//./a") == pathlib.PurePosixPath("//a")
    assert posix_normpath("//./a/../b") == pathlib.PurePosixPath("//b")

    assert posix_normpath("///") == pathlib.PurePosixPath("/")
    assert posix_normpath("///a") == pathlib.PurePosixPath("/a")
    assert posix_normpath("///a/../b") == pathlib.PurePosixPath("/b")
    assert posix_normpath("///a/../") == pathlib.PurePosixPath("/")

    assert posix_normpath("////a/../b") == pathlib.PurePosixPath("/b")
