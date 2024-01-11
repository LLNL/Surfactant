# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import stat
from hashlib import md5, sha1, sha256


def get_file_info(filename):
    """Get information about a file.

    Args:
        filename (str): Name of file.

    Returns:
        Optional[dict]: Dictionary that contains info about the file.
    """
    try:
        fstats = os.stat(filename)
    except FileNotFoundError:
        return None

    filehidden = False
    # stat.UF_HIDDEN (file shouldn't be shown in GUI macOS 10.5+)
    if hasattr(fstats, "st_flags"):
        filehidden = bool(fstats.st_flags & stat.UF_HIDDEN)
    # stat.FILE_ATTRIBUTE_HIDDEN (shouldn't be shown on Windows)
    if hasattr(fstats, "st_file_attributes"):
        filehidden = bool(fstats.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    # Should consider if symlinks on Linux/macOS/Windows, or reparse points on Windows need to be recognized and handled
    # lstat() does not follow symbolic links
    # fstats.st_reparse_tag from os.lstat()
    # stat.IO_REPARSE_TAG_SYMLINK
    # stat.IO_REPARSE_TAG_MOUNT_POINT
    return {
        "size": fstats.st_size,
        "accesstime": fstats.st_atime,
        "modifytime": fstats.st_mtime,
        "createtime": fstats.st_ctime,
        "filemode": stat.filemode(fstats.st_mode),
        "filehidden": filehidden,
    }


def calc_file_hashes(filename):
    """Calculate hashes for a file specified.

    Args:
        filename (str): Name of file.

    Returns:
        Optional[dict]: Dictionary with the sha256, sha1, and md5 hashes of the file.
    """
    sha256_hash = sha256()
    sha1_hash = sha1()
    md5_hash = md5()
    b = bytearray(4096)
    mv = memoryview(b)
    try:
        with open(filename, "rb", buffering=0) as f:
            while n := f.readinto(mv):
                sha256_hash.update(mv[:n])
                sha1_hash.update(mv[:n])
                md5_hash.update(mv[:n])
    except FileNotFoundError:
        return None
    return {
        "sha256": sha256_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
    }
