import pathlib
from typing import Union


def normalize_path(*path_parts: Union[str, pathlib.PurePosixPath]) -> str:
    """
    Normalize one or more path parts into a single POSIX-style path string.

    Args:
        *path_parts: One or more path components, strings or PurePath objects.

    Returns:
        str: POSIX-style normalized path (e.g., 'C:/Program Files/App')
    """
    # Replace backslashes in each part before joining
    cleaned_parts = [str(p).replace("\\", "/") for p in path_parts]
    return pathlib.PurePosixPath(*cleaned_parts).as_posix()


def basename_posix(path: Union[str, pathlib.PurePath]) -> str:
    """
    Return the POSIX-style basename of a path. Never raises for string inputs.
    - Uses normalize_path for consistent slash handling.
    - Strips trailing slash for non-root paths so 'dir/' -> 'dir'.
    """
    s = normalize_path(path)          # ensures a POSIX string
    if s and s != "/":
        s = s.rstrip("/")             # keep '/' as-is; makes 'dir/' -> 'dir'
    # For strings, PurePosixPath(...).name returns:
    #   '' for '' / '.' / '/' ; 'dir' for 'dir' or 'dir/'
    return pathlib.PurePosixPath(s).name
