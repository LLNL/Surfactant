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
