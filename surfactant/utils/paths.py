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
    # Defensive check: support single call like normalize_path("C:\\App") or multiple parts
    if len(path_parts) == 1 and isinstance(path_parts[0], (str, pathlib.PurePosixPath)):
        return pathlib.PurePosixPath(str(path_parts[0])).as_posix()

    # Join and normalize all parts
    return pathlib.PurePosixPath(*[str(p) for p in path_parts]).as_posix()
