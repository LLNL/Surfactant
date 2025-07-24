import pytest
from surfactant.utils.paths import normalize_path
from pathlib import PurePosixPath

def test_single_string_path():
    assert normalize_path("C:\\Program Files\\App") == "C:/Program Files/App"

def test_multiple_parts():
    assert normalize_path("C:", "Program Files", "App") == "C:/Program Files/App"

def test_with_purepath():
    assert normalize_path(PurePosixPath("C:/Program Files"), "App") == "C:/Program Files/App"

def test_trailing_slash_is_preserved():
    assert normalize_path("C:/App/") == "C:/App"  # PosixPath strips trailing slashes

def test_empty_parts():
    assert normalize_path("") == "."
