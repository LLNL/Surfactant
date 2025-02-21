import pytest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from surfactant.sbomtypes import SBOM, Software
from surfactantplugin_angrimportfinder import angrimport_finder


@pytest.fixture
def mock_sbom():
    """Fixture to create a mock SBOM object."""
    print("make mock_sbom")
    return MagicMock(spec=SBOM)


@pytest.fixture
def mock_software():
    """Fixture to create a mock Software object with a sha256 hash."""
    software = MagicMock(spec=Software)
    software.sha256 = "mocked_sha256_hash"
    print("make mock_software")
    return software


@pytest.fixture
def mock_elf_file(tmp_path):
    """Fixture to create a temporary ELF file for testing."""
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)  # Mock ELF header
    print("make mock_elf_file")
    return elf_file


@pytest.fixture
def mock_pe_file(tmp_path):
    """Fixture to create a temporary PE file for testing."""
    pe_file = tmp_path / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)  # Mock PE header
    print("make mock_pe_file")
    return pe_file


@patch("angr.Project")
def test_angrimport_finder_elf(mock_angr_project, mock_sbom, mock_software, mock_elf_file, tmp_path):
    """Test the angrimport_finder function with an ELF file."""
    # Mock the angr project and its symbols
    mock_angr_project.return_value.loader.main_object.symbols = [
        MagicMock(name="func1", is_function=True),
        MagicMock(name="func2", is_function=True),
    ]

    # Call the plugin function
    print("call angrimport_finder")
    angrimport_finder(mock_sbom, mock_software, str(mock_elf_file), "ELF")

    # Verify the output JSON file
    output_file = tmp_path / f"{mock_software.sha256}_additional_metadata.json"
    assert output_file.exists()

    with open(output_file, "r") as f:
        data = json.load(f)

    assert data["sha256hash"] == mock_software.sha256
    assert data["filename"] == [mock_elf_file.name]
    assert data["imported function names"] == ["func1", "func2"]


@patch("angr.Project")
def test_angrimport_finder_pe(mock_angr_project, mock_sbom, mock_software, mock_pe_file, tmp_path):
    """Test the angrimport_finder function with a PE file."""
    # Mock the angr project and its symbols
    mock_angr_project.return_value.loader.main_object.symbols = [
        MagicMock(name="imported_func1", is_function=True),
        MagicMock(name="imported_func2", is_function=True),
    ]

    # Call the plugin function
    print("call angrimport_finder")
    angrimport_finder(mock_sbom, mock_software, str(mock_pe_file), "PE")

    # Verify the output JSON file
    output_file = tmp_path / f"{mock_software.sha256}_additional_metadata.json"
    assert output_file.exists()

    with open(output_file, "r") as f:
        data = json.load(f)

    assert data["sha256hash"] == mock_software.sha256
    assert data["filename"] == [mock_pe_file.name]
    assert data["imported function names"] == ["imported_func1", "imported_func2"]


def test_angrimport_finder_non_executable(mock_sbom, mock_software, tmp_path):
    """Test the angrimport_finder function with a non-executable file."""
    # Create a non-executable file
    non_exec_file = tmp_path / "test.txt"
    non_exec_file.write_text("This is a text file.")

    # Call the plugin function
    print("call angrimport_finder")
    angrimport_finder(mock_sbom, mock_software, str(non_exec_file), "TXT")

    # Verify no JSON file is created
    output_file = tmp_path / f"{mock_software.sha256}_additional_metadata.json"
    assert not output_file.exists()


@patch("angr.Project")
def test_angrimport_finder_duplicate_file(mock_angr_project, mock_sbom, mock_software, mock_elf_file, tmp_path):
    """Test the angrimport_finder function with a duplicate file."""
    # Create an existing JSON file for the same hash
    existing_data = {
        "sha256hash": mock_software.sha256,
        "filename": [mock_elf_file.name],
        "imported function names": ["existing_func"],
    }
    existing_file = tmp_path / f"{mock_software.sha256}_additional_metadata.json"
    with open(existing_file, "w") as f:
        json.dump(existing_data, f)

    # Mock the angr project and its symbols
    mock_angr_project.return_value.loader.main_object.symbols = [
        MagicMock(name="new_func", is_function=True),
    ]

    # Call the plugin function
    print("call angrimport_finder")
    angrimport_finder(mock_sbom, mock_software, str(mock_elf_file), "ELF")

    # Verify the existing JSON file is updated
    with open(existing_file, "r") as f:
        data = json.load(f)

    assert data["sha256hash"] == mock_software.sha256
    assert data["filename"] == [mock_elf_file.name]
    assert "existing_func" in data["imported function names"]
    assert "new_func" in data["imported function names"]