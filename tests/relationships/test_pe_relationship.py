# pylint: disable=redefined-outer-name
import pytest
import pathlib

from surfactant.relationships import pe_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


@pytest.fixture
def basic_pe_sbom():
    """
    Create a minimal SBOM with:
      - One binary (UUID: uuid-bin) located in C:/bin
      - One DLL (UUID: uuid-dll) located in C:/libs
      - The binary declares a direct PE import of 'foo.dll'

    Returns:
        Tuple[SBOM, Software, Software]: the SBOM, the binary, and the DLL
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["foo.dll"],
        installPath=["C:/libs/foo.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
        installPath=["C:/bin/app.exe"],
        metadata=[{"peImport": ["foo.dll"]}],
    )

    # Add both software components to the SBOM
    sbom.add_software(dll)
    sbom.add_software(binary)

    return sbom, binary, dll


def test_pe_import_via_fs_tree(basic_pe_sbom):
    """
    Test that a PE import is resolved correctly via fs_tree-based path matching.
    """
    sbom, binary, dll = basic_pe_sbom

    # Simulate fs_tree having indexed the DLL path
    path = "C:/libs/foo.dll"
    sbom.fs_tree.add_node(path, software_uuid=dll.UUID)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results is not None
    assert len(results) == 1
    assert results[0] == Relationship(binary.UUID, dll.UUID, "Uses")


def test_pe_import_legacy_fallback():
    """
    Test that PE relationship fallback works when fs_tree does not contain the path.
    It should fall back to installPath + fileName matching.
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["bar.dll"],
        installPath=["D:/tools/bar.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
        installPath=["D:/tools/app.exe"],
        metadata=[{"peBoundImport": ["bar.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results is not None
    assert results == [Relationship("uuid-bin", "uuid-dll", "Uses")]


def test_pe_symlink_heuristic():
    """
    Test the heuristic fallback:
    Match a DLL if its fileName matches and its installPath is in the same folder
    as one of the probed directories derived from the binary's installPath.
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["common.dll"],
        installPath=["E:/bin/common.dll"],  # <== change this
    )

    binary = Software(
        UUID="uuid-bin",
        fileName=["app"],
        installPath=["E:/bin/app.exe"],
        metadata=[{"peDelayImport": ["common.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert pathlib.PurePosixPath("E:/bin/common.dll").parent.as_posix() == "E:/bin"
    assert results is not None
    assert results == [Relationship("uuid-bin", "uuid-dll", "Uses")]


def test_pe_no_match():
    """
    Ensure no relationship is emitted if the imported DLL cannot be resolved
    through any mechanism (fs_tree, legacy, or heuristic).
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["missing.dll"],
        installPath=["Z:/opt/ghost.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
        installPath=["Z:/opt/app.exe"],
        metadata=[{"peImport": ["doesnotexist.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results == []


def test_pe_has_required_fields():
    """
    Unit test for has_required_fields(): ensure it returns True only if at least
    one valid PE field is present in the metadata.
    """
    assert pe_relationship.has_required_fields({"peImport": ["foo.dll"]})
    assert pe_relationship.has_required_fields({"peBoundImport": ["bar.dll"]})
    assert pe_relationship.has_required_fields({"peDelayImport": ["baz.dll"]})
    assert not pe_relationship.has_required_fields({"unrelated": []})
