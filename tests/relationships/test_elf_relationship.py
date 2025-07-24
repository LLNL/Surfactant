# pylint: disable=redefined-outer-name
import pathlib

import pytest

from surfactant.relationships import elf_relationship
from surfactant.relationships.elf_relationship import establish_relationships
from surfactant.sbomtypes import SBOM, Relationship, Software


@pytest.fixture
def example_sbom():
    sbom = SBOM()

    sw1 = Software(UUID="uuid-1", fileName=["libfoo.so.1"], installPath=["/usr/lib/libfoo.so.1"])
    sw2 = Software(UUID="uuid-2", fileName=["libbar.so"], installPath=["/opt/myapp/lib/libbar.so"])

    sw3a = Software(
        UUID="uuid-3a",
        installPath=["/opt/myapp/bin/myapp"],
        metadata=[{"elfDependencies": ["/usr/lib/libfoo.so.1"]}],
    )
    sw3b = Software(
        UUID="uuid-3b",
        installPath=["/opt/myapp/bin/myapp"],
        metadata=[{"elfDependencies": ["libbar.so"], "elfRunpath": ["$ORIGIN/../lib"]}],
    )
    sw4 = Software(
        UUID="uuid-4",
        fileName=["libxyz.so"],
        installPath=["/lib/libxyz.so"],
        metadata=[{"elfDependencies": ["libxyz.so"]}],
    )
    sw5 = Software(UUID="uuid-5", fileName=["libdep.so"], installPath=["/app/lib/libdep.so"])
    sw6 = Software(
        UUID="uuid-6",
        installPath=["/app/bin/mybin"],
        metadata=[{"elfDependencies": ["libdep.so"], "elfRunpath": ["$ORIGIN/../lib"]}],
    )
    sw7 = Software(
        UUID="uuid-7",
        installPath=["/legacy/bin/legacyapp"],
        metadata=[{"elfDependencies": ["libbar.so"], "elfRpath": ["/opt/myapp/lib"]}],
    )
    sw8 = Software(UUID="uuid-8", fileName=["libalias.so"], installPath=["/opt/alt/lib/libreal.so"])
    sw9 = Software(
        UUID="uuid-9",
        installPath=["/opt/alt/bin/app"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/alt/lib"]}],
    )

    # add symlink mapping for sw8
    sbom._record_symlink("/opt/alt/lib/libalias.so", "/opt/alt/lib/libreal.so", subtype="file")  # pylint: disable=protected-access

    for sw in [sw1, sw2, sw3a, sw3b, sw4, sw5, sw6, sw7, sw8, sw9]:
        sbom.add_software(sw)

    return sbom, {
        "absolute": (sw3a, "uuid-1"),
        "relative": (sw3b, "uuid-2"),
        "system": (sw4, "uuid-4"),
        "origin": (sw6, "uuid-5"),
        "rpath": (sw7, "uuid-2"),
        "symlink": (sw9, "uuid-8"),
    }


@pytest.mark.parametrize("label", ["absolute", "relative", "system", "origin", "rpath", "symlink"])
def test_elf_relationship_cases(example_sbom, label):
    print(f"==== RUNNING: {label} ====")
    sbom, case_map = example_sbom
    sw, expected_uuid = case_map[label]
    metadata = sw.metadata[0] if sw.metadata else {}
    print("Dependency paths:", metadata.get("elfDependencies", []))
    print("fs_tree nodes:", list(sbom.fs_tree.nodes))
    for dep in metadata.get("elfDependencies", []):
        norm = pathlib.PurePosixPath(dep).as_posix()
        print(f"Trying lookup: {norm} ->", sbom.get_software_by_path(norm))
    result = elf_relationship.establish_relationships(sbom, sw, metadata)
    assert result is not None, f"{label} case failed: no result"
    assert len(result) == 1, f"{label} case failed: expected 1 relationship"
    assert result[0] == Relationship(sw.UUID, expected_uuid, "Uses"), (
        f"{label} case mismatch: {result[0]} != {expected_uuid}"
    )


@pytest.fixture
def symlink_heuristic_sbom():
    """
    Constructs a test SBOM scenario where the only valid match is via the symlink heuristic.

    - The binary depends on 'libalias.so'
    - The SBOM does not include a direct path or fs_tree match for 'libalias.so'
    - The candidate dependency's fileName matches 'libalias.so'
    - The candidate dependency's installPath parent directory matches search path
    """
    # Binary depending on 'libalias.so' with a runpath that includes /opt/app/lib
    binary = Software(
        UUID="bin-uuid",
        fileName=["myapp"],
        installPath=["/opt/app/bin/myapp"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/app/lib"]}],
    )

    # Candidate dependency: install path and fileName line up for heuristic
    dependency = Software(
        UUID="lib-uuid", fileName=["libalias.so"], installPath=["/opt/app/lib/libalias.so"]
    )

    sbom = SBOM()
    sbom.add_software(binary)
    sbom.add_software(dependency)

    return sbom, binary


def test_symlink_heuristic_match(symlink_heuristic_sbom):
    sbom, binary = symlink_heuristic_sbom
    metadata = binary.metadata[0]

    results = establish_relationships(sbom, binary, metadata)

    assert results is not None, "Expected relationship from symlink heuristic"
    assert len(results) == 1
    assert results[0] == Relationship("bin-uuid", "lib-uuid", "Uses")


@pytest.mark.parametrize("label", ["symlink"])
def test_symlink_heuristic_match_edge(example_sbom, label):
    sbom, case_map = example_sbom
    sw, expected_uuid = case_map[label]
    metadata = sw.metadata[0]

    # Clear fs_tree matches to force heuristic
    sbom.fs_tree.remove_edge("/opt/alt/lib/libalias.so", "/opt/alt/lib/libalias.so")
    sbom.fs_tree.remove_node("/opt/alt/lib/libalias.so")

    result = elf_relationship.establish_relationships(sbom, sw, metadata)
    assert result is not None
    assert result == [Relationship(sw.UUID, expected_uuid, "Uses")], (
        "Expected heuristic symlink match"
    )


def test_no_match_edge_case():
    """
    Test case: No matching dependency by any means (fs_tree, legacy, or heuristic).
    Expect no relationships.
    """
    binary = Software(
        UUID="bin-uuid",
        fileName=["mybin"],
        installPath=["/some/bin/mybin"],
        metadata=[{"elfDependencies": ["libnotfound.so"], "elfRunpath": ["/some/lib"]}],
    )

    unrelated = Software(
        UUID="unrelated-uuid",
        fileName=["libsomethingelse.so"],
        installPath=["/unrelated/path/libsomethingelse.so"],
    )

    sbom = SBOM(systems=[], hardware=[], software=[binary, unrelated])
    sbom.fs_tree.add_node("/unrelated/path/libsomethingelse.so", software=unrelated)

    metadata = binary.metadata[0]
    results = establish_relationships(sbom, binary, metadata)

    assert results is not None
    assert len(results) == 0, "Expected no relationships for unmatched dependency"


def test_symlink_heuristic_guard():
    """
    Tests that the symlink heuristic does not falsely match entries where
    fileName matches but installPath is in a different directory.
    """
    binary = Software(
        UUID="bin-uuid",
        fileName=["myapp"],
        installPath=["/opt/app/bin/myapp"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/app/lib"]}],
    )

    # Same file name, but located in a different directory -> should NOT match
    candidate = Software(
        UUID="falsematch-uuid", fileName=["libalias.so"], installPath=["/different/dir/libalias.so"]
    )

    sbom = SBOM(systems=[], hardware=[], software=[binary, candidate])
    sbom.fs_tree.add_node("/different/dir/libalias.so", software=candidate)

    metadata = binary.metadata[0]
    results = establish_relationships(sbom, binary, metadata)

    assert results is not None
    assert all(rel.yUUID != "falsematch-uuid" for rel in results), (
        "Heuristic should not have matched"
    )
