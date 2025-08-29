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
    sw4_consumer = Software(
        UUID="uuid-4-consumer",
        installPath=["/bin/testbin"],
        metadata=[{"elfDependencies": ["libxyz.so"]}],
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
    sbom.record_symlink("/opt/alt/lib/libalias.so", "/opt/alt/lib/libreal.so", subtype="file")

    for sw in [sw1, sw2, sw3a, sw3b, sw4, sw4_consumer, sw5, sw6, sw7, sw8, sw9]:
        sbom.add_software(sw)

    return sbom, {
        "absolute": (sw3a, "uuid-1"),
        "relative": (sw3b, "uuid-2"),
        "system": (sw4_consumer, "uuid-4"),
        "origin": (sw6, "uuid-5"),
        "rpath": (sw7, "uuid-2"),
        "symlink": (sw9, "uuid-8"),
    }


@pytest.mark.parametrize("label", ["absolute", "relative", "system", "origin", "rpath", "symlink"])
def test_elf_relationship_cases(example_sbom, label):
    """
    Validate ELF relationship resolution across multiple scenarios.

    This test is parameterized to exercise the six primary resolution paths used by
    the ELF plugin. For each `label`, the `example_sbom` fixture returns:
      - `sw`:   the consumer `Software` object under test
      - `expected_uuid`: the UUID of the supplier `Software` that should be linked via a
                         `Relationship(sw.UUID, expected_uuid, "Uses")`

    The cases covered:
      - "absolute": dependency is an absolute path (e.g., /usr/lib/libfoo.so.1)
      - "relative": dependency name + runpath derived from $ORIGIN, e.g. "$ORIGIN/../lib"
      - "system":   dependency resolved via standard system library directories (e.g., /lib)
      - "origin":   dependency resolved via $ORIGIN expansion relative to the binary
      - "rpath":    dependency resolved via legacy RPATH entries
      - "symlink":  dependency resolved through a symlink edge in the SBOM fs_tree

    Expectations:
      - Exactly one "Uses" relationship is emitted.
      - The dependency resolves to `expected_uuid`, and never to the consumer itself.
    """
    # Debug prints are helpful during bring-up, but can be noisy in CI.
    # Keep them for now; if logs are cluttered, consider replacing with logger.debug or removing.
    print(f"==== RUNNING: {label} ====")
    sbom, case_map = example_sbom

    # Retrieve the consumer under test and the expected supplier UUID
    sw, expected_uuid = case_map[label]

    # Pull the ELF metadata for this software (may include elfDependencies, elfRunpath/Rpath, etc.)
    metadata = sw.metadata[0] if sw.metadata else {}
    print("Dependency paths:", metadata.get("elfDependencies", []))
    print("fs_tree nodes:", list(sbom.fs_tree.nodes))

    # Optional trace: show how raw dependency strings normalize to POSIX and what fs_tree returns
    for dep in metadata.get("elfDependencies", []):
        norm = pathlib.PurePosixPath(dep).as_posix()
        print(f"Trying lookup: {norm} ->", sbom.get_software_by_path(norm))

    # Execute the plugin and assert a single, correct relationship is produced
    result = elf_relationship.establish_relationships(sbom, sw, metadata)

    # Sanity checks: one result, and it matches the expected supplier UUID
    assert result is not None, f"{label} case failed: no result"
    assert len(result) == 1, f"{label} case failed: expected 1 relationship"
    assert result[0] == Relationship(sw.UUID, expected_uuid, "Uses"), (
        f"{label} case mismatch: {result[0]} != {expected_uuid}"
    )


@pytest.fixture
def symlink_heuristic_sbom():
    """
    Construct a minimal SBOM that *forces* the ELF plugin's heuristic phase.

    Mechanics:
      - Consumer depends on 'libalias.so' and has runpath '/opt/app/lib'.
      - Provider's *fileName* includes 'libalias.so' (so the name matches),
        but its *installPath* is '/opt/app/lib/libalias.so.1' (different basename).
      - This guarantees:
          • Phase 1 (fs_tree) fails: no exact '/opt/app/lib/libalias.so' node.
          • Phase 2 (legacy) fails: no installPath exactly equals '/opt/app/lib/libalias.so'.
          • Phase 3 (heuristic) succeeds: filename matches and directory matches.

    Expected behavior:
      The plugin emits Relationship('bin-uuid', 'lib-uuid', 'Uses') via the heuristic path.
    """
    # Consumer binary: depends on 'libalias.so' and searches in /opt/app/lib
    binary = Software(
        UUID="bin-uuid",
        fileName=["myapp"],
        installPath=["/opt/app/bin/myapp"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/app/lib"]}],
    )

    # Provider library: same directory, matching fileName, different on-disk basename.
    provider = Software(
        UUID="lib-uuid",
        fileName=["libalias.so"],                         # matches dependency name
        installPath=["/opt/app/lib/libalias.so.1"],       # NOT the same as '/opt/app/lib/libalias.so'
    )

    sbom = SBOM()
    sbom.add_software(binary)
    sbom.add_software(provider)  # indexes '/opt/app/lib/libalias.so.1' in fs_tree

    return sbom, binary


def test_symlink_heuristic_match(symlink_heuristic_sbom):
    """
    Validate the ELF plugin resolves via the heuristic (same-dir + filename)
    when both fs_tree and legacy exact-path matching cannot succeed.
    """
    sbom, binary = symlink_heuristic_sbom
    metadata = binary.metadata[0]

    # Note: We do *not* remove fs_tree nodes here; the heuristic is enforced
    # by using a different basename in provider.installPath so Phase 2 fails.

    results = elf_relationship.establish_relationships(sbom, binary, metadata)

    assert results is not None, "Expected relationship via heuristic"
    assert len(results) == 1
    assert results[0] == Relationship("bin-uuid", "lib-uuid", "Uses")


@pytest.mark.parametrize("label", ["symlink"])
def test_symlink_heuristic_match_edge(example_sbom, label):
    """
    Force the symlink scenario to resolve via the heuristic phase:

    - Start with the example 'symlink' case (alias -> real path recorded).
    - Delete the alias symlink edge and alias node so Phase 1 (fs_tree symlink traversal)
      cannot succeed.
    - Expect a match via Phase 3 (same-directory + filename), because provider.fileName
      is 'libalias.so' and its parent directory matches the search path.
    """
    sbom, case_map = example_sbom
    sw, expected_uuid = case_map[label]
    metadata = sw.metadata[0]

    # Defensive edge removal to avoid NetworkXError
    edge_u = "/opt/alt/lib/libalias.so"
    edge_v = "/opt/alt/lib/libreal.so"
    if sbom.fs_tree.has_edge(edge_u, edge_v):
        sbom.fs_tree.remove_edge(edge_u, edge_v)

    if sbom.fs_tree.has_node(edge_u):
        sbom.fs_tree.remove_node(edge_u)

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

    metadata = binary.metadata[0]
    results = establish_relationships(sbom, binary, metadata)

    assert results is not None
    assert all(rel.yUUID != "falsematch-uuid" for rel in results), (
        "Heuristic should not have matched"
    )