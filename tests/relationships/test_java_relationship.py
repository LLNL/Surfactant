import pytest

from surfactant.relationships import java_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


@pytest.fixture
def java_class_path():
    return "com/example/HelloWorld.class"


@pytest.fixture
def test_sbom():
    sbom = SBOM()

    # Software exporting a class
    jar_supplier = Software(
        UUID="uuid-supplier",
        fileName=["HelloWorld.class"],
        installPath=["/app/lib/com/example/HelloWorld.class"],
        metadata=[
            {
                "javaClasses": {
                    "com.example.HelloWorld": {
                        "javaExports": ["com.example.HelloWorld"],
                        "javaImports": [],
                    }
                }
            }
        ],
    )

    # Software importing that class (dependency)
    jar_importer = Software(
        UUID="uuid-importer",
        fileName=["app.jar"],
        installPath=["/app/bin/app.jar"],
        metadata=[
            {
                "javaClasses": {
                    "com.example.Main": {
                        "javaExports": ["com.example.Main"],
                        "javaImports": ["com.example.HelloWorld"],
                    }
                }
            }
        ],
    )

    sbom.add_software(jar_supplier)
    sbom.add_software(jar_importer)

    return sbom, jar_importer, jar_supplier


def test_phase_1_fs_tree_match(test_sbom, java_class_path):
    """
    Phase 1: Check that sbom.get_software_by_path() resolves the dependency
    """
    sbom, importer, supplier = test_sbom

    # Inject into fs_tree
    sbom.fs_tree.add_node(f"/app/lib/{java_class_path}", software_uuid=supplier.UUID)

    metadata = importer.metadata[0]
    results = java_relationship.establish_relationships(sbom, importer, metadata)

    assert results is not None
    assert len(results) == 1
    assert results[0] == Relationship(importer.UUID, supplier.UUID, "Uses")


def test_phase_2_legacy_path_match():
    """
    Phase 2: Match based on installPath + fileName fallback
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-supplier",
        fileName=["HelloWorld.class"],
        installPath=["/app/classes/com/example/HelloWorld.class"],
        metadata=[
            {"javaClasses": {"com.example.HelloWorld": {"javaExports": ["com.example.HelloWorld"]}}}
        ],
    )

    importer = Software(
        UUID="uuid-importer",
        installPath=["/other/bin/app.jar"],
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results is not None
    assert results == [Relationship(importer.UUID, supplier.UUID, "Uses")]


def test_phase_3_heuristic_match():
    """
    Phase 3: Match via fileName + shared directory (heuristic)
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-supplier",
        fileName=["HelloWorld.class"],
        installPath=["/shared/lib/HelloWorld.class"],
    )

    importer = Software(
        UUID="uuid-importer",
        installPath=["/shared/bin/app.jar"],
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    # place them in same directory /shared
    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results is not None
    assert results == [Relationship(importer.UUID, supplier.UUID, "Uses")]


def test_no_match_returns_empty():
    """
    Validate that no relationship is returned when no match is possible
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-supplier", fileName=["Other.class"], installPath=["/somewhere/Other.class"]
    )

    importer = Software(
        UUID="uuid-importer",
        installPath=["/bin/app.jar"],
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results == []
