# pylint: disable=redefined-outer-name
import pytest

from surfactant.relationships import dotnet_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


@pytest.fixture
def sbom_fixture():
    """
    Fixture: returns a basic SBOM with a .NET supplier and consumer.
    - Supplier exports SomeLibrary.dll with version and culture metadata.
    - Consumer references SomeLibrary.dll in its dotnetAssemblyRef.
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-supplier",
        fileName=["SomeLibrary.dll"],
        installPath=["/app/bin/SomeLibrary.dll"],
        metadata=[
            {"dotnetAssembly": {"Name": "SomeLibrary", "Version": "1.0.0.0", "Culture": "neutral"}}
        ],
    )

    consumer = Software(
        UUID="uuid-consumer",
        installPath=["/app/bin/App.exe"],
        metadata=[
            {
                "dotnetAssemblyRef": [
                    {"Name": "SomeLibrary", "Version": "1.0.0.0", "Culture": "neutral"}
                ]
            }
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    return sbom, consumer, supplier


def test_dotnet_fs_tree_match(sbom_fixture):
    """
    Test Phase 1: fs_tree resolution using get_software_by_path.
    Ensures the plugin emits a relationship if the path is indexed.
    """
    sbom, consumer, supplier = sbom_fixture

    # Simulate the DLL being located in fs_tree
    sbom.fs_tree.add_node("/app/bin/SomeLibrary.dll", software_uuid=supplier.UUID)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(consumer.UUID, supplier.UUID, "Uses")]


def test_dotnet_codebase_match():
    """
    Test: codeBase.href resolution from app.config.
    Ensures href is respected as a valid relative match.
    """
    sbom = SBOM()

    supplier = Software(UUID="uuid-lib", fileName=["lib.dll"], installPath=["/app/private/lib.dll"])

    consumer = Software(
        UUID="uuid-app",
        installPath=["/app/main.exe"],
        metadata=[
            {
                "dotnetAssemblyRef": [{"Name": "lib"}],
                "appConfigFile": {
                    "runtime": {
                        "assemblyBinding": {
                            "dependentAssembly": [{"codeBase": {"href": "private/lib.dll"}}]
                        }
                    }
                },
            }
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    # Match is located exactly at the codebase href
    sbom.fs_tree.add_node("/app/private/lib.dll", software_uuid=supplier.UUID)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("uuid-app", "uuid-lib", "Uses")]


def test_dotnet_implmap_unmanaged_match():
    """
    Test: unmanaged import from dotnetImplMap should resolve as native.
    Ensures fallback probing with name variants like native.dll, native.so, etc.
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-native", fileName=["native.so"], installPath=["/app/lib/native.so"]
    )

    consumer = Software(
        UUID="uuid-consumer",
        installPath=["/app/main.exe"],
        metadata=[{"dotnetImplMap": [{"Name": "native"}], "dotnetAssemblyRef": []}],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("uuid-consumer", "uuid-native", "Uses")]


def test_dotnet_same_directory():
    """
    Test: assembly in same directory as consumer should be resolved.
    Covers legacy phase and base probing behavior.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib1", fileName=["samedirlib.dll"], installPath=["/app/samedirlib.dll"]
    )
    consumer = Software(
        UUID="app",
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "samedirlib"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("app", "lib1", "Uses")]


def test_dotnet_subdir():
    """
    Test: DLL in a subdirectory (e.g., /app/subdir/) is found by probing.
    Covers Phase 2 fallback behavior.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib2", fileName=["subdirlib.dll"], installPath=["/app/subdir/subdirlib.dll"]
    )
    consumer = Software(
        UUID="app",
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "subdirlib"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("app", "lib2", "Uses")]


def test_dotnet_culture_subdir():
    """
    Test: DLL in a culture-specific subdirectory is matched if Culture is specified.
    Covers culture-aware probing logic.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib3", fileName=["culturelib.dll"], installPath=["/app/culture/culturelib.dll"]
    )
    consumer = Software(
        UUID="app",
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "culturelib", "Culture": "culture"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("app", "lib3", "Uses")]


def test_dotnet_private_path():
    """
    Test: DLL resolved from app.config probing.privatePath directories.
    Ensures private paths are appended to probe set.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib4", fileName=["pvtlib.dll"], installPath=["/app/bin/custom/pvtlib.dll"]
    )
    consumer = Software(
        UUID="app",
        installPath=["/app/bin/app.exe"],
        metadata=[
            {
                "dotnetAssemblyRef": [{"Name": "pvtlib"}],
                "appConfigFile": {
                    "runtime": {"assemblyBinding": {"probing": {"privatePath": "custom"}}}
                },
            }
        ],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship("app", "lib4", "Uses")]


def test_dotnet_version_mismatch_filtered():
    """
    Test: supplier has wrong version; should be filtered out by version check.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib5",
        fileName=["wrong.dll"],
        installPath=["/lib/wrong.dll"],
        metadata=[{"dotnetAssembly": {"Name": "wrong", "Version": "2.0.0.0"}}],
    )
    consumer = Software(
        UUID="app",
        installPath=["/lib/app.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "wrong", "Version": "1.0.0.0"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == []


def test_dotnet_culture_mismatch_filtered():
    """
    Test: supplier has wrong culture; should be filtered out by culture check.
    """
    sbom = SBOM()
    supplier = Software(
        UUID="lib6",
        fileName=["wrongcult.dll"],
        installPath=["/lib/wrongcult.dll"],
        metadata=[{"dotnetAssembly": {"Name": "wrongcult", "Culture": "xx"}}],
    )
    consumer = Software(
        UUID="app",
        installPath=["/lib/app.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "wrongcult", "Culture": "yy"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == []
