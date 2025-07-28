# pylint: disable=redefined-outer-name
import pytest

from surfactant.sbomtypes import SBOM, Software


@pytest.fixture
def software_entries():
    return [
        Software(UUID="uuid-1", installPath=["/usr/bin/ls"]),
        Software(UUID="uuid-2", installPath=["/usr/lib/libc.so"]),
        Software(UUID="uuid-3", installPath=["/opt/tools/bin/run"]),
    ]


def test_fs_tree_population(software_entries):
    sbom = SBOM()
    for sw in software_entries:
        sbom.add_software(sw)  # This should trigger _add_software_to_fs_tree()
    fs = sbom.fs_tree
    # Check that expected nodes exist
    assert fs.has_node("/usr")
    assert fs.has_node("/usr/bin")
    assert fs.has_node("/usr/bin/ls")
    assert fs.has_node("/usr/lib/libc.so")
    assert fs.has_node("/opt/tools/bin/run")
    # Check that edges reflect directory hierarchy
    assert fs.has_edge("/usr", "/usr/bin")
    assert fs.has_edge("/usr/bin", "/usr/bin/ls")
    assert fs.has_edge("/usr/lib", "/usr/lib/libc.so")
    assert fs.has_edge("/opt", "/opt/tools")
    assert fs.has_edge("/opt/tools/bin", "/opt/tools/bin/run")
    # Check software UUID tagging
    assert fs.nodes["/usr/bin/ls"]["software_uuid"] == "uuid-1"
    assert fs.nodes["/usr/lib/libc.so"]["software_uuid"] == "uuid-2"
    assert fs.nodes["/opt/tools/bin/run"]["software_uuid"] == "uuid-3"


def test_get_software_by_path(software_entries):
    sbom = SBOM()
    for sw in software_entries:
        sbom.add_software(sw)
    sw1 = sbom.get_software_by_path("/usr/bin/ls")
    sw2 = sbom.get_software_by_path("/opt/tools/bin/run")
    sw_invalid = sbom.get_software_by_path("/nonexistent")
    assert sw1.UUID == "uuid-1"
    assert sw2.UUID == "uuid-3"
    assert sw_invalid is None
