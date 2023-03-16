import surfactant.pluginsystem
from surfactant.sbomtypes import SBOM, Relationship, Software

sbom = SBOM(
    software=[
        Software(
            UUID="abc",
            fileName=["helics_broker"],
            installPath=["/usr/local/bin/helics_broker"],
            metadata=[
                {
                    "elfDependencies": ["libhelicscpp-apps.so"],
                    "elfRpath": [],
                    "elfRunpath": ["$ORIGIN:$ORIGIN/../lib:/usr/lib/x86_64-linux-gnu"],
                    "elfDynamicFlags": [{"DF_ORIGIN": False}],
                    "elfDynamicFlags1": [{"DF_1_ORIGIN": False, "DF_1_NODEFLIB": False}],
                }
            ],
        ),
        Software(
            UUID="xyz",
            fileName=["libhelicscpp-apps.so"],
            installPath=["/usr/local/lib/libhelicscpp-apps.so"],
            metadata=[
                {
                    "elfDependencies": ["libzmq.so"],
                    "elfRpath": [],
                    "elfRunpath": ["$ORIGIN:$ORIGIN/../lib:/usr/lib/x86_64-linux-gnu"],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID="def",
            fileName=["libzmq.so"],
            installPath=["/lib/libzmq.so", "/customlib/abspath/libzmq.so"],
            metadata=[
                {
                    "elfDependencies": [],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID="hij",
            fileName=["libcomm.so"],
            installPath=["/customlib/relpath/misc/libcomm.so"],
            metadata=[
                {
                    "elfDependencies": ["/customlib/abspath/libzmq.so"],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID="klm",
            fileName=["libcomm-cpp.so"],
            installPath=["/customlib/relpath/libcomm-cpp.so"],
            metadata=[
                {
                    "elfDependencies": ["misc/libcomm.so"],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
    ],
    relationships=[],
)


def test_relative_paths():
    elfPlugin = surfactant.pluginsystem.RelationshipPlugin.get_plugin("ELF")
    sw = sbom.software[4]
    md = sw.metadata[0]
    assert elfPlugin.has_required_fields(md)
    # located in /customlib/relpath/misc, dependency specified as being under misc/ relative path
    assert elfPlugin.get_relationships(sbom, sw, md) == [Relationship("klm", "hij", "Uses")]


def test_absolute_paths():
    elfPlugin = surfactant.pluginsystem.RelationshipPlugin.get_plugin("ELF")
    sw = sbom.software[3]
    md = sw.metadata[0]
    assert elfPlugin.has_required_fields(md)
    # located in /customlib/abspath
    assert elfPlugin.get_relationships(sbom, sw, md) == [Relationship("hij", "def", "Uses")]


def test_default_system_paths():
    elfPlugin = surfactant.pluginsystem.RelationshipPlugin.get_plugin("ELF")
    sw = sbom.software[1]
    md = sw.metadata[0]
    assert elfPlugin.has_required_fields(md)
    # located in /lib
    assert elfPlugin.get_relationships(sbom, sw, md) == [Relationship("xyz", "def", "Uses")]


def test_dst_expansion():
    elfPlugin = surfactant.pluginsystem.RelationshipPlugin.get_plugin("ELF")
    sw = sbom.software[0]
    md = sw.metadata[0]
    assert elfPlugin.has_required_fields(md)
    # uses origin expansion
    assert elfPlugin.get_relationships(sbom, sw, md) == [Relationship("abc", "xyz", "Uses")]
