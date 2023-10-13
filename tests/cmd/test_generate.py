import json
from pathlib import Path

from surfactant.cmd.generate import sbom

testing_data = Path(Path(__file__).parent.parent, "data")


def test_generate_no_install_prefix(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom([config_path, output_path], standalone_mode=False)
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    expected_install_paths = {
        "hello_world.exe": extract_path + "/hello_world.exe",
        "testlib.dll": extract_path + "/testlib.dll",
    }
    for software in generated_sbom["software"]:
        assert software["installPath"][0] == expected_install_paths[software["fileName"][0]]

    uuids = {software["fileName"][0]: software["UUID"] for software in generated_sbom["software"]}
    assert len(generated_sbom["relationships"]) == 1
    assert generated_sbom["relationships"][0] == {
        "xUUID": uuids["hello_world.exe"],
        "yUUID": uuids["testlib.dll"],
        "relationship": "Uses",
    }


def test_generate_with_install_prefix(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"], "installPrefix": "test_prefix/"}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom([config_path, output_path], standalone_mode=False)
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    expected_install_paths = {
        "hello_world.exe": "test_prefix/hello_world.exe",
        "testlib.dll": "test_prefix/testlib.dll",
    }
    for software in generated_sbom["software"]:
        assert software["installPath"][0] == expected_install_paths[software["fileName"][0]]

    uuids = {software["fileName"][0]: software["UUID"] for software in generated_sbom["software"]}
    assert len(generated_sbom["relationships"]) == 1
    assert generated_sbom["relationships"][0] == {
        "xUUID": uuids["hello_world.exe"],
        "yUUID": uuids["testlib.dll"],
        "relationship": "Uses",
    }


def test_generate_with_skip_install_path(tmp_path):
    extract_path = Path(testing_data, "Windows_dll_test_no1").as_posix()
    config_data = f'[{{"extractPaths": ["{extract_path}"]}}]'
    config_path = str(Path(tmp_path, "config.json"))
    output_path = str(Path(tmp_path, "out.json"))

    with open(config_path, "w") as f:
        f.write(config_data)

    # the click.testing module would be better here but it doesn't allow for files to be generated
    # pylint: disable=no-value-for-parameter
    sbom(["--skip_install_path", config_path, output_path], standalone_mode=False)
    # pylint: enable

    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    for software in generated_sbom["software"]:
        assert software["installPath"] == []

    assert len(generated_sbom["relationships"]) == 0
