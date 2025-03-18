import subprocess
import pytest
import json


def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {command}\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
    return result.stdout.strip()


@pytest.fixture(scope="session")
def setup_environment():
    """Fixture to install Grype and the Grype plugin."""
    check_command_availability("surfactant")
    check_command_availability("docker")
    
    # Verify and install required tools
    install_grype()

    # Install the Grype plugin in editable mode
    print("Installing the Grype plugin in editable mode ...")
    output = run_command("pip install -e .")
    print(f"Install output: {output}")

    enable_plugin("surfactantplugin_grype")


def check_command_availability(command):
    if subprocess.run(f"which {command}", shell=True, capture_output=True).returncode != 0:
        pytest.skip(f"{command} is not available in the test environment.")


def install_grype():
    """Install Grype if not already installed."""
    try:
        output = run_command("grype --version")
        print(f"Grype is already installed: {output}")
    except RuntimeError:
        print("Installing Grype...")
        run_command("curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin")
        print("Grype installed successfully.")


def enable_plugin(plugin_name):
    run_command(f"surfactant plugin enable {plugin_name}")
    output = run_command(f"surfactant plugin list | grep '> name:' | grep '{plugin_name}'")
    assert plugin_name in output, f"{plugin_name} not found in enabled plugins"


def disable_plugin(plugin_name):
    run_command(f"surfactant plugin disable {plugin_name}")
    output = run_command(f"surfactant plugin list | grep -A 5 'DISABLED PLUGINS' | grep '{plugin_name}'")
    assert plugin_name in output, f"{plugin_name} not found in disabled plugins"


@pytest.fixture(scope="function")
def create_config_and_tarball(tmp_path):
    """
    Fixture to create the configuration file and Docker tarball for testing.
    The tarball contains the 'hello-world' Docker container filesystem.
    """
    # Pull the 'hello-world' Docker image
    print("Pulling the 'hello-world' Docker image...")
    run_command("sudo docker pull hello-world")

    # Export the container's filesystem to a tarball
    tarball_file = tmp_path / "myimage_latest.tar.gz"
    print(f"Exporting the container filesystem to {tarball_file}...")
    run_command(f"sudo docker save hello-world:latest | gzip > {tarball_file}")
        

    # Remove the container to clean up
    print("Removing the container...")
    run_command(f"sudo docker rmi hello-world:latest")

    # Create the configuration file
    config_data = [
        {
            "extractPaths": [str(tarball_file)],
            "installPrefix": "/usr/"
        }
    ]
    config_file = tmp_path / "config_dockertball.json"
    with open(config_file, "w") as f:
        json.dump(config_data, f, indent=4)
    print(f"Configuration file created: {config_file}")

    return str(config_file), str(tarball_file)


def test_debug_create_config_and_tarball(create_config_and_tarball):
    # pytest test_grype.py -k test_debug_create_config_and_tarball -v
    # Call the fixture and unpack its return values
    config_file, tarball_file = create_config_and_tarball

    # Print or log the outputs for debugging
    print(f"Config file path: {config_file}")
    print(f"Tarball file path: {tarball_file}")

    # Assert that the files were created successfully
    assert config_file is not None, "Config file was not created"
    assert tarball_file is not None, "Tarball file was not created"


def test_surfactant_generate(setup_environment, create_config_and_tarball, tmp_path):
    """Test the Surfactant generate command with the Grype plugin."""
    # Get the configuration file and tarball file from the fixture
    config_file, tarball_file = create_config_and_tarball

    # **********************
    # **** Enabled Test ***
    # **********************

    # Enable and verify the Grype plugin is enabled
    enable_plugin("surfactantplugin_grype")

    # Run the Surfactant generate command (with Grype enabled)
    output_enabled_sbom = tmp_path / "docker_tball_grype-enabled_sbom.json"
    print(config_file)
    with open(config_file, "r") as f:
        config_out = json.load(f)
    print(json.dumps(config_out, indent=4))
    command = f"surfactant generate {config_file} {output_enabled_sbom}"
    print(f"Running command: {command}")
    run_command(command)

    # Verify the SBOM file is created
    assert output_enabled_sbom.exists(), f"SBOM file not created: {output_enabled_sbom}"

    # Read and parse the SBOM
    with open(output_enabled_sbom, "r") as f:
        sbom_enabled = json.load(f)

    # Assert that the Grype output is present
    print("ENABLED")
    print(json.dumps(sbom_enabled, indent=4))
    assert any("grype_output" in entry for entry in sbom_enabled["software"][0]["metadata"]), \
        "Grype output should be present when the plugin is enabled"
    
    # Assert that the Grype output is empty (in this specific test case)
    assert all(
        entry.get("grype_output") == []
        for entry in sbom_enabled["software"][0]["metadata"]
        if "grype_output" in entry
    ), "Grype output should be empty for a minimal tarball with no vulnerabilities"

    # **********************
    # **** Disabled Test ***
    # **********************

    # Disable the Grype plugin and verify the plugin is disabled
    disable_plugin("surfactantplugin_grype")

    # Run the Surfactant generate command (with Grype disabled)
    output_disabled_sbom = tmp_path / "docker_tball_grype-disabled_sbom.json"
    command = f"surfactant generate {config_file} {output_disabled_sbom}"
    print(f"Running command: {command}")
    run_command(command)

    # Verify the SBOM file is created
    assert output_disabled_sbom.exists(), f"SBOM file not created: {output_disabled_sbom}"

    # Read and parse the SBOM
    with open(output_disabled_sbom, "r") as f:
        sbom_disabled = json.load(f)

    # Assert that the Grype output is not present
    print("DISABLED")
    print(json.dumps(sbom_disabled, indent=4))
    assert not any("grype_output" in entry for entry in sbom_disabled["software"][0]["metadata"]), (
        "Grype output should not be present when the plugin is disabled"
    )

    # ************************
    # *** Test consistency ***
    # ************************

    # Compare the two SBOMs for consistency (except for Grype output)
    assert sbom_disabled["software"][0]["fileName"] == sbom_enabled["software"][0]["fileName"], (
        "File names should match between disabled and enabled cases"
    )
    assert sbom_disabled["software"][0]["sha256"] == sbom_enabled["software"][0]["sha256"], (
        "SHA256 hashes should match between disabled and enabled cases"
    )
