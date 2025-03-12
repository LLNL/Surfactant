import subprocess
import pytest
import os
import json
import time


def run_command(command):
    """Helper function to run shell commands."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {command}\n{result.stderr}")
    return result.stdout.strip()


@pytest.fixture(scope="session")
def setup_environment():
    """Fixture to install Grype and the Grype plugin."""
    # Step 1: Verify Surfactant is already installed
    output = run_command("surfactant --version")
    print(f"Surfactant is already installed: {output}")

    # Step 2: Install Grype
    print("Installing Grype...")
    run_command("curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin")

    # Verify Grype installation
    output = run_command("grype --version")
    print(f"Grype installed successfully: {output}")

    # Install the Grype plugin in editable mode
    print(f"Installing the Grype plugin in editable mode ...")
    output = run_command(f"pip install -e .")
    print(f"Install output: {output}")

    # Ensure that the Grype plugin is enabled (neccessary if running pytest multiple times)
    run_command("surfactant plugin enable surfactantplugin_grype")

    # Verify the Grype plugin installation
    output = run_command(f"surfactant plugin list | grep '> name:' | grep 'surfactantplugin_grype'")
    print(f"Filtered plugin output: {output}")
    assert "surfactantplugin_grype" in output, "Grype plugin not found in Surfactant plugins"


@pytest.fixture(scope="function")
def create_config_and_tarball(tmp_path):
    """
    Fixture to create the configuration file and Docker tarball for testing.
    The tarball contains the 'hello-world' Docker container filesystem.
    """
    # Step 1: Pull the 'hello-world' Docker image
    print("Pulling the 'hello-world' Docker image...")
    run_command("sudo docker pull hello-world")

    # Step 2: Create a container from the 'hello-world' image
    print("Creating a container from the 'hello-world' image...")
    container_id = run_command("sudo docker create hello-world")
    print(f"Container created with ID: {container_id}")

    # Step 3: Export the container's filesystem to a tarball
    tarball_file = tmp_path / "myimage_latest.tar.gz"
    print(f"Exporting the container filesystem to {tarball_file}...")
    with open(tarball_file, "wb") as f:
        subprocess.run(f"sudo docker export {container_id}", shell=True, stdout=f, check=True)

    # Step 4: Remove the container to clean up
    print("Removing the container...")
    run_command(f"sudo docker rm {container_id}")

    # Step 5: Create the configuration file
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


def test_surfactant_generate(setup_environment, create_config_and_tarball, tmp_path):
    """Test the Surfactant generate command with the Grype plugin."""
    # Get the configuration file and tarball file from the fixture
    config_file, tarball_file = create_config_and_tarball

    # **********************
    # **** Enabled Test ***
    # **********************

    # Enable the Grype plugin
    run_command("surfactant plugin enable surfactantplugin_grype")

    # Verify the Grype plugin is enabled
    output = run_command(f"surfactant plugin list | grep '> name:' | grep 'surfactantplugin_grype'")
    assert "surfactantplugin_grype" in output, "Grype plugin not found in Surfactant plugins"

    # Run the Surfactant generate command (with Grype enabled)
    output_enabled_sbom = tmp_path / "docker_tball_grype-enabled_sbom.json"
    print(config_file)
    with open(config_file, "r") as f:
        config_out = json.load(f)
    print(json.dumps(config_out, indent=4))
    command = f"surfactant generate {config_file} {output_enabled_sbom}"
    print(f"Running command: {command}")
    run_command(command)
    time.sleep(40)

    # Verify the SBOM file is created
    assert output_enabled_sbom.exists(), f"SBOM file not created: {output_enabled_sbom}"

    # Read and parse the SBOM
    with open(output_enabled_sbom, "r") as f:
        sbom_enabled = json.load(f)

    # Assert that the Grype output is present
    print("ENABLED")
    print(json.dumps(sbom_enabled, indent=4))
    print(any("grype_output" in entry for entry in sbom_enabled["software"][0]["metadata"]))
    assert any("grype_output" in entry for entry in sbom_enabled["software"][0]["metadata"]), \
        "Grype output should be present when the plugin is enabled"
    

    # Assert that the Grype output is empty (in this specific test case)
    assert all(entry.get("grype_output") == [] for entry in sbom_enabled["software"][0]["metadata"] if "grype_output" in entry), \
        "Grype output should be empty for a minimal tarball with no vulnerabilities"


    # **********************
    # **** Disabled Test ***
    # **********************

    # Disable the Grype plugin
    run_command("surfactant plugin disable surfactantplugin_grype")
    
    # Run the command to check for disabled plugins
    output = run_command("surfactant plugin list | grep -A 5 'DISABLED PLUGINS' | grep 'surfactantplugin_grype'")
    
    # Assert that the plugin is found in the disabled plugins section
    assert "surfactantplugin_grype" in output, "Grype plugin is not disabled in Surfactant plugins"

    # Run the Surfactant generate command (with Grype disabled)
    output_disabled_sbom = tmp_path / "docker_tball_grype-disabled_sbom.json"
    command = f"surfactant generate {config_file} {output_disabled_sbom}"
    print(f"Running command: {command}")
    run_command(command)
    time.sleep(10)

    # Verify the SBOM file is created
    assert output_disabled_sbom.exists(), f"SBOM file not created: {output_disabled_sbom}"

    # Read and parse the SBOM
    with open(output_disabled_sbom, "r") as f:
        sbom_disabled = json.load(f)

    # Assert that the Grype output is not present
    print("DISABLED")
    print(json.dumps(sbom_disabled, indent=4))
    assert not any("grype_output" in entry for entry in sbom_disabled["software"][0]["metadata"]), \
        "Grype output should not be present when the plugin is disabled"


    # ************************
    # *** Test consistency ***
    # ************************

    # Compare the two SBOMs for consistency (except for Grype output)
    assert sbom_disabled["software"][0]["fileName"] == sbom_enabled["software"][0]["fileName"], \
        "File names should match between disabled and enabled cases"
    assert sbom_disabled["software"][0]["sha256"] == sbom_enabled["software"][0]["sha256"], \
        "SHA256 hashes should match between disabled and enabled cases"

