# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from surfactant.cmd.plugin import plugin_update_db_cmd


@pytest.fixture
def mock_plugin_manager():
    """Create a mock plugin manager with a test plugin."""
    pm = MagicMock()
    test_plugin = MagicMock()
    test_plugin.update_db = MagicMock(return_value="Database updated successfully.")

    pm.get_plugins.return_value = [test_plugin]
    pm.get_name.return_value = "test_plugin"
    pm.get_canonical_name.return_value = "test_plugin"

    return pm, test_plugin


def test_update_db_with_force_flag(mock_plugin_manager):
    """Test that the --force flag is passed to the plugin's update_db method."""
    pm, test_plugin = mock_plugin_manager

    with (
        patch("surfactant.cmd.plugin.get_plugin_manager", return_value=pm),
        patch("surfactant.cmd.plugin.call_init_hooks"),
        patch("surfactant.cmd.plugin.is_hook_implemented", return_value=True),
        patch("surfactant.cmd.plugin.find_plugin_by_name", return_value=test_plugin),
    ):
        runner = CliRunner()
        result = runner.invoke(plugin_update_db_cmd, ["test_plugin", "--force"])

        # Verify the command executed successfully
        assert result.exit_code == 0

        # Verify update_db was called with force=True
        test_plugin.update_db.assert_called_once_with(force=True)

        # Verify the output contains expected message
        assert "Updating test_plugin" in result.output


def test_update_db_without_force_flag(mock_plugin_manager):
    """Test that update_db is called with force=False when --force is not specified."""
    pm, test_plugin = mock_plugin_manager

    with (
        patch("surfactant.cmd.plugin.get_plugin_manager", return_value=pm),
        patch("surfactant.cmd.plugin.call_init_hooks"),
        patch("surfactant.cmd.plugin.is_hook_implemented", return_value=True),
        patch("surfactant.cmd.plugin.find_plugin_by_name", return_value=test_plugin),
    ):
        runner = CliRunner()
        result = runner.invoke(plugin_update_db_cmd, ["test_plugin"])

        # Verify the command executed successfully
        assert result.exit_code == 0

        # Verify update_db was called with force=False
        test_plugin.update_db.assert_called_once_with(force=False)

        # Verify the output contains expected message
        assert "Updating test_plugin" in result.output


def test_update_db_all_with_force_flag(mock_plugin_manager):
    """Test that the --force flag works with --all option."""
    pm, test_plugin = mock_plugin_manager

    with (
        patch("surfactant.cmd.plugin.get_plugin_manager", return_value=pm),
        patch("surfactant.cmd.plugin.call_init_hooks"),
        patch("surfactant.cmd.plugin.is_hook_implemented", return_value=True),
    ):
        runner = CliRunner()
        result = runner.invoke(plugin_update_db_cmd, ["--all", "--force"])

        # Verify the command executed successfully
        assert result.exit_code == 0

        # Verify update_db was called with force=True
        test_plugin.update_db.assert_called_once_with(force=True)

        # Verify the output contains expected message
        assert "Updating test_plugin" in result.output


def test_update_db_all_without_force_flag(mock_plugin_manager):
    """Test that --all option works without --force flag."""
    pm, test_plugin = mock_plugin_manager

    with (
        patch("surfactant.cmd.plugin.get_plugin_manager", return_value=pm),
        patch("surfactant.cmd.plugin.call_init_hooks"),
        patch("surfactant.cmd.plugin.is_hook_implemented", return_value=True),
    ):
        runner = CliRunner()
        result = runner.invoke(plugin_update_db_cmd, ["--all"])

        # Verify the command executed successfully
        assert result.exit_code == 0

        # Verify update_db was called with force=False
        test_plugin.update_db.assert_called_once_with(force=False)

        # Verify the output contains expected message
        assert "Updating test_plugin" in result.output
