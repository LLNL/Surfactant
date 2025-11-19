# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from surfactant.cmd.plugin import plugin_update_db_cmd
from surfactant.configmanager import ConfigManager
from surfactant.database_manager.utils import check_gpl_acceptance


@pytest.fixture
def temp_config_dir(tmp_path):  # pylint: disable=redefined-outer-name
    """Create a temporary config directory for testing."""
    config_dir = tmp_path / "test_config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def isolated_config(temp_config_dir):  # pylint: disable=redefined-outer-name
    """Create an isolated ConfigManager instance for testing."""
    # Delete any existing instance
    ConfigManager.delete_instance("surfactant")
    # Create a new instance with temporary config directory
    config_manager = ConfigManager(config_dir=str(temp_config_dir.parent))
    yield config_manager
    # Clean up
    ConfigManager.delete_instance("surfactant")


def test_allow_gpl_flag_once(isolated_config):  # pylint: disable=redefined-outer-name
    """Test --allow-gpl flag without a value (one-time acceptance)."""
    runner = CliRunner()
    
    with patch("surfactant.cmd.plugin.get_plugin_manager") as mock_pm_getter:
        # Mock plugin manager
        mock_pm = MagicMock()
        mock_pm_getter.return_value = mock_pm
        mock_pm.get_plugins.return_value = []
        
        with patch("surfactant.cmd.plugin.call_init_hooks"):
            # Run command with --allow-gpl flag (no value)
            result = runner.invoke(plugin_update_db_cmd, ["--allow-gpl", "--all"])
            
            # Check that command succeeded
            assert result.exit_code == 0
            
            # Verify runtime override is NOT persisted (should be cleaned up)
            gpl_setting = isolated_config.get("sources", "gpl_license_ok")
            assert gpl_setting is None
            
            # Verify runtime override was cleared
            assert not isolated_config.has_runtime_overrides()


def test_allow_gpl_flag_always(isolated_config):  # pylint: disable=redefined-outer-name
    """Test --allow-gpl=always to permanently set GPL acceptance."""
    runner = CliRunner()
    
    with patch("surfactant.cmd.plugin.get_plugin_manager") as mock_pm_getter:
        # Mock plugin manager
        mock_pm = MagicMock()
        mock_pm_getter.return_value = mock_pm
        mock_pm.get_plugins.return_value = []
        
        with patch("surfactant.cmd.plugin.call_init_hooks"):
            # Run command with --allow-gpl=always
            result = runner.invoke(plugin_update_db_cmd, ["--allow-gpl=always", "--all"])
            
            # Check that command succeeded
            assert result.exit_code == 0
            assert "GPL license acceptance set to 'always'" in result.output
            
            # Verify permanent setting is stored
            gpl_setting = isolated_config.get("sources", "gpl_license_ok")
            assert gpl_setting == "always"


def test_allow_gpl_flag_never(isolated_config):  # pylint: disable=redefined-outer-name
    """Test --allow-gpl=never to permanently disable GPL acceptance."""
    runner = CliRunner()
    
    with patch("surfactant.cmd.plugin.get_plugin_manager") as mock_pm_getter:
        # Mock plugin manager
        mock_pm = MagicMock()
        mock_pm_getter.return_value = mock_pm
        mock_pm.get_plugins.return_value = []
        
        with patch("surfactant.cmd.plugin.call_init_hooks"):
            # Run command with --allow-gpl=never
            result = runner.invoke(plugin_update_db_cmd, ["--allow-gpl=never", "--all"])
            
            # Check that command succeeded
            assert result.exit_code == 0
            assert "GPL license acceptance set to 'never'" in result.output
            
            # Verify permanent setting is stored
            gpl_setting = isolated_config.get("sources", "gpl_license_ok")
            assert gpl_setting == "never"


def test_check_gpl_acceptance_with_runtime_flag():
    """Test that check_gpl_acceptance respects the runtime allow_gpl flag."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create isolated config
        ConfigManager.delete_instance("surfactant")
        config_manager = ConfigManager(config_dir=tmpdir)
        
        try:
            # Set runtime override
            config_manager.set_runtime_override("sources", "gpl_license_ok", "always")
            
            # Test that GPL is accepted due to runtime override
            result = check_gpl_acceptance(
                database_category="test_category",
                key="test_key",
                gpl=True,
                overridden=False
            )
            assert result is True
        finally:
            ConfigManager.delete_instance("surfactant")


def test_check_gpl_acceptance_with_permanent_always():
    """Test that check_gpl_acceptance respects permanent 'always' setting."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create isolated config
        ConfigManager.delete_instance("surfactant")
        config_manager = ConfigManager(config_dir=tmpdir)
        
        try:
            # Set permanent always flag
            config_manager.set("sources", "gpl_license_ok", "always")
            
            # Test that GPL is accepted
            result = check_gpl_acceptance(
                database_category="test_category",
                key="test_key",
                gpl=True,
                overridden=False
            )
            assert result is True
        finally:
            ConfigManager.delete_instance("surfactant")


def test_check_gpl_acceptance_with_permanent_never():
    """Test that check_gpl_acceptance respects permanent 'never' setting."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create isolated config
        ConfigManager.delete_instance("surfactant")
        config_manager = ConfigManager(config_dir=tmpdir)
        
        try:
            # Set permanent never flag
            config_manager.set("sources", "gpl_license_ok", "never")
            
            # Test that GPL is rejected
            result = check_gpl_acceptance(
                database_category="test_category",
                key="test_key",
                gpl=True,
                overridden=False
            )
            assert result is False
        finally:
            ConfigManager.delete_instance("surfactant")


def test_no_allow_gpl_flag(isolated_config):  # pylint: disable=redefined-outer-name
    """Test command without --allow-gpl flag (default behavior)."""
    runner = CliRunner()
    
    with patch("surfactant.cmd.plugin.get_plugin_manager") as mock_pm_getter:
        # Mock plugin manager
        mock_pm = MagicMock()
        mock_pm_getter.return_value = mock_pm
        mock_pm.get_plugins.return_value = []
        
        with patch("surfactant.cmd.plugin.call_init_hooks"):
            # Run command without --allow-gpl flag
            result = runner.invoke(plugin_update_db_cmd, ["--all"])
            
            # Check that command succeeded
            assert result.exit_code == 0
            
            # Verify no GPL settings were changed
            gpl_setting = isolated_config.get("sources", "gpl_license_ok")
            assert gpl_setting is None
            
            # Verify no runtime overrides were set
            assert not isolated_config.has_runtime_overrides()
