import os
import platform
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional, Union

import tomlkit


class ConfigManager:
    """A configuration manager for handling settings stored in a configuration file. The
    configuration manager internally caches a copy of the loaded configuration file, so
    external changes won't affect the setting value while a program is running.

    Attributes:
        app_name (str): The name of the application. (Default: 'surfactant')
        config_dir (Optional[Path]): The directory where the configuration file is stored.
        config (tomlkit.document): The configuration document loaded by tomlkit. Preserves formatting and comments.
        config_file_path (Path): The path to the configuration file.
    """

    _initialized: bool = False
    _instances: Dict[str, "ConfigManager"] = {}
    _lock = Lock()

    def __new__(
        cls, app_name: str = "surfactant", config_dir: Optional[Union[str, Path]] = None
    ) -> "ConfigManager":
        """Manage singleton configuration manager for each unique application name.

        Args:
            app_name (str): The name of the application. (Default: 'surfactant')
            config_dir (Optional[Union[str, Path]]): The directory where the application configuration is stored.

        Returns:
            ConfigManager: The singleton instance of the configuration manager for the given application name.
        """
        with cls._lock:
            if app_name not in cls._instances:
                instance = super(ConfigManager, cls).__new__(cls)
                instance._initialized = False
                cls._instances[app_name] = instance
            return cls._instances[app_name]

    def __init__(
        self, app_name: str = "surfactant", config_dir: Optional[Union[str, Path]] = None
    ) -> None:
        """Initializes the configuration manager.

        Args:
            app_name (str): The name of the application. (Default: 'surfactant')
            config_dir (Optional[Union[str, Path]]): The directory where the application configuration is stored.
        """
        if self._initialized:
            return
        self._initialized = True

        self.app_name = app_name
        self.config_dir = Path(config_dir) / app_name if config_dir else None
        self.config = tomlkit.document()
        self.config_file_path = self._get_config_file_path()
        self._load_config()

    def _get_config_file_path(self) -> Path:
        """Determines the path to the configuration file.

        Returns:
            Path: The path to the configuration file.
        """
        if self.config_dir:
            config_dir = Path(self.config_dir)
        else:
            if platform.system() == "Windows":
                config_dir = Path(os.getenv("APPDATA", os.path.expanduser("~\\AppData\\Roaming")))
            else:
                config_dir = Path(os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")))
            config_dir = config_dir / self.app_name
        return config_dir / "config.toml"

    def _load_config(self) -> None:
        """Loads the configuration from the configuration file."""
        if self.config_file_path.exists():
            with open(self.config_file_path, "r") as configfile:
                self.config = tomlkit.parse(configfile.read())

    def get(self, section: str, option: str, fallback: Optional[Any] = None) -> Any:
        """Gets a configuration value.

        Args:
            section (str): The section within the configuration file.
            option (str): The option within the section.
            fallback (Optional[Any]): The fallback value if the option is not found.

        Returns:
            Any: The configuration value or the fallback value.
        """
        return self.config.get(section, {}).get(option, fallback)

    def set(self, section: str, option: str, value: Any) -> None:
        """Sets a configuration value.

        Args:
            section (str): The section  within the configuration file.
            option (str): The option within the section.
            value (Any): The value to set.
        """
        if section not in self.config:
            self.config[section] = tomlkit.table()
        self.config[section][option] = value
        self._save_config()

    def _save_config(self) -> None:
        """Saves the configuration to the configuration file."""
        if not self.config_file_path.exists():
            self.config_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file_path, "w") as configfile:
            configfile.write(tomlkit.dumps(self.config))

    def __getitem__(self, key: str) -> Any:
        """Enables dictionary-like syntax for accessing configuration settings.
        NOTE: Remember to check that the value returned is not 'None' before
        trying to access nested keys.

        Args:
            key (str): The key for accessing a TOML value or table.

        Returns:
            Any: The configuration value or 'NoneType' if the key doesn't exist.
        """
        if key not in self.config:
            return None
        return self.config[key]

    @classmethod
    def delete_instance(cls, app_name: str) -> None:
        """Deletes the singleton instance for the given application name.

        Args:
            app_name (str): The name of the application.
        """
        with cls._lock:
            if app_name in cls._instances:
                del cls._instances[app_name]
