"""
BugHuntRecon - Configuration Manager
Handles loading, validating, and accessing configuration.
"""

import os
import yaml
from datetime import datetime


class ConfigManager:
    """Manages tool configuration from YAML file."""

    DEFAULT_CONFIG_PATH = "config.yaml"

    def __init__(self, config_path=None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        with open(self.config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        if not self.config:
            raise ValueError("Configuration file is empty or invalid.")

    def get(self, key_path, default=None):
        """
        Get a nested config value using dot notation.
        Example: config.get('subdomain_enum.subfinder.enabled')
        """
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path, value):
        """Set a nested config value using dot notation."""
        keys = key_path.split('.')
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value

    def get_output_dir(self, target):
        """Get the output directory for a target."""
        base_dir = self.get('general.output_dir', 'output')
        # Sanitize target name for directory
        safe_target = target.replace('https://', '').replace('http://', '')
        safe_target = safe_target.replace('/', '_').replace(':', '_')
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(base_dir, safe_target, date_str)

    def get_threads(self):
        """Get global thread count."""
        return self.get('general.threads', 50)

    def get_timeout(self):
        """Get global timeout."""
        return self.get('general.timeout', 30)

    def is_phase_enabled(self, phase):
        """Check if a phase is enabled."""
        return self.get(f'{phase}.enabled', True)

    def get_tool_config(self, phase, tool):
        """Get tool-specific configuration."""
        return self.get(f'{phase}.{tool}', {})

    def is_tool_enabled(self, phase, tool):
        """Check if a specific tool is enabled."""
        return self.get(f'{phase}.{tool}.enabled', False)

    def save_config(self, path=None):
        """Save current configuration to file."""
        save_path = path or self.config_path
        with open(save_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)

    def __repr__(self):
        return f"<ConfigManager config_path='{self.config_path}'>"