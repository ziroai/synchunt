"""
BugHuntRecon - Configuration Manager
Handles loading, validating, and accessing configuration.
"""

import os
import yaml
from datetime import datetime


class ConfigManager:
    """Manages config files, profile selection, and nested lookup."""

    DEFAULT_CONFIG_PATH = 'config.yaml'

    def __init__(self, config_path=None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = {}
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f) or {}

        if not self.config:
            raise ValueError('Configuration file is empty or invalid.')

    def get(self, key_path, default=None):
        value = self.config
        for key in str(key_path).split('.'):
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path, value):
        keys = str(key_path).split('.')
        config = self.config
        for key in keys[:-1]:
            if key not in config or not isinstance(config[key], dict):
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value

    def get_bool(self, key_path, default=False):
        value = self.get(key_path, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('1', 'true', 'yes', 'on')
        return bool(value)

    def get_int(self, key_path, default=0):
        value = self.get(key_path, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def get_list(self, key_path, default=None):
        value = self.get(key_path, default or [])
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        return []

    def get_output_dir(self, target):
        base_dir = self.get('general.output_dir', 'output')
        safe_target = target.replace('https://', '').replace('http://', '')
        safe_target = safe_target.replace('/', '_').replace(':', '_').lower()
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(base_dir, safe_target, date_str)

    def get_threads(self):
        return self.get_int('general.threads', 50)

    def get_timeout(self):
        return self.get_int('general.timeout', 30)

    def is_phase_enabled(self, phase):
        return self.get_bool(f'{phase}.enabled', True)

    def get_tool_config(self, phase, tool):
        return self.get(f'{phase}.{tool}', {})

    def is_tool_enabled(self, phase, tool):
        return self.get_bool(f'{phase}.{tool}.enabled', False)

    def get_profile(self, profile_name='balanced'):
        profiles = self.get('profiles', {})
        default = {
            'phases': [
                'subdomain', 'validation', 'enrichment', 'portscan', 'fingerprint',
                'github_recon', 'content', 'api_discovery', 'jsanalysis', 'cloud_enum',
                'vulnscan', 'sensitive', 'screenshot', 'prioritize', 'report'
            ]
        }
        if profile_name in profiles:
            return profiles[profile_name]
        return default

    def save_config(self, path=None):
        save_path = path or self.config_path
        with open(save_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

    def __repr__(self):
        return f"<ConfigManager config_path='{self.config_path}'>"
