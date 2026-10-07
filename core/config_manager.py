"""
SyncHunt - Configuration Manager
Handles loading, validating and accessing configuration.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_PROFILE = "balanced"


class ConfigManager:
    """Manages tool configuration from a YAML file."""

    DEFAULT_CONFIG_PATH = "config.yaml"

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config: Dict[str, Any] = {}
        self._load_config()

    # ------------------------------------------------------------------
    # Loading / saving
    # ------------------------------------------------------------------
    def _load_config(self) -> None:
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )
        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f) or {}
        if not self.config:
            raise ValueError("Configuration file is empty or invalid.")

    def save_config(self, path: Optional[str] = None) -> None:
        save_path = path or self.config_path
        with open(save_path, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2, sort_keys=False)

    # ------------------------------------------------------------------
    # Generic accessors
    # ------------------------------------------------------------------
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a nested config value using dot notation.

        Example: config.get('subdomain_enum.subfinder.enabled')
        """
        value: Any = self.config
        for key in str(key_path).split("."):
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value: Any) -> None:
        """Set a nested config value using dot notation."""
        keys = str(key_path).split(".")
        node = self.config
        for key in keys[:-1]:
            if not isinstance(node.get(key), dict):
                node[key] = {}
            node = node[key]
        node[keys[-1]] = value

    def get_bool(self, key_path: str, default: bool = False) -> bool:
        value = self.get(key_path, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def get_int(self, key_path: str, default: int = 0) -> int:
        try:
            return int(self.get(key_path, default))
        except (TypeError, ValueError):
            return default

    def get_float(self, key_path: str, default: float = 0.0) -> float:
        try:
            return float(self.get(key_path, default))
        except (TypeError, ValueError):
            return default

    def get_list(self, key_path: str, default: Optional[List[Any]] = None) -> List[Any]:
        value = self.get(key_path, default)
        if value is None:
            return list(default or [])
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return [value]

    # ------------------------------------------------------------------
    # Phase / profile helpers
    # ------------------------------------------------------------------
    @property
    def profile(self) -> str:
        return self.get("general.profile", DEFAULT_PROFILE)

    def profile_phases(self, profile: Optional[str] = None) -> List[str]:
        """Phase list for a profile (empty list means "use the default pipeline")."""
        name = profile or self.profile
        phases = self.get(f"profiles.{name}.phases", None)
        if isinstance(phases, (list, tuple)):
            return [str(p).strip().lower() for p in phases if str(p).strip()]
        return []

    def available_profiles(self) -> List[str]:
        profiles = self.get("profiles", {})
        return sorted(profiles.keys()) if isinstance(profiles, dict) else []

    def get_output_dir(self, target: str, run_id: Optional[str] = None,
                       base_dir: Optional[str] = None) -> str:
        """Get the output directory for a target and run."""
        base = base_dir or self.get("general.output_dir", "output")
        safe_target = str(target).replace("https://", "").replace("http://", "")
        safe_target = safe_target.replace("/", "_").replace(":", "_").replace("*", "_")
        run = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(base, safe_target, run)

    def latest_output_dir(self, target: str, base_dir: Optional[str] = None) -> Optional[str]:
        """Most recent output directory for a target (used by --resume)."""
        base = base_dir or self.get("general.output_dir", "output")
        safe_target = str(target).replace("https://", "").replace("http://", "")
        safe_target = safe_target.replace("/", "_").replace(":", "_").replace("*", "_")
        target_dir = os.path.join(base, safe_target)
        if not os.path.isdir(target_dir):
            return None
        runs = sorted(
            (
                os.path.join(target_dir, name)
                for name in os.listdir(target_dir)
                if os.path.isdir(os.path.join(target_dir, name))
            ),
            reverse=True,
        )
        return runs[0] if runs else None

    # ------------------------------------------------------------------
    # Phase / tool gates
    # ------------------------------------------------------------------
    def get_threads(self) -> int:
        return self.get_int("general.threads", 50)

    def get_timeout(self) -> int:
        return self.get_int("general.timeout", 30)

    def get_rate_limit(self) -> float:
        return self.get_float("general.rate_limit", 50)

    def is_phase_enabled(self, section: str, default: bool = True) -> bool:
        """Whether a config section (usually a phase) is enabled."""
        return self.get_bool(f"{section}.enabled", default)

    def get_tool_config(self, phase: str, tool: str) -> Dict[str, Any]:
        """Tool-specific configuration block."""
        value = self.get(f"{phase}.{tool}", {})
        return value if isinstance(value, dict) else {}

    def is_tool_enabled(self, phase: str, tool: str, default: bool = False) -> bool:
        """Whether a specific tool inside a phase is enabled."""
        return self.get_bool(f"{phase}.{tool}.enabled", default)

    def disabled_tools(self, phase: str) -> List[str]:
        block = self.get(phase, {})
        if not isinstance(block, dict):
            return []
        return [
            name
            for name, value in block.items()
            if isinstance(value, dict) and value.get("enabled") is False
        ]

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate(self, known_phases: Optional[List[str]] = None) -> List[str]:
        """
        Return a list of human-readable configuration warnings.

        Only warnings with `severity: warning` are reported here; the doctor
        command in main.py combines this with dependency checks.
        """
        warnings: List[str] = []
        known = set(known_phases or [])

        for profile in self.available_profiles():
            phases = self.profile_phases(profile)
            if not phases:
                warnings.append(f"profile '{profile}' has no phases defined")
                continue
            if known:
                unknown = [p for p in phases if p not in known]
                if unknown:
                    warnings.append(
                        f"profile '{profile}' references unknown phase(s): "
                        f"{', '.join(sorted(set(unknown)))}"
                    )

        wordlist_paths: List[str] = []
        for section in ("subdomain_enum", "content_discovery"):
            block = self.get(section, {})
            if isinstance(block, dict):
                for tool_cfg in block.values():
                    if isinstance(tool_cfg, dict) and tool_cfg.get("wordlist"):
                        wordlist_paths.append(str(tool_cfg["wordlist"]))
        missing = sorted({p for p in wordlist_paths if not os.path.exists(p)})
        if missing:
            warnings.append(
                "wordlists not found (tools using them will be skipped): "
                + ", ".join(missing)
            )

        scope_file = self.get("general.scope_file", "")
        if scope_file and not os.path.exists(scope_file):
            warnings.append(f"scope_file '{scope_file}' does not exist")
        oos_file = self.get("general.out_of_scope_file", "")
        if oos_file and not os.path.exists(oos_file):
            warnings.append(f"out_of_scope_file '{oos_file}' does not exist")

        if self.get_float("general.rate_limit", 50) <= 0:
            warnings.append("general.rate_limit must be > 0")

        return warnings

    def __repr__(self) -> str:
        return f"<ConfigManager config_path='{self.config_path}' profile='{self.profile}'>"
