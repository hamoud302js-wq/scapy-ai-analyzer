"""Configuration loading and precedence handling.

Precedence (highest wins): CLI arguments > environment variables > config file > defaults.

API keys are read only from environment variables. They are never written to the
config file, the session directory, or any report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "default.yaml"

# Environment variable names for secrets.
ENV_AI_API_KEY = "SCAPY_AI_API_KEY"
ENV_AI_BASE_URL = "SCAPY_AI_BASE_URL"
ENV_AI_MODEL = "SCAPY_AI_MODEL"
ENV_AI_PROVIDER = "SCAPY_AI_PROVIDER"


@dataclass
class CaptureConfig:
    batch_size: int = 5000
    max_packets: Optional[int] = None
    interface: Optional[str] = None
    duration: Optional[float] = None
    snaplen: int = 65535
    promisc: bool = True


@dataclass
class AnalysisConfig:
    flow_idle_timeout: float = 120.0
    scan_window_seconds: float = 60.0
    scan_min_distinct_ports: int = 15
    scan_min_flows: int = 15
    fanout_min_distinct_destinations: int = 30
    dns_window_seconds: float = 60.0
    dns_min_queries: int = 50
    dns_nxdomain_ratio: float = 0.5
    host_volume_zscore: float = 3.0


@dataclass
class AIConfig:
    enabled: bool = True
    provider: str = "mock"
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    timeout_seconds: float = 30.0
    max_retries: int = 2
    max_evidence_packets: int = 25
    max_evidence_flows: int = 20
    max_evidence_alerts: int = 30
    max_prompt_bytes: int = 200_000
    language: str = "en"  # "en" | "ar"


@dataclass
class PrivacyConfig:
    redact_private_ips: bool = False
    include_raw_payloads: bool = False
    redact_mac_addresses: bool = False


@dataclass
class ReportConfig:
    output_dir: str = "results"
    formats: list[str] = field(default_factory=lambda: ["json", "html"])
    include_packet_details: bool = True
    max_packets_in_report: int = 5000


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "text"  # "text" | "json"


@dataclass
class AppConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def to_dict(self, include_secrets: bool = False) -> dict[str, Any]:
        """Serialize the config. Secrets are excluded unless explicitly asked.

        Even with ``include_secrets=True`` the API key is replaced by a
        presence flag, so a report can record *whether* a key was configured
        without storing the key itself.
        """
        data = asdict(self)
        if not include_secrets:
            data["ai"]["api_key"] = None
        else:
            data["ai"]["api_key_set"] = bool(self.ai.api_key)
            data["ai"]["api_key"] = None
        return data


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_section(section_obj: Any, values: dict) -> None:
    for key, value in values.items():
        if hasattr(section_obj, key):
            setattr(section_obj, key, value)


def load_config(
    config_path: Optional[str | Path] = None,
    overrides: Optional[dict[str, Any]] = None,
    env: Optional[dict[str, str]] = None,
) -> AppConfig:
    """Build an :class:`AppConfig` from file, environment, and overrides."""
    environ = env if env is not None else os.environ
    config = AppConfig()

    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path, "r", encoding="utf-8") as handle:
            file_data = yaml.safe_load(handle) or {}
        if not isinstance(file_data, dict):
            raise ValueError(f"Config file {path} must contain a YAML mapping at the top level.")
        for section in ("capture", "analysis", "ai", "privacy", "report", "logging"):
            section_values = file_data.get(section)
            if isinstance(section_values, dict):
                _apply_section(getattr(config, section), section_values)

    # Environment overrides for secrets and provider selection.
    if environ.get(ENV_AI_API_KEY):
        config.ai.api_key = environ[ENV_AI_API_KEY]
    if environ.get(ENV_AI_BASE_URL):
        config.ai.base_url = environ[ENV_AI_BASE_URL]
    if environ.get(ENV_AI_MODEL):
        config.ai.model = environ[ENV_AI_MODEL]
    if environ.get(ENV_AI_PROVIDER):
        config.ai.provider = environ[ENV_AI_PROVIDER]

    if overrides:
        for section in ("capture", "analysis", "ai", "privacy", "report", "logging"):
            section_values = overrides.get(section)
            if isinstance(section_values, dict):
                _apply_section(getattr(config, section), section_values)

    validate_config(config)
    return config


def validate_config(config: AppConfig) -> None:
    """Fail fast on values that would produce meaningless analysis."""
    if config.capture.batch_size <= 0:
        raise ValueError("capture.batch_size must be greater than 0.")
    if config.capture.max_packets is not None and config.capture.max_packets <= 0:
        raise ValueError("capture.max_packets must be greater than 0 when set.")
    if config.analysis.flow_idle_timeout <= 0:
        raise ValueError("analysis.flow_idle_timeout must be greater than 0.")
    if config.analysis.scan_window_seconds <= 0:
        raise ValueError("analysis.scan_window_seconds must be greater than 0.")
    if config.ai.timeout_seconds <= 0:
        raise ValueError("ai.timeout_seconds must be greater than 0.")
    if config.ai.max_retries < 0:
        raise ValueError("ai.max_retries must be 0 or greater.")
    if config.ai.language not in ("en", "ar"):
        raise ValueError("ai.language must be 'en' or 'ar'.")
    if config.logging.level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ValueError(f"Unsupported logging level: {config.logging.level}")
    for fmt in config.report.formats:
        if fmt not in ("json", "html"):
            raise ValueError(f"Unsupported report format: {fmt}")
