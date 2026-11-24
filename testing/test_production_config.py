"""Production safety defaults with and without an explicit environment setting."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest


def _load_config(monkeypatch, setting):
    if setting is None:
        monkeypatch.delenv("SCANNER_ALLOW_PRIVATE_TARGETS", raising=False)
    else:
        monkeypatch.setenv("SCANNER_ALLOW_PRIVATE_TARGETS", setting)

    # Keep the test independent of developer-specific .env files.
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: None)
    path = Path(__file__).resolve().parents[1] / "backend" / "config.py"
    spec = spec_from_file_location("production_config_under_test", path)
    assert spec is not None and spec.loader is not None
    config = module_from_spec(spec)
    spec.loader.exec_module(config)
    return config


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        pytest.param(None, False, id="unset"),
        pytest.param("", False, id="empty"),
        pytest.param("typo", False, id="invalid"),
        pytest.param("false", False, id="disabled"),
        pytest.param("true", True, id="explicit-opt-in"),
    ],
)
def test_production_private_target_setting(monkeypatch, setting, expected):
    config = _load_config(monkeypatch, setting)
    assert config.ProductionConfig.SCANNER_ALLOW_PRIVATE_TARGETS is expected


def test_local_configs_allow_private_targets_by_default(monkeypatch):
    config = _load_config(monkeypatch, None)
    assert config.DevelopmentConfig.SCANNER_ALLOW_PRIVATE_TARGETS is True
    assert config.TestingConfig.SCANNER_ALLOW_PRIVATE_TARGETS is True
