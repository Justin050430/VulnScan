"""Production configuration must fail closed."""
import importlib
import os

import pytest


@pytest.fixture
def reloaded_config(monkeypatch):
    """Reload the config module under a controlled environment."""
    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: None)

    def _load(**env):
        for key in ("SCANNER_ALLOW_PRIVATE_TARGETS", "TRUST_BOUNDARY_MODE"):
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        import config

        return importlib.reload(config)

    yield _load

    monkeypatch.undo()
    import config

    importlib.reload(config)

def test_production_blocks_private_targets_when_setting_absent(reloaded_config):
    config = reloaded_config()

    assert config.ProductionConfig.SCANNER_ALLOW_PRIVATE_TARGETS is False
    assert config.ProductionConfig.TRUST_BOUNDARY_MODE == "enforce"


def test_production_honours_explicit_private_target_opt_in(reloaded_config):
    config = reloaded_config(SCANNER_ALLOW_PRIVATE_TARGETS="true")

    assert config.ProductionConfig.SCANNER_ALLOW_PRIVATE_TARGETS is True


def test_development_still_allows_local_targets(reloaded_config):
    config = reloaded_config()

    assert config.DevelopmentConfig.SCANNER_ALLOW_PRIVATE_TARGETS is True


def test_private_target_guard_still_rejects_loopback_in_production_mode(monkeypatch):
    from app.scanner.safety import check_target_allowed

    ok, reason = check_target_allowed("http://127.0.0.1:5001/", allow_private=False)
    assert ok is False
    assert "Loopback" in reason

    ok, reason = check_target_allowed("http://169.254.169.254/latest/meta-data/", allow_private=False)
    assert ok is False
