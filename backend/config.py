"""
VulnScan application configuration.

Secrets and environment-specific values are read from environment variables
(optionally loaded from a .env file) and are never hard-coded.
"""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

# Project root = backend/ (parent of this file)
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from backend/.env (and repo root .env)
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR.parent / ".env")


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _default_mssql_url():
    """Build the default local Microsoft SQL Server (LocalDB) connection URL."""
    server = os.getenv("MSSQL_SERVER", r"(localdb)\MSSQLLocalDB")
    database = os.getenv("MSSQL_DATABASE", "VulnScan")
    driver = os.getenv("MSSQL_DRIVER", "ODBC Driver 17 for SQL Server")
    if os.getenv("MSSQL_USERNAME"):
        user = os.getenv("MSSQL_USERNAME")
        pwd = os.getenv("MSSQL_PASSWORD", "")
        return (
            f"mssql+pyodbc://{user}:{pwd}@{server}/{database}"
            f"?driver={driver.replace(' ', '+')}&Encrypt=no&TrustServerCertificate=yes"
        )
    return (
        f"mssql+pyodbc://@{server}/{database}"
        f"?driver={driver.replace(' ', '+')}&trusted_connection=yes&Encrypt=no&TrustServerCertificate=yes"
    )


class Config:
    """Base configuration shared by all environments."""

    # ---------------------------------------------------------------- Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me-in-production")

    # ---------------------------------------------------------------- Database
    # Priority: explicit DATABASE_URL > derived MS SQL Server URL.
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or _default_mssql_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    # ---------------------------------------------------------------- JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", str(60 * 60)))
    )
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_TYPE = "Bearer"
    JWT_ERROR_MESSAGE_KEY = "message"
    JWT_IDENTITY_CLAIM = "sub"

    # ---------------------------------------------------------------- Google OAuth 2.0
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI = os.getenv(
        "GOOGLE_REDIRECT_URI", "http://localhost:5000/api/auth/google/callback"
    )
    GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo"

    # ---------------------------------------------------------------- Scanner
    SCANNER_DEFAULT_TIMEOUT = float(os.getenv("SCANNER_TIMEOUT", "10"))
    SCANNER_MAX_PAGES_DEFAULT = int(os.getenv("SCANNER_MAX_PAGES", "30"))
    SCANNER_MAX_DEPTH_DEFAULT = int(os.getenv("SCANNER_MAX_DEPTH", "2"))
    SCANNER_REQUEST_DELAY_MS_DEFAULT = int(os.getenv("SCANNER_REQUEST_DELAY_MS", "200"))
    # Protect against SSRF: block scanning of private/loopback networks unless
    # explicitly permitted for local development/testing.
    SCANNER_ALLOW_PRIVATE_TARGETS = _as_bool(os.getenv("SCANNER_ALLOW_PRIVATE_TARGETS", "true"))
    # Opt-in, bounded time-based SQLi probes (slow; off by default).
    SCANNER_ENABLE_TIME_BASED = _as_bool(os.getenv("SCANNER_ENABLE_TIME_BASED", "false"))
    # Run scans in a background worker thread (async). Set false for tests.
    SCAN_ASYNC = _as_bool(os.getenv("SCAN_ASYNC", "true"))
    # Startup recovery: fail scans orphaned by a previous process (F1).
    SCANNER_RECOVER_ORPHAN_SCANS = _as_bool(
        os.getenv("SCANNER_RECOVER_ORPHAN_SCANS", "true")
    )
    # Concurrency caps for active (Pending/Running) scans (F2); 0 disables.
    SCAN_MAX_ACTIVE_PER_USER = int(os.getenv("SCAN_MAX_ACTIVE_PER_USER", "3"))
    SCAN_MAX_ACTIVE_GLOBAL = int(os.getenv("SCAN_MAX_ACTIVE_GLOBAL", "5"))

    # ---------------------------------------------------------------- Misc
    AUDIT_LOG_ENABLED = True
    JSON_SORT_KEYS = False


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = False
    # In-memory SQLite for the automated test-suite (models are DB-agnostic).
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite://")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    WTF_CSRF_ENABLED = False
    # Run scans synchronously so tests are deterministic.
    SCAN_ASYNC = False
    SCANNER_ALLOW_PRIVATE_TARGETS = True
    # Tests must be hermetic: never pick up real Google credentials from a
    # developer's .env. Tests that need them (e.g. the OAuth flow tests) set
    # them explicitly on the app fixture.
    GOOGLE_CLIENT_ID = ""
    GOOGLE_CLIENT_SECRET = ""


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Require explicit secrets in production (enforced in create_app).
    REQUIRE_SECRET = True
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "") or SECRET_KEY


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(name=None):
    name = name or os.getenv("FLASK_ENV", "development")
    return config_by_name.get(name, config_by_name["default"])
