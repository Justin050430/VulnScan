"""
WSGI entry point for production hosts (e.g. Azure App Service / Gunicorn).

The application object is exposed as `app`.  Production configuration is
selected via the FLASK_ENV environment variable (default: production).
"""
import os

from app import create_app

app = create_app(os.getenv("FLASK_ENV", "production"))
