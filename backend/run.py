"""
VulnScan development entry point.

Usage:
    python run.py
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 5000
    app.run(host=host, port=port, debug=True)
