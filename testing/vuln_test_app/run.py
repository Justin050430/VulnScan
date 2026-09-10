"""Run the VulnScan controlled vulnerable test application (local only)."""
from app import app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
