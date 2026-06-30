"""
VulnScan
Main application entry point.

Author: OOI JIAN XIN

Project:
VulnScan - Intelligent Web Application Vulnerability Assessment Platform
"""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>Welcome to VulnScan 🚀</h1>
    <h2>Development Environment Successfully Configured</h2>
    <p>Your Final Year Project officially starts here.</p>
    """


if __name__ == "__main__":
    app.run(debug=True)