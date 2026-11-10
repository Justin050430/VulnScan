"""Run the VulnScan controlled vulnerable test application (local only).

Bound on both IPv4 and IPv6 loopback so a target registered under the exact
hostname ``localhost`` responds immediately instead of paying an IPv6
fallback penalty on every scanner request.
"""
import threading

from werkzeug.serving import make_server

from app import app

PORT = 5001


def main():
    servers = []
    for host in ("127.0.0.1", "::1"):
        try:
            servers.append(make_server(host, PORT, app))
        except OSError:
            continue  # e.g. IPv6 loopback unavailable
    if not servers:
        raise SystemExit(f"could not bind 127.0.0.1/::1 on port {PORT}")
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Test shop on http://localhost:{PORT}/ (INTENTIONALLY VULNERABLE, local only)")
    print(f"Publish a verification challenge at "
          f"http://localhost:{PORT}/__test__/verification")
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
