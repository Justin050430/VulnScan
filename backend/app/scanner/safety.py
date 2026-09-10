"""Scan-target safety guards (anti-SSRF and scope controls)."""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger("vulnscan.safety")


def _is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def check_target_allowed(target_url, allow_private=True):
    """
    Returns (ok, reason).  Ensures the scanner only ever contacts hosts that
    are permitted by configuration (SSRF protection).
    """
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "Target URL has no host."

    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        if allow_private:
            return True, ""
        return False, "Loopback targets are disabled by configuration."

    # Direct IP literal
    try:
        ip = ipaddress.ip_address(host)
        if _is_private_ip(str(ip)) and not allow_private:
            return False, "Private IP targets are disabled by configuration."
        return True, ""
    except ValueError:
        pass

    # Hostname - resolve and inspect addresses.
    if not allow_private:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False, "Could not resolve target hostname."
        for info in infos:
            addr = info[4][0]
            if _is_private_ip(addr):
                return (
                    False,
                    "Target hostname resolves to a private/loopback address, "
                    "which is disabled by configuration.",
                )
    return True, ""
