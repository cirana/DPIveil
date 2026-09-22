"""Certificate-checked HTTPS, WebSocket, QUIC and DNS probes.

This module contains the network-facing pieces used by automatic strategy
selection.  It deliberately keeps the existing TLS context and HTTP status
checks intact: callers never get a successful result from a mere TCP connect,
and certificate verification is never disabled.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
from urllib.parse import quote


class DirectHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a verified DNS IP while retaining host SNI and certificate checks."""

    def __init__(self, host, address, timeout, on_connected=None):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address
        self.on_connected = on_connected

    def connect(self):
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            if self.on_connected:
                self.on_connected(raw.getsockname()[1])
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def https_request(
    host,
    address,
    path,
    timeout,
    on_connected=None,
    accept=None,
    headers=None,
    allowed_statuses=None,
):
    connection = DirectHTTPSConnection(host, address, timeout, on_connected)
    try:
        request_headers = dict(headers or {})
        if accept:
            request_headers["Accept"] = accept
        connection.request("GET" if accept or headers else "HEAD", path, headers=request_headers)
        response = connection.getresponse()
        if allowed_statuses is not None:
            valid_status = response.status in allowed_statuses
        else:
            valid_status = 200 <= response.status < 500
        if not valid_status:
            raise ValueError(f"Invalid HTTP status: {response.status}")
        return response.status, response.read(65536) if accept or headers else b""
    finally:
        connection.close()


def websocket_probe(host, address, path, timeout, on_connected=None):
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    status, body = https_request(
        host, address, path, timeout, on_connected=on_connected,
        headers={
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            "User-Agent": "DPIveil/health-check",
        },
        allowed_statuses={101, 400, 401, 403, 404, 426},
    )
    return status, body


def quic_request(host, address, path, timeout, on_connected=None):
    """Perform a real certificate-checked HTTP/3 request with curl.

    Windows 10/11 ships curl with Schannel certificate validation.  The
    command intentionally does not pass ``--insecure``/``-k``; an unsupported
    HTTP/3 build simply makes this candidate fail and lets the selector try
    the remaining candidates.
    """
    del on_connected  # kept for the same probe callback shape as HTTPS
    command = [
        "curl.exe",
        "--http3-only",
        "--silent",
        "--show-error",
        "--connect-timeout", str(max(1, int(timeout))),
        "--max-time", str(max(1, int(timeout))),
        "--resolve", f"{host}:443:{address}",
        "--output", "NUL",
        "--write-out", "%{http_code}",
        f"https://{host}{path}",
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=max(2, float(timeout) + 2),
        check=False,
    )
    output = (result.stdout or "").strip()
    try:
        status = int(output[-3:])
    except (ValueError, TypeError):
        status = 0
    if result.returncode != 0 or not 200 <= status < 500:
        detail = (result.stderr or output or "curl HTTP/3 failed").strip()
        raise OSError(f"HTTP/3 probe failed ({result.returncode}, status={status}): {detail}")
    return status, b""


def resolve_verified(host, timeout, max_ips):
    # DoH's own TLS identity is verified even though system DNS is poisoned.
    last_error = None
    for server in ("1.1.1.1", "1.0.0.1"):
        try:
            status, body = https_request(
                "cloudflare-dns.com", server,
                f"/dns-query?name={quote(host, safe='')}&type=A", timeout,
                accept="application/dns-json",
            )
            data = json.loads(body)
            if status != 200 or data.get("Status") != 0:
                raise ValueError("DoH returned no successful DNS answer")
            addresses = sorted({entry["data"] for entry in data.get("Answer", [])
                                if entry.get("type") == 1 and
                                ipaddress.ip_address(entry["data"]).version == 4},
                               key=ipaddress.ip_address)
            if addresses:
                return addresses[:max_ips]
            raise ValueError("No IPv4 A records")
        except (OSError, ssl.SSLError, ValueError, KeyError) as exc:
            last_error = exc
    raise RuntimeError(f"Verified DNS unavailable: {last_error}")


def resolve_system(host, max_ips):
    addresses = {result[4][0] for result in socket.getaddrinfo(
        host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)}
    return sorted(addresses, key=ipaddress.ip_address)[:max_ips]


def check_probe(kind, host, address, path, timeout, on_connected=None, probe=https_request):
    if kind == "websocket":
        return websocket_probe(host, address, path, timeout, on_connected)
    accept = "application/json" if kind == "json" else None
    return probe(host, address, path, timeout, on_connected=on_connected, accept=accept)


