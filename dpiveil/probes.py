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
import logging
import os
import socket
import ssl
import subprocess
from pathlib import Path
from urllib.parse import quote


_LOGGER = logging.getLogger("dpiveil.probes")


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


def _curl_doh_request(server, path, timeout):
    """Retry a DoH request with Windows curl/Schannel after Python cert errors."""
    windows_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    curl_exe = str(Path(windows_root) / "System32" / "curl.exe") if windows_root else "curl.exe"
    command = [
        curl_exe,
        "--disable",  # Ignore user curl config files; TLS verification stays enabled.
        "--silent",
        "--show-error",
        "--http1.1",
        "--connect-timeout", str(max(1, int(timeout))),
        "--max-time", str(max(1, int(timeout))),
        "--resolve", f"cloudflare-dns.com:443:{server}",
        "--header", "Accept: application/dns-json",
        "--write-out", "\\n%{http_code}",
        f"https://cloudflare-dns.com{path}",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=max(2, float(timeout) + 2),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"curl.exe DoH request failed: {exc}") from exc

    output = result.stdout or b""
    if result.returncode != 0:
        detail = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        raise OSError(
            f"curl.exe DoH request failed ({result.returncode}): "
            f"{detail or 'no error details'}"
        )

    body, separator, status_text = output.rpartition(b"\n")
    if not separator or not status_text.isdigit():
        raise ValueError("curl.exe DoH response did not include an HTTP status")
    status = int(status_text)
    if status != 200:
        raise ValueError(f"curl.exe DoH returned HTTP status {status}")
    return status, body


def resolve_verified(host, timeout, max_ips):
    # DoH's own TLS identity is verified even though system DNS is poisoned.
    # Only a Python certificate-chain verification failure triggers curl: other
    # network/TLS errors keep the original retry behavior and are not masked.
    last_error = None
    for server in ("1.1.1.1", "1.0.0.1"):
        method = "Python HTTPS"
        try:
            path = f"/dns-query?name={quote(host, safe='')}&type=A"
            try:
                status, body = https_request(
                    "cloudflare-dns.com", server, path, timeout,
                    accept="application/dns-json",
                )
            except ssl.SSLCertVerificationError as python_error:
                _LOGGER.warning(
                    "Python DoH TLS certificate verification failed via %s: %s; "
                    "retrying with curl.exe (certificate verification remains enabled).",
                    server,
                    python_error,
                )
                try:
                    status, body = _curl_doh_request(server, path, timeout)
                    method = "curl.exe"
                except (OSError, ValueError) as curl_error:
                    last_error = RuntimeError(
                        f"Python TLS certificate verification failed: {python_error}; "
                        f"curl.exe fallback failed: {curl_error}"
                    )
                    _LOGGER.error(
                        "DoH failed via %s: Python certificate verification failed (%s); "
                        "curl.exe fallback failed (%s).",
                        server,
                        python_error,
                        curl_error,
                    )
                    continue

            data = json.loads(body)
            if status != 200 or data.get("Status") != 0:
                raise ValueError("DoH returned no successful DNS answer")
            addresses = sorted({entry["data"] for entry in data.get("Answer", [])
                                if entry.get("type") == 1 and
                                ipaddress.ip_address(entry["data"]).version == 4},
                               key=ipaddress.ip_address)
            if addresses:
                if method == "curl.exe":
                    _LOGGER.info("curl.exe DoH fallback returned a verified DNS answer via %s.", server)
                return addresses[:max_ips]
            raise ValueError("No IPv4 A records")
        except (OSError, ssl.SSLError, ValueError, KeyError) as exc:
            last_error = exc
            if method == "Python HTTPS":
                _LOGGER.warning("Python DoH request failed via %s: %s", server, exc)
            else:
                _LOGGER.warning("curl.exe DoH response was invalid via %s: %s", server, exc)
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
