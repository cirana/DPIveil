"""Verified HTTPS probing and session-scoped strategy selection."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
from urllib.parse import quote
from dataclasses import dataclass

from dpiveil.strategies.candidates import Candidate, CandidateStrategy


@dataclass(frozen=True)
class AutoConfig:
    host: str
    timeout: float
    max_ips: int
    candidates: tuple[Candidate, ...]

    @classmethod
    def from_options(cls, options):
        host = options.get("host", "discord.com")
        timeout = options.get("timeout", 6)
        max_ips = options.get("max_ips", 2)
        rows = options.get("candidates", [])
        if (not isinstance(host, str) or not host or not host.isascii() or
                not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                not 1 <= timeout <= 30 or not isinstance(max_ips, int) or
                isinstance(max_ips, bool) or not 1 <= max_ips <= 10 or
                not isinstance(rows, list)):
            raise ValueError("Invalid auto strategy settings")
        candidates = tuple(Candidate(**row) for row in rows)
        if not candidates or len({c.name for c in candidates}) != len(candidates):
            raise ValueError("Provide unique candidate names")
        for candidate in candidates:
            CandidateStrategy(candidate, host)
        return cls(host, float(timeout), max_ips, candidates)


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


def https_request(host, address, path, timeout, on_connected=None, accept=None):
    connection = DirectHTTPSConnection(host, address, timeout, on_connected)
    try:
        headers = {"Accept": accept} if accept else {}
        connection.request("GET" if accept else "HEAD", path, headers=headers)
        response = connection.getresponse()
        if not 200 <= response.status < 500:
            raise ValueError(f"Invalid HTTP status: {response.status}")
        return response.status, response.read(65536) if accept else b""
    finally:
        connection.close()


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


class SessionStrategy:
    name = "auto"

    def __init__(self, host):
        self.host = host
        self._lock = threading.Lock()
        self._candidate = None
        self._port = None
        self._active = False
        self._applied = False

    def set_probe(self, candidate, port=None):
        with self._lock:
            self._candidate = candidate
            self._port = port
            self._active = False
            self._applied = False

    def probe_applied(self):
        with self._lock:
            return self._applied

    def activate(self, candidate):
        with self._lock:
            self._candidate = candidate
            self._port = None
            self._active = True
            self.name = candidate.name

    def process(self, packet):
        with self._lock:
            candidate, port, active = self._candidate, self._port, self._active
        if candidate is None or packet.tcp is None or (not active and packet.tcp.src_port != port):
            return [packet]
        output = list(CandidateStrategy(candidate, self.host).process(packet))
        if not active and len(output) > 1:
            with self._lock:
                if self._candidate == candidate and self._port == port:
                    self._applied = True
        return output


def direct_works(config, addresses, logger, probe=https_request):
    success = False
    for ip in addresses:
        try:
            status, _ = probe(config.host, ip, "/", config.timeout)
            logger.info("Direct HTTPS | %s | verified status=%s", ip, status)
            success = True
        except Exception as exc:
            logger.info("Direct HTTPS | %s | failed: %s", ip, exc)
    return success


def test_candidates(config, session, logger, addresses, probe=https_request):
    results = {}
    for candidate in config.candidates:
        outcomes = []
        for ip in addresses:
            session.set_probe(candidate)
            try:
                status, _ = probe(config.host, ip, "/", config.timeout,
                                  on_connected=lambda port: session.set_probe(candidate, port))
                if not session.probe_applied():
                    raise ValueError("Candidate did not alter the probe ClientHello")
                logger.info("Probe | %s | %s | verified HTTPS status=%s", candidate.name, ip, status)
                outcomes.append(True)
            except Exception as exc:
                logger.warning("Probe | %s | %s | failed: %s", candidate.name, ip, exc)
                outcomes.append(False)
            finally:
                session.set_probe(None)
        results[candidate.name] = sum(outcomes)
        logger.info("Candidate %s: %s/%s verified HTTPS responses", candidate.name, sum(outcomes), len(addresses))
    working = [c for c in config.candidates if results[c.name] > 0]
    if not working:
        logger.error("No candidate produced verified HTTPS; no strategy selected.")
        return None, results
    selected = min(working, key=lambda c: (-results[c.name], c.priority, c.name))
    session.activate(selected)
    logger.info("Selected session strategy: %s", selected.name)
    return selected, results
