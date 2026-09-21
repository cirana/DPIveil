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


DEFAULT_HEALTH_CHECKS = (
    ("web", "discord.com", "/", "http"),
)

DEFAULT_ACTIVE_DOMAINS = (
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "discordcdn.com",
    "discord.dev",
    "discord.new",
    "discord.gift",
    "discordstatus.com",
    "dis.gd",
    "discord.co",
    "discord-attachments-uploads-prd.storage.googleapis.com",
)


@dataclass(frozen=True)
class AutoConfig:
    host: str
    timeout: float
    max_ips: int
    candidates: tuple[Candidate, ...]
    health_checks: tuple[tuple[str, str, str, str], ...] = DEFAULT_HEALTH_CHECKS

    @classmethod
    def from_options(cls, options):
        host = options.get("host", "discord.com")
        timeout = options.get("timeout", 6)
        max_ips = options.get("max_ips", 2)
        rows = options.get("candidates", [])
        checks = options.get("health_checks")
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

        parsed_checks = DEFAULT_HEALTH_CHECKS
        if checks is not None:
            if not isinstance(checks, list) or not checks:
                raise ValueError("health_checks must be a non-empty list")
            parsed = []
            for row in checks:
                if not isinstance(row, dict):
                    raise ValueError("health_checks entries must be objects")
                name = row.get("name")
                check_host = row.get("host")
                path = row.get("path", "/")
                kind = row.get("kind", "http")
                if (not isinstance(name, str) or not name or
                        not isinstance(check_host, str) or not check_host or not check_host.isascii() or
                        not isinstance(path, str) or not path.startswith("/") or
                        kind not in {"http", "json", "websocket"}):
                    raise ValueError("Invalid health check")
                parsed.append((name, check_host.lower(), path, kind))
            if len({row[0] for row in parsed}) != len(parsed):
                raise ValueError("Health check names must be unique")
            parsed_checks = tuple(parsed)

        return cls(host.lower(), float(timeout), max_ips, candidates, parsed_checks)


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


def https_request(host, address, path, timeout, on_connected=None, accept=None, headers=None):
    connection = DirectHTTPSConnection(host, address, timeout, on_connected)
    try:
        request_headers = dict(headers or {})
        if accept:
            request_headers["Accept"] = accept
        connection.request("GET" if accept or headers else "HEAD", path, headers=request_headers)
        response = connection.getresponse()
        if not 200 <= response.status < 500:
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
    )
    if status not in (101, 400, 401, 403, 404, 426):
        raise ValueError(f"Unexpected gateway HTTP status: {status}")
    return status, body


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

    def __init__(self, host, active_domains=DEFAULT_ACTIVE_DOMAINS):
        self.host = host
        self.active_domains = tuple(active_domains)
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
        domains = self.active_domains if active else (self.host,)
        output = list(CandidateStrategy(candidate, domains).process(packet))
        if not active and len(output) > 1:
            with self._lock:
                if self._candidate == candidate and self._port == port:
                    self._applied = True
        return output


def _check_probe(kind, host, address, path, timeout, on_connected=None, probe=https_request):
    if kind == "websocket":
        return websocket_probe(host, address, path, timeout, on_connected)
    accept = "application/json" if kind == "json" else None
    return probe(host, address, path, timeout, on_connected=on_connected, accept=accept)


def _endpoint_addresses(config, logger):
    resolved = {}
    for _, host, _, _ in config.health_checks:
        if host in resolved:
            continue
        try:
            resolved[host] = resolve_verified(host, config.timeout, config.max_ips)
        except Exception as exc:
            logger.warning("Health DNS | %s | failed: %s", host, exc)
            resolved[host] = []
    return resolved


def health_check_direct(config, logger):
    resolved = _endpoint_addresses(config, logger)
    results = {}
    for name, host, path, kind in config.health_checks:
        ok = False
        for ip in resolved.get(host, []):
            try:
                status, _ = _check_probe(kind, host, ip, path, config.timeout)
                logger.info("Direct health | %s | %s | %s | status=%s", name, host, ip, status)
                ok = True
                break
            except Exception as exc:
                logger.info("Direct health | %s | %s | %s | failed: %s", name, host, ip, exc)
        results[name] = ok
    return all(results.values()), results


def direct_works(config, addresses, logger, probe=https_request):
    # Keep compatibility for existing tests/callers; the app now uses health_check_direct.
    success = False
    for ip in addresses:
        try:
            status, _ = probe(config.host, ip, "/", config.timeout)
            logger.info("Direct HTTPS | %s | verified status=%s", ip, status)
            success = True
        except Exception as exc:
            logger.info("Direct HTTPS | %s | failed: %s", ip, exc)
    return success


def test_candidates(config, session, logger, addresses=None, probe=https_request):
    endpoint_addresses = {config.host: addresses or resolve_verified(config.host, config.timeout, config.max_ips)}
    results = {}
    details = {}

    for candidate in config.candidates:
        endpoint_results = {}
        for name, host, path, kind in (("web", config.host, "/", "http"),):
            ok = False
            failures = []
            ips = endpoint_addresses.get(host, [])
            for ip in ips:
                session.set_probe(candidate)
                try:
                    status, _ = _check_probe(
                        kind, host, ip, path, config.timeout,
                        on_connected=lambda port, c=candidate: session.set_probe(c, port),
                        probe=probe,
                    )
                    if not session.probe_applied():
                        raise ValueError("Candidate did not alter the probe ClientHello")
                    logger.info(
                        "Health probe | %s | %s | %s | %s | status=%s",
                        candidate.name, name, host, ip, status,
                    )
                    ok = True
                    break
                except Exception as exc:
                    failures.append(str(exc))
                    logger.warning(
                        "Health probe | %s | %s | %s | %s | failed: %s",
                        candidate.name, name, host, ip, exc,
                    )
                finally:
                    session.set_probe(None)

            endpoint_results[name] = ok
            if not ok and not ips:
                failures.append("no verified IPv4 address")
            if failures and not ok:
                logger.warning("Health result | %s | %s | FAIL | %s",
                               candidate.name, name, "; ".join(failures[:2]))
            else:
                logger.info("Health result | %s | %s | OK", candidate.name, name)

        passed = sum(endpoint_results.values())
        required = len(config.health_checks)
        results[candidate.name] = passed
        details[candidate.name] = endpoint_results
        logger.info(
            "Candidate %s: %s/%s Discord health checks passed",
            candidate.name, passed, required,
        )

    working = [c for c in config.candidates
               if results[c.name] == 1]
    if not working:
        logger.error("No candidate passed all Discord health checks; no strategy selected.")
        return None, details

    selected = min(working, key=lambda c: (c.priority, c.name))
    session.activate(selected)
    logger.info("Selected session strategy: %s", selected.name)
    return selected, details
