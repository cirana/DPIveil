"""Verified HTTPS probing and session-scoped strategy selection."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import subprocess
import threading
from urllib.parse import quote
from dataclasses import dataclass

from dpiveil.classifier import classify_packet
from dpiveil.constants import DISCORD_DOMAINS
from dpiveil.strategies.candidates import Candidate, CandidateStrategy


DEFAULT_HEALTH_CHECKS = (
    ("web", "discord.com", "/", "http"),
    ("updates", "updates.discord.com", "/", "http"),
    ("gateway", "gateway.discord.gg", "/?v=10&encoding=json", "websocket"),
)


@dataclass(frozen=True)
class AutoConfig:
    host: str
    timeout: float
    max_ips: int
    candidates: tuple[Candidate, ...]
    health_checks: tuple[tuple[str, str, str, str], ...] = DEFAULT_HEALTH_CHECKS
    candidate_timeout: float | None = None

    @classmethod
    def from_options(cls, options):
        host = options.get("host", "discord.com")
        timeout = options.get("timeout", 6)
        max_ips = options.get("max_ips", 2)
        candidate_timeout = options.get("candidate_timeout", min(float(timeout), 4.0))
        rows = options.get("candidates", [])
        checks = options.get("health_checks")
        if (not isinstance(host, str) or not host or not host.isascii() or
                not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                not 1 <= timeout <= 30 or not isinstance(max_ips, int) or
                isinstance(max_ips, bool) or not 1 <= max_ips <= 10 or
                not isinstance(candidate_timeout, (int, float)) or
                isinstance(candidate_timeout, bool) or not 1 <= candidate_timeout <= timeout or
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

        return cls(
            host.lower(), float(timeout), max_ips, candidates, parsed_checks,
            float(candidate_timeout),
        )


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


class SessionStrategy:
    name = "auto"

    def __init__(self, host, active_domains=DISCORD_DOMAINS):
        self.host = host
        self.active_domains = tuple(active_domains)
        self._lock = threading.Lock()
        self._candidate = None
        self._port = None
        self._probe_addresses = set()
        self._probe_host = host
        self._active = False
        self._applied = False
        self._tracked_ips = set()

    def set_probe(self, candidate, port=None, host=None, addresses=None):
        with self._lock:
            self._candidate = candidate
            self._port = port
            if host is not None:
                self._probe_host = host
            self._probe_addresses = {str(address) for address in (addresses or ())}
            self._active = False
            self._applied = False

    def bind_probe(self, candidate, port, host=None):
        """Bind a TCP probe's ephemeral port without resetting SYN results."""
        with self._lock:
            if self._candidate != candidate or self._active:
                return
            self._port = port
            if host is not None:
                self._probe_host = host

    def probe_applied(self):
        with self._lock:
            return self._applied

    def _matches_active_domain(self, host):
        hostname = (host or "").lower().rstrip(".")
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in self.active_domains
        )

    def record_dns_answer(self, host, addresses):
        if not self._matches_active_domain(host):
            return
        with self._lock:
            before = len(self._tracked_ips)
            self._tracked_ips.update(str(address) for address in addresses)
            added = len(self._tracked_ips) - before
        if added:
            # Keep this intentionally low-volume; the app log already shows packet details.
            pass

    def protects_ip(self, address):
        with self._lock:
            return self._active and str(address) in self._tracked_ips

    def activate(self, candidate):
        with self._lock:
            self._candidate = candidate
            self._port = None
            self._probe_addresses = set()
            self._active = True
            self.name = candidate.name

    def process(self, packet):
        with self._lock:
            candidate = self._candidate
            port = self._port
            active = self._active
            probe_host = self._probe_host
            probe_addresses = set(self._probe_addresses)
        if candidate is None:
            return [packet]

        destination = str(getattr(packet, "dst_addr", ""))
        learned_from_sni = False
        if candidate.transport == "udp":
            udp = getattr(packet, "udp", None)
            if (
                udp is None
                or bool(getattr(packet, "is_inbound", False))
                or int(getattr(udp, "dst_port", 0)) != 443
                or (not active and probe_addresses and destination not in probe_addresses)
                or (active and self._tracked_ips and not self.protects_ip(destination))
            ):
                return [packet]
        else:
            tcp = getattr(packet, "tcp", None)
            if tcp is None or bool(getattr(packet, "is_inbound", False)):
                return [packet]
            # syndata acts on the SYN before an ephemeral port is available;
            # other TCP candidates are bound to the HTTPS probe port.
            is_syn_data = candidate.canonical_kind == "syndata" and bool(getattr(tcp, "syn", False))
            if not active and not is_syn_data and tcp.src_port != port:
                return [packet]
            if not active and probe_addresses and destination not in probe_addresses:
                return [packet]
            if active and self._tracked_ips and not self.protects_ip(destination):
                # Discord CDN addresses can rotate after the initial DNS seed.
                # A TLS ClientHello carries the authoritative hostname, so
                # learn a new address from a matching SNI before applying the
                # selected strategy.  This prevents updates.discord.com (and
                # similar endpoints) from falling back to an unmodified first
                # ClientHello and waiting for repeated TCP resets.
                info = classify_packet(packet)
                if not (info.is_tls_client_hello and self._matches_active_domain(info.sni)):
                    return [packet]
                with self._lock:
                    if self._active:
                        self._tracked_ips.add(destination)
                learned_from_sni = True

        domains = self.active_domains if active else (probe_host,)
        strategy = CandidateStrategy(candidate, domains)
        force_ip = (
            active
            and not learned_from_sni
            and self.protects_ip(destination)
            and candidate.canonical_kind in {"multisplit", "multidisorder", "fake_badseq"}
        )
        output = list(strategy.process(packet, force_ip=force_ip))
        changed = len(output) > 1
        if len(output) == 1:
            outgoing = output[0]
            changed = (
                bytes(getattr(outgoing, "payload", b"") or b"")
                != bytes(getattr(packet, "payload", b"") or b"")
                or getattr(getattr(outgoing, "tcp", None), "seq_num", None)
                != getattr(getattr(packet, "tcp", None), "seq_num", None)
                or bytes(getattr(outgoing, "raw", b"") or b"")
                != bytes(getattr(packet, "raw", b"") or b"")
            )
        if not active and changed:
            with self._lock:
                if self._candidate == candidate:
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
            # One verified normal connection is sufficient to leave the
            # packet engine in pass-through mode.  Do not wait on the other
            # addresses after this path has already succeeded.
            break
        except Exception as exc:
            logger.info("Direct HTTPS | %s | failed: %s", ip, exc)
    return success


def test_candidates(
    config,
    session,
    logger,
    addresses=None,
    probe=https_request,
    quic_probe=quic_request,
):
    """Test every candidate, then select the best verified result.

    TCP candidates require a completed certificate-checked HTTPS response.
    The UDP candidate uses curl's certificate-checked HTTP/3 path.  A packet
    being intercepted or a socket merely connecting is never considered a
    success.  Testing continues after failures and after the first success so
    the deterministic priority ordering can be compared at the end.
    """
    ips = addresses or resolve_verified(config.host, config.timeout, config.max_ips)
    # Candidate probes deliberately have a tighter bound than DNS and normal
    # HTTPS checks.  A failed strategy must not hold startup for the full
    # resolver timeout, while successful probes still require a complete,
    # certificate-checked response.
    probe_timeout = config.candidate_timeout or min(config.timeout, 4.0)
    details = {}
    successful = []

    for candidate in sorted(config.candidates, key=lambda c: (c.priority, c.name)):
        ok = False
        failures = []
        for ip in ips:
            session.set_probe(candidate, host=config.host, addresses=(ip,))
            try:
                if candidate.transport == "udp":
                    status, _ = quic_probe(config.host, ip, "/", probe_timeout)
                    check_name = "quic"
                else:
                    status, _ = _check_probe(
                        "http", config.host, ip, "/", probe_timeout,
                        on_connected=lambda port, c=candidate: session.bind_probe(c, port, config.host),
                        probe=probe,
                    )
                    check_name = "web"
                if not session.probe_applied():
                    raise ValueError("Candidate did not alter the probe packet")
                logger.info(
                    "%s probe | %s | %s | %s | status=%s",
                    check_name.capitalize(), candidate.name, config.host, ip, status,
                )
                ok = True
            except Exception as exc:
                failures.append(str(exc))
                logger.warning(
                    "%s probe | %s | %s | %s | failed: %s",
                    "QUIC" if candidate.transport == "udp" else "Web",
                    candidate.name, config.host, ip, exc,
                )
            finally:
                session.set_probe(None)
            # One verified address is enough to mark this candidate working;
            # the remaining candidates must still be tested for comparison.
            if ok:
                break

        check_name = "quic" if candidate.transport == "udp" else "web"
        details[candidate.name] = {check_name: ok}
        if ok:
            successful.append(candidate)
            logger.info("Candidate passed %s health check: %s", check_name, candidate.name)
        else:
            logger.warning(
                "Candidate %s failed Discord %s health check%s",
                candidate.name,
                check_name,
                f": {'; '.join(failures[:2])}" if failures else "",
            )

    if successful:
        selected = min(successful, key=lambda c: (c.priority, c.name))
        session.activate(selected)
        logger.info(
            "Selected session strategy: %s (tested %s successful candidate(s))",
            selected.name,
            len(successful),
        )
        return selected, details

    logger.error("No candidate passed verified Discord health checks; no strategy selected.")
    return None, details


def diagnose_desktop_endpoints(config, logger):
    """Best-effort short checks for desktop Discord dependencies.

    The session strategy is already active when this runs, so these requests
    pass through the selected DPI manipulation. Failures are diagnostic only.
    """
    timeout = min(config.timeout, 2.0)
    results = {}
    for name, host, path, kind in config.health_checks:
        if name == "web":
            continue
        ok = False
        try:
            ips = resolve_verified(host, timeout, 1)
        except Exception as exc:
            logger.warning("Desktop diagnostic DNS | %s | %s | failed: %s", name, host, exc)
            results[name] = False
            continue

        for ip in ips:
            try:
                status, _ = _check_probe(kind, host, ip, path, timeout)
                logger.info(
                    "Desktop diagnostic | %s | %s | %s | status=%s",
                    name, host, ip, status,
                )
                ok = True
                break
            except Exception as exc:
                logger.warning(
                    "Desktop diagnostic | %s | %s | %s | failed: %s",
                    name, host, ip, exc,
                )
        results[name] = ok
    return results
