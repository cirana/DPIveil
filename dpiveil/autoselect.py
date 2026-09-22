"""Verified HTTPS probing and session-scoped strategy selection."""
from __future__ import annotations

import threading
from dataclasses import dataclass

from dpiveil.classifier import classify_packet
from dpiveil.constants import DISCORD_DOMAINS
from dpiveil.probes import (
    check_probe as _check_probe,
    https_request,
    quic_request,
    resolve_system,
    resolve_verified,
    websocket_probe,
)
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
    probe_timeout = config.candidate_timeout or min(config.timeout, 4.0)
    for ip in addresses:
        try:
            status, _ = probe(config.host, ip, "/", probe_timeout)
            logger.info("Direct HTTPS | %s | verified status=%s", ip, status)
            success = True
            # One verified normal connection is sufficient to leave the
            # packet engine in pass-through mode.  Do not wait on the other
            # addresses after this path has already succeeded.
            break
        except Exception as exc:
            logger.info("Direct HTTPS | %s | failed: %s", ip, exc)
    return success


def _probe_candidate(
    config,
    session,
    logger,
    candidate,
    ip,
    probe,
    quic_probe,
    probe_timeout,
):
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
        return True, None
    except Exception as exc:
        logger.warning(
            "%s probe | %s | %s | %s | failed: %s",
            "QUIC" if candidate.transport == "udp" else "Web",
            candidate.name, config.host, ip, exc,
        )
        return False, str(exc)
    finally:
        session.set_probe(None)


def test_cached_candidate(
    config,
    session,
    logger,
    candidate,
    addresses=None,
    probe=https_request,
    quic_probe=quic_request,
):
    """Validate one cached candidate with the same real probe as full selection."""
    ips = addresses or resolve_verified(config.host, config.timeout, config.max_ips)
    probe_timeout = config.candidate_timeout or min(config.timeout, 4.0)
    failures = []
    for ip in ips:
        ok, failure = _probe_candidate(
            config, session, logger, candidate, ip, probe, quic_probe, probe_timeout,
        )
        if ok:
            session.activate(candidate)
            logger.info("Cached session strategy verified: %s", candidate.name)
            return candidate
        if failure:
            failures.append(failure)
    logger.warning(
        "Cached strategy %s failed verified Discord health check%s",
        candidate.name,
        f": {'; '.join(failures[:2])}" if failures else "",
    )
    return None


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
            ok, failure = _probe_candidate(
                config, session, logger, candidate, ip, probe, quic_probe, probe_timeout,
            )
            if failure:
                failures.append(failure)
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
