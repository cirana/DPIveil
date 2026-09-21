"""WinDivert UDP/53 DNS address translation, independent of TCP/TLS strategies."""
from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
import time
from dataclasses import dataclass, replace

import pydivert

from dpiveil.dns_proxy import parse_dns_addresses


@dataclass(frozen=True)
class DNSConfig:
    enabled: bool = False
    ipv4_resolver: str = "1.1.1.1"
    ipv4_port: int = 53
    ipv6_resolver: str = "2606:4700:4700::1111"
    ipv6_port: int = 53
    max_age: float = 15.0

    @classmethod
    def from_options(cls, options):
        if not isinstance(options, dict):
            raise ValueError("dns_redirect must be an object")
        config = cls(**options)
        if type(config.enabled) is not bool:
            raise ValueError("dns_redirect.enabled must be boolean")
        if (ipaddress.ip_address(config.ipv4_resolver).version != 4 or
                ipaddress.ip_address(config.ipv6_resolver).version != 6):
            raise ValueError("DNS resolver addresses have wrong IP family")
        if (type(config.ipv4_port) is not int or type(config.ipv6_port) is not int or
                not 1 <= config.ipv4_port <= 65535 or not 1 <= config.ipv6_port <= 65535):
            raise ValueError("DNS resolver ports must be between 1 and 65535")
        if type(config.max_age) not in (int, float) or not 1 <= config.max_age <= 60:
            raise ValueError("DNS query lifetime must be 1–60 seconds")
        return replace(
            config,
            ipv4_resolver=str(ipaddress.ip_address(config.ipv4_resolver)),
            ipv6_resolver=str(ipaddress.ip_address(config.ipv6_resolver)),
        )

    @property
    def packet_filter(self):
        ports = sorted({53, self.ipv4_port, self.ipv6_port})
        inbound = " or ".join(f"udp.SrcPort == {port}" for port in ports)
        return (
            "udp and !loopback and !impostor and "
            f"((outbound and udp.DstPort == 53) or (inbound and ({inbound})))"
        )


def question_key(payload: bytes, response: bool):
    """Identify a DNS transaction by ID and its sole, uncompressed question."""
    if len(payload) < 17:
        return None
    flags = int.from_bytes(payload[2:4], "big")
    if bool(flags & 0x8000) != response or (flags & 0x7800) != 0:
        return None
    if int.from_bytes(payload[4:6], "big") != 1:
        return None
    pos = 12
    while True:
        if pos >= len(payload):
            return None
        length = payload[pos]
        pos += 1
        if length > 63 or pos + length > len(payload):
            return None
        pos += length
        if length == 0:
            break
    if pos + 4 > len(payload):
        return None
    return payload[:2], payload[12:pos + 4].lower()


class DNSRedirect:
    """Transparent DNS redirect handled inside DPIveil's main WinDivert loop.

    Windows keeps its configured DNS server. Outbound UDP/53 packets are rewritten
    to a trusted resolver and replies are rewritten back so the DNS client sees
    the original resolver address.
    """

    def __init__(
        self,
        config: DNSConfig,
        logger: logging.Logger,
        clock=time.monotonic,
        answer_callback=None,
    ):
        self.config = config
        self.logger = logger
        self.clock = clock
        self.answer_callback = answer_callback
        self.pending = {}
        self._next_port = 54000
        self.ready = threading.Event()
        self.error = None
        self._divert = None
        self._thread = None
        self.queries = 0
        self.responses = 0
        self.spoofed = 0

    def _cleanup(self, now):
        self.pending = {
            key: record
            for key, record in self.pending.items()
            if now - record[2] <= self.config.max_age
        }

    def _observe_reply(self, payload: bytes):
        if self.answer_callback is None:
            return
        host, addresses = parse_dns_addresses(payload)
        if host and addresses:
            try:
                self.answer_callback(host, addresses)
            except Exception as exc:
                self.logger.debug("DNS answer callback failed: %s", exc)

    def process(self, packet):
        udp = packet.udp
        if udp is None:
            return packet

        payload = bytes(packet.payload or b"")
        local_addr = packet.dst_addr if packet.is_inbound else packet.src_addr
        family = ipaddress.ip_address(str(local_addr)).version
        resolver = self.config.ipv4_resolver if family == 4 else self.config.ipv6_resolver
        port = self.config.ipv4_port if family == 4 else self.config.ipv6_port
        now = self.clock()
        self._cleanup(now)

        if packet.is_outbound and udp.dst_port == 53:
            parsed = question_key(payload, response=False)
            if parsed is None:
                return packet

            original_port = udp.src_port
            original_address = str(packet.dst_addr)
            prefix = (family, str(packet.src_addr))
            key = (family, str(packet.src_addr), original_port, *parsed)

            if key in self.pending and self.pending[key][0] != original_address:
                for _ in range(11536):
                    mapped_port = self._next_port
                    self._next_port = 54000 if self._next_port == 65535 else self._next_port + 1
                    candidate = (*prefix, mapped_port, *parsed)
                    if candidate not in self.pending:
                        key = candidate
                        udp.src_port = mapped_port
                        break
                else:
                    self.logger.error("DNS port mapping exhausted")
                    return packet

            self.pending[key] = (original_address, 53, now, original_port)
            self.logger.info(
                "DNS query redirect | %s:%s -> %s:%s | original DNS %s:53",
                packet.src_addr,
                udp.src_port,
                resolver,
                port,
                original_address,
            )
            packet.ip.dst_addr = resolver
            udp.dst_port = port
            packet.recalculate_checksums()
            self.queries += 1
            return packet

        if packet.is_inbound and udp.src_port in (53, port):
            same_transaction = (
                len(payload) >= 2
                and any(
                    key[:4] == (
                        family,
                        str(packet.dst_addr),
                        udp.dst_port,
                        payload[:2],
                    )
                    for key in self.pending
                )
            )
            parsed = question_key(payload, response=True)
            if parsed is None:
                return None if same_transaction else packet

            key = (family, str(packet.dst_addr), udp.dst_port, *parsed)
            record = self.pending.get(key)
            if record is None:
                return None if same_transaction else packet

            if (
                str(ipaddress.ip_address(str(packet.src_addr))) != resolver
                or udp.src_port != port
            ):
                self.spoofed += 1
                self.logger.warning(
                    "Discarded unexpected DNS response | %s:%s",
                    packet.src_addr,
                    udp.src_port,
                )
                return None

            self.pending.pop(key, None)
            self._observe_reply(payload)
            self.logger.info(
                "DNS reply restore | %s:%s -> original DNS %s:%s | local:%s",
                packet.src_addr,
                udp.src_port,
                record[0],
                record[1],
                record[3],
            )
            packet.ip.src_addr = record[0]
            udp.src_port = record[1]
            udp.dst_port = record[3]
            packet.recalculate_checksums()
            self.responses += 1

        return packet

    # Kept for compatibility with standalone use/tests. DPIveil normally uses
    # this object inside PacketEngine so DNS and TLS share one WinDivert handle.
    def _run(self):
        try:
            with pydivert.WinDivert(self.config.packet_filter, priority=1) as divert:
                self._divert = divert
                self.ready.set()
                for packet in divert:
                    outgoing = self.process(packet)
                    if outgoing is not None:
                        divert.send(outgoing)
        except Exception as exc:
            if not self._stopping:
                self.error = exc
                self.logger.exception("DNS redirect stopped unexpectedly")
            self.ready.set()
        finally:
            self._divert = None

    def start(self):
        self._stopping = False
        self._thread = threading.Thread(
            target=self._run,
            name="dpiveil-dns",
            daemon=True,
        )
        self._thread.start()
        if not self.ready.wait(timeout=5) or self.error or not self._thread.is_alive():
            self.stop()
            raise RuntimeError(
                f"Could not start DNS redirect: {self.error or 'not ready'}"
            )
        self.logger.info(
            "DNS redirect active | IPv4 %s:%s | IPv6 %s:%s",
            self.config.ipv4_resolver,
            self.config.ipv4_port,
            self.config.ipv6_resolver,
            self.config.ipv6_port,
        )

    def stop(self):
        self._stopping = True
        divert = self._divert
        if divert is not None and getattr(divert, "is_open", True):
            try:
                divert.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.logger.info(
            "DNS redirect: %s queries, %s replies, %s unexpected replies",
            self.queries,
            self.responses,
            self.spoofed,
        )


def repair_stale_loopback_dns(logger: logging.Logger):
    """Undo a stale 127.0.0.1 DNS setting left by older local-proxy builds.

    Only active physical adapters with a default gateway are touched. Virtual
    adapters (Radmin/VPN/etc.) are deliberately ignored.
    """
    script = r"""
$items = Get-NetIPConfiguration | Where-Object {
  $_.NetAdapter.Status -eq 'Up' -and
  $_.NetAdapter.HardwareInterface -eq $true -and
  ($null -ne $_.IPv4DefaultGateway -or $null -ne $_.IPv6DefaultGateway)
}
foreach ($item in $items) {
  $idx = $item.InterfaceIndex
  $servers = @(Get-DnsClientServerAddress -InterfaceIndex $idx | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
  if ($servers -contains '127.0.0.1') {
    Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses
    Write-Output ($item.InterfaceAlias + '|' + $idx)
  }
}
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "PowerShell DNS repair failed").strip())
    repaired = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for item in repaired:
        logger.warning("Repaired stale local DNS setting | adapter=%s", item)
    return tuple(repaired)


def flush_dns_cache():
    result = subprocess.run(
        ["ipconfig", "/flushdns"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise OSError("ipconfig /flushdns failed; Windows DNS cache was not cleared")
