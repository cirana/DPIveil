from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pydivert

from dpiveil.classifier import classify_packet


@dataclass(frozen=True)
class ZapretCompatConfig:
    mode: str = "multisplit"
    split_pos: int = 2
    fake_ttl: int = 1
    target_domains: tuple[str, ...] = ()


class ZapretCompatStrategy:
    """Small WinDivert implementations of blockcheck-proven Zapret ideas.

    Supported modes:
    - multisplit: split TLS ClientHello at a fixed TCP payload position.
    - multidisorder: same split, but inject the second segment first.
    - fake_ttl: send a decoy ClientHello with a short TTL before the real one.
    """

    name = "zapret_compat"
    supported_modes = {"multisplit", "multidisorder", "fake_ttl"}

    def __init__(self, config: ZapretCompatConfig | None = None) -> None:
        self.config = config or ZapretCompatConfig()
        if self.config.mode not in self.supported_modes:
            raise ValueError(
                "mode must be one of: " + ", ".join(sorted(self.supported_modes))
            )
        if self.config.split_pos < 1:
            raise ValueError("split_pos must be positive")
        if not 1 <= self.config.fake_ttl <= 255:
            raise ValueError("fake_ttl must be between 1 and 255")
        if any(
            not domain or domain != domain.lower() or domain.startswith(".")
            for domain in self.config.target_domains
        ):
            raise ValueError("target_domains must contain lowercase hostnames")

    @staticmethod
    def _clone_packet(packet):
        return pydivert.Packet(
            bytes(packet.raw),
            interface=packet.interface,
            direction=packet.direction,
            timestamp=packet.timestamp,
        )

    def _matches_target(self, sni: str | None) -> bool:
        if not self.config.target_domains:
            return True
        if not sni:
            return False
        hostname = sni.lower()
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in self.config.target_domains
        )

    def _split(self, packet, reverse: bool) -> Iterable:
        payload = bytes(packet.payload or b"")
        split_at = self.config.split_pos
        if not 0 < split_at < len(payload):
            yield packet
            return

        first = self._clone_packet(packet)
        second = self._clone_packet(packet)
        original_seq = packet.tcp.seq_num

        first.payload = payload[:split_at]
        second.payload = payload[split_at:]
        second.tcp.seq_num = (original_seq + split_at) & 0xFFFFFFFF

        first.recalculate_checksums()
        second.recalculate_checksums()

        if reverse:
            yield second
            yield first
        else:
            yield first
            yield second

    def _fake_ttl(self, packet, sni: str, sni_offset: int) -> Iterable:
        fake = self._clone_packet(packet)
        fake_payload = bytearray(fake.payload or b"")

        # Keep the TLS structure and SNI length intact, but replace the hostname
        # with a harmless decoy. The short TTL is intended to prevent this
        # packet from reaching the destination while still exposing it to DPI.
        end = sni_offset + len(sni)
        if 0 <= sni_offset < end <= len(fake_payload):
            fake_payload[sni_offset:end] = b"a" * len(sni)
            fake.payload = bytes(fake_payload)

        if fake.ip is None:
            yield packet
            return

        fake.ip.ttl = self.config.fake_ttl
        fake.recalculate_checksums()

        yield fake
        yield packet

    def process_forced(self, packet) -> Iterable:
        """Apply split strategies to DNS-confirmed target IPs even when SNI parsing is incomplete."""
        payload = bytes(packet.payload or b"")
        if packet.tcp is None or len(payload) < 2 or payload[0] != 0x16:
            yield packet
            return

        if self.config.mode == "multisplit":
            yield from self._split(packet, reverse=False)
            return
        if self.config.mode == "multidisorder":
            yield from self._split(packet, reverse=True)
            return

        # fake_ttl needs a parsed SNI so the decoy can preserve TLS structure.
        yield packet

    def process(self, packet) -> Iterable:
        info = classify_packet(packet)

        if (
            not info.is_tls_client_hello
            or packet.tcp is None
            or not self._matches_target(info.sni)
        ):
            yield packet
            return

        if self.config.mode == "multisplit":
            yield from self._split(packet, reverse=False)
            return

        if self.config.mode == "multidisorder":
            yield from self._split(packet, reverse=True)
            return

        if info.sni is None or info.sni_offset is None:
            yield packet
            return

        yield from self._fake_ttl(packet, info.sni, info.sni_offset)
