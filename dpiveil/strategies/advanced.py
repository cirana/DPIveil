"""Additional WinDivert strategies used by the automatic selector.

The legacy zapret-compatible strategies live in :mod:`zapret_compat` and are
intentionally kept separate.  This module contains the three newer methods
which have different packet/protocol requirements:

* ``fake+badseq``: a decoy TLS ClientHello with an out-of-window TCP sequence;
* ``syndata``: data carried by the initial TCP SYN (without touching TFO SYNs);
* ``ipfrag2``: real IPv4 fragmentation of an outbound UDP/443 packet.

All packet construction is done through WinDivert/PyDivert packet objects.  No
TLS certificate or hostname verification is bypassed by these strategies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pydivert

from dpiveil.classifier import classify_packet


def _clone_packet(packet):
    """Clone a packet while retaining the WinDivert metadata."""
    kwargs = {
        name: getattr(packet, name)
        for name in ("interface", "direction", "timestamp")
        if hasattr(packet, name)
    }
    try:
        return pydivert.Packet(bytes(packet.raw), **kwargs)
    except TypeError:  # small test doubles and older PyDivert builds
        return pydivert.Packet(bytes(packet.raw))


def _is_outbound(packet) -> bool:
    return not bool(getattr(packet, "is_inbound", False))


def _matches_domain(sni: str | None, domains: tuple[str, ...]) -> bool:
    if not domains:
        return True
    if not sni:
        return False
    hostname = sni.lower().rstrip(".")
    return any(hostname == domain or hostname.endswith("." + domain) for domain in domains)


@dataclass(frozen=True)
class FakeBadSeqConfig:
    target_domains: tuple[str, ...] = ()
    badseq_increment: int = -10000
    badack_increment: int = -66000


class FakeBadSeqStrategy:
    """Send a decoy TLS ClientHello which the server rejects by sequence."""

    name = "fake+badseq"

    def __init__(self, config: FakeBadSeqConfig | None = None) -> None:
        self.config = config or FakeBadSeqConfig()
        if not isinstance(self.config.badseq_increment, int):
            raise ValueError("badseq_increment must be an integer")
        if not isinstance(self.config.badack_increment, int):
            raise ValueError("badack_increment must be an integer")
        if any(
            not domain or domain != domain.lower() or domain.startswith(".")
            for domain in self.config.target_domains
        ):
            raise ValueError("target_domains must contain lowercase hostnames")

    def _apply(self, packet, require_domain: bool) -> Iterable:
        if not _is_outbound(packet) or packet.tcp is None:
            yield packet
            return

        info = classify_packet(packet)
        if not info.is_tls_client_hello or (
            require_domain and not _matches_domain(info.sni, self.config.target_domains)
        ):
            yield packet
            return

        fake = _clone_packet(packet)
        fake_payload = bytearray(fake.payload or b"")
        if info.sni is not None and info.sni_offset is not None:
            end = info.sni_offset + len(info.sni)
            if 0 <= info.sni_offset < end <= len(fake_payload):
                fake_payload[info.sni_offset:end] = b"a" * len(info.sni)
                fake.payload = bytes(fake_payload)

        original_seq = int(getattr(packet.tcp, "seq_num", 0))
        fake.tcp.seq_num = (original_seq + self.config.badseq_increment) & 0xFFFFFFFF
        if hasattr(fake.tcp, "ack_num") and hasattr(packet.tcp, "ack_num"):
            original_ack = int(getattr(packet.tcp, "ack_num", 0))
            fake.tcp.ack_num = (original_ack + self.config.badack_increment) & 0xFFFFFFFF
        fake.recalculate_checksums()
        yield fake
        yield packet

    def process(self, packet) -> Iterable:
        return self._apply(packet, require_domain=True)

    def process_forced(self, packet) -> Iterable:
        return self._apply(packet, require_domain=False)


@dataclass(frozen=True)
class SynDataConfig:
    payload: bytes = b"\x00" * 16


class SynDataStrategy:
    """Carry harmless data on a non-TFO SYN to confuse DPI parsers."""

    name = "syndata"

    def __init__(self, config: SynDataConfig | None = None) -> None:
        self.config = config or SynDataConfig()
        if not self.config.payload:
            raise ValueError("syndata payload must not be empty")

    def _apply(self, packet) -> Iterable:
        tcp = getattr(packet, "tcp", None)
        if (
            not _is_outbound(packet)
            or tcp is None
            or not bool(getattr(tcp, "syn", False))
            or bool(getattr(tcp, "ack", False))
            or bytes(packet.payload or b"")
        ):
            # A SYN with data is a TCP Fast Open attempt.  Do not alter it.
            yield packet
            return

        modified = _clone_packet(packet)
        modified.payload = self.config.payload
        modified.recalculate_checksums()
        yield modified

    def process(self, packet) -> Iterable:
        return self._apply(packet)

    def process_forced(self, packet) -> Iterable:
        return self._apply(packet)


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[pos:pos + 2], "big") for pos in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _new_packet(packet, raw: bytes):
    kwargs = {
        name: getattr(packet, name)
        for name in ("interface", "direction", "timestamp")
        if hasattr(packet, name)
    }
    try:
        return pydivert.Packet(raw, **kwargs)
    except TypeError:
        return pydivert.Packet(raw)


@dataclass(frozen=True)
class IPFragment2Config:
    position: int = 8

    def __post_init__(self):
        if self.position < 8 or self.position > 65528 or self.position % 8:
            raise ValueError("ipfrag2 position must be a multiple of 8 between 8 and 65528")


class IPFragment2Strategy:
    """Split outbound IPv4 UDP/443 packets into two real IP fragments."""

    name = "ipfrag2-8"

    def __init__(self, config: IPFragment2Config | None = None) -> None:
        self.config = config or IPFragment2Config()

    def _fragment(self, packet) -> list:
        raw = bytes(packet.raw)
        if len(raw) < 20 or raw[0] >> 4 != 4:
            return [packet]

        header_len = (raw[0] & 0x0F) * 4
        total_length = int.from_bytes(raw[2:4], "big")
        if header_len < 20 or total_length < header_len:
            return [packet]
        total_length = min(total_length, len(raw))
        ip_payload = raw[header_len:total_length]
        split_at = self.config.position
        if split_at >= len(ip_payload) or split_at % 8:
            return [packet]

        # Fragmentation is measured from the transport header.  The first
        # fragment carries the first 8 bytes of UDP (and any selected bytes),
        # while the second fragment carries the remainder.  The UDP checksum
        # remains valid after reassembly and is not rewritten per fragment.
        header = bytearray(raw[:header_len])
        flags_offset = int.from_bytes(header[6:8], "big")
        original_offset = flags_offset & 0x1FFF
        original_more = flags_offset & 0x2000
        reserved = flags_offset & 0x8000

        first_header = bytearray(header)
        second_header = bytearray(header)
        first_header[6:8] = (reserved | 0x2000 | original_offset).to_bytes(2, "big")
        second_flags = reserved | ((original_offset + split_at // 8) & 0x1FFF)
        if original_more:
            second_flags |= 0x2000
        second_header[6:8] = second_flags.to_bytes(2, "big")

        first_raw = first_header + ip_payload[:split_at]
        second_raw = second_header + ip_payload[split_at:]
        for fragment_header, fragment in (
            (first_header, first_raw),
            (second_header, second_raw),
        ):
            fragment_header[2:4] = len(fragment).to_bytes(2, "big")
            fragment_header[10:12] = b"\x00\x00"
            fragment_header[10:12] = _internet_checksum(bytes(fragment_header)).to_bytes(2, "big")
            fragment[:header_len] = fragment_header

        return [_new_packet(packet, bytes(first_raw)), _new_packet(packet, bytes(second_raw))]

    def _apply(self, packet) -> Iterable:
        udp = getattr(packet, "udp", None)
        if (
            not _is_outbound(packet)
            or udp is None
            or int(getattr(udp, "dst_port", 0)) != 443
        ):
            yield packet
            return
        yield from self._fragment(packet)

    def process(self, packet) -> Iterable:
        return self._apply(packet)

    def process_forced(self, packet) -> Iterable:
        return self._apply(packet)
