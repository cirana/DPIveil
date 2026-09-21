from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pydivert

from dpiveil.classifier import classify_packet


@dataclass(frozen=True)
class FragmentConfig:
    first_chunk_size: int = 32
    split_mode: str = "sni"
    reverse_order: bool = False
    target_domains: tuple[str, ...] = ()
    drop_suspect_rst: bool = False


class TLSClientHelloFragmentStrategy:
    name = "tls_client_hello_fragment"

    def __init__(self, config: FragmentConfig | None = None) -> None:
        self.config = config or FragmentConfig()
        if self.config.first_chunk_size < 1:
            raise ValueError("first_chunk_size must be positive")
        if self.config.split_mode not in {"sni", "fixed"}:
            raise ValueError("split_mode must be 'sni' or 'fixed'")
        if any(not domain or domain != domain.lower() or domain.startswith(".") for domain in self.config.target_domains):
            raise ValueError("target_domains must contain lowercase hostnames")

    @staticmethod
    def _clone_packet(packet):
        return pydivert.Packet(
            bytes(packet.raw),
            interface=packet.interface,
            direction=packet.direction,
            timestamp=packet.timestamp,
        )

    def process(self, packet) -> Iterable:
        info = classify_packet(packet)
        payload = bytes(packet.payload or b"")

        if not info.is_tls_client_hello or packet.tcp is None:
            yield packet
            return

        if self.config.target_domains and not any(
            info.sni and (info.sni.lower() == domain or info.sni.lower().endswith("." + domain))
            for domain in self.config.target_domains
        ):
            yield packet
            return

        if (
            self.config.split_mode == "sni"
            and info.sni_offset is not None
            and info.sni
            and len(info.sni) > 1
        ):
            # Neither TCP segment carries the complete hostname by itself.
            split_at = info.sni_offset + 1
        else:
            split_at = self.config.first_chunk_size

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

        if self.config.reverse_order:
            yield second
            yield first
        else:
            yield first
            yield second
