from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pydivert

from dpiveil.classifier import classify_packet


@dataclass(frozen=True)
class FragmentConfig:
    first_chunk_size: int = 32


class TLSClientHelloFragmentStrategy:
    name = "tls_client_hello_fragment"

    def __init__(self, config: FragmentConfig | None = None) -> None:
        self.config = config or FragmentConfig()

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

        if (
            not info.is_tls_client_hello
            or packet.tcp is None
            or len(payload) <= self.config.first_chunk_size
        ):
            yield packet
            return

        split_at = max(1, min(self.config.first_chunk_size, len(payload) - 1))

        first = self._clone_packet(packet)
        second = self._clone_packet(packet)

        original_seq = packet.tcp.seq_num

        first.payload = payload[:split_at]
        second.payload = payload[split_at:]
        second.tcp.seq_num = (original_seq + split_at) & 0xFFFFFFFF

        first.recalculate_checksums()
        second.recalculate_checksums()

        yield first
        yield second
