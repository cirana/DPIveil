from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dpiveil.classifier import classify_packet


@dataclass(frozen=True)
class FragmentConfig:
    first_chunk_size: int = 32


class TLSClientHelloFragmentStrategy:
    name = "tls_client_hello_fragment"

    def __init__(self, config: FragmentConfig | None = None) -> None:
        self.config = config or FragmentConfig()

    def process(self, packet) -> Iterable:
        info = classify_packet(packet)
        payload = bytes(packet.payload or b"")

        if not info.is_tls_client_hello or len(payload) <= self.config.first_chunk_size:
            yield packet
            return

        split_at = max(1, min(self.config.first_chunk_size, len(payload) - 1))

        first = packet
        second = packet

        first.payload = payload[:split_at]
        second.payload = payload[split_at:]

        yield first
        yield second
