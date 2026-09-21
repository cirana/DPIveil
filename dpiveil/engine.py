from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import pydivert

from dpiveil.classifier import classify_packet


@dataclass
class EngineStats:
    packets: int = 0
    bytes: int = 0
    send_errors: int = 0
    tls_client_hellos: int = 0
    sni_detected: int = 0


class PassthroughEngine:
    def __init__(
        self,
        packet_filter: str,
        logger: logging.Logger,
        stats_interval: float = 10.0,
    ) -> None:
        self.packet_filter = packet_filter
        self.logger = logger
        self.stats_interval = stats_interval
        self.stats = EngineStats()
        self._last_report = time.monotonic()

    def _report_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_report < self.stats_interval:
            return

        self.logger.info(
            "Passthrough stats: %s packets | %s bytes | TLS ClientHello: %s | SNI: %s | %s send errors",
            f"{self.stats.packets:,}",
            f"{self.stats.bytes:,}",
            self.stats.tls_client_hellos,
            self.stats.sni_detected,
            self.stats.send_errors,
        )
        self._last_report = now

    def run(self) -> EngineStats:
        self.logger.info("Opening WinDivert passthrough engine...")

        with pydivert.WinDivert(self.packet_filter) as divert:
            self.logger.info("WinDivert engine is active.")

            for packet in divert:
                self.stats.packets += 1
                self.stats.bytes += len(packet.raw)

                info = classify_packet(packet)

                if info.is_tls_client_hello:
                    self.stats.tls_client_hellos += 1

                    if info.sni:
                        self.stats.sni_detected += 1
                        self.logger.info(
                            "TLS ClientHello | %s:%s | SNI=%s | payload=%s | flags=%s",
                            info.destination_ip,
                            info.destination_port,
                            info.sni,
                            info.payload_length,
                            info.flags,
                        )
                    else:
                        self.logger.debug(
                            "TLS ClientHello | %s:%s | SNI unavailable | payload=%s | flags=%s",
                            info.destination_ip,
                            info.destination_port,
                            info.payload_length,
                            info.flags,
                        )

                try:
                    divert.send(packet)
                except OSError as exc:
                    self.stats.send_errors += 1
                    self.logger.error("Could not resend packet: %s", exc)

                self._report_if_needed()

        return self.stats
