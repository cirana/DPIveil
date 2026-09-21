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
    strategy_packets: int = 0
    fragmented_client_hellos: int = 0
    inbound_resets: int = 0


class PacketEngine:
    def __init__(
        self,
        packet_filter: str,
        logger: logging.Logger,
        strategy,
        stats_interval: float = 10.0,
    ) -> None:
        self.packet_filter = packet_filter
        self.logger = logger
        self.strategy = strategy
        self.stats_interval = stats_interval
        self.stats = EngineStats()
        self._last_report = time.monotonic()

    def _report_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_report < self.stats_interval:
            return

        self.logger.info(
            "Stats: %s packets | %s bytes | TLS ClientHello: %s | SNI: %s | fragmented: %s | inbound RST: %s | strategy output: %s | %s send errors",
            f"{self.stats.packets:,}",
            f"{self.stats.bytes:,}",
            self.stats.tls_client_hellos,
            self.stats.sni_detected,
            self.stats.fragmented_client_hellos,
            self.stats.inbound_resets,
            self.stats.strategy_packets,
            self.stats.send_errors,
        )
        self._last_report = now

    def run(self) -> EngineStats:
        self.logger.info("Opening WinDivert engine...")
        self.logger.info("Strategy: %s", self.strategy.name)

        with pydivert.WinDivert(self.packet_filter) as divert:
            self.logger.info("WinDivert engine is active.")

            for packet in divert:
                self.stats.packets += 1
                self.stats.bytes += len(packet.raw)

                if packet.is_inbound:
                    if packet.tcp is not None and packet.tcp.rst:
                        self.stats.inbound_resets += 1
                        self.logger.info(
                            "Inbound TCP RST | %s:%s -> local:%s",
                            packet.src_addr,
                            packet.tcp.src_port,
                            packet.tcp.dst_port,
                        )
                    try:
                        divert.send(packet)
                        self.stats.strategy_packets += 1
                    except OSError as exc:
                        self.stats.send_errors += 1
                        self.logger.error("Could not send inbound packet: %s", exc)
                    self._report_if_needed()
                    continue

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

                try:
                    outgoing_packets = list(self.strategy.process(packet))
                except Exception:
                    self.logger.exception("Strategy failed; sending original packet unchanged.")
                    outgoing_packets = [packet]

                if info.is_tls_client_hello and len(outgoing_packets) == 2:
                    self.stats.fragmented_client_hellos += 1
                    self.logger.info(
                        "TLS split | %s:%s | SNI=%s | mode=%s | reverse=%s | send=%s+%s",
                        info.destination_ip,
                        info.destination_port,
                        info.sni or "?",
                        getattr(getattr(self.strategy, "config", None), "split_mode", "?"),
                        getattr(getattr(self.strategy, "config", None), "reverse_order", False),
                        len(outgoing_packets[0].payload),
                        len(outgoing_packets[1].payload),
                    )

                for outgoing in outgoing_packets:
                    try:
                        divert.send(outgoing)
                        self.stats.strategy_packets += 1
                    except OSError as exc:
                        self.stats.send_errors += 1
                        self.logger.error("Could not send packet: %s", exc)

                self._report_if_needed()

        return self.stats
