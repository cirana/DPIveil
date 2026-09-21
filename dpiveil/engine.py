from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import pydivert

from dpiveil.classifier import classify_packet


def is_suspect_rst(syn_ttl: int, syn_ip_id: int, rst_ttl: int, rst_ip_id: int) -> bool:
    """Match the differing SYN-ACK/RST fingerprint observed on the test network."""
    return syn_ip_id == 0 and rst_ip_id != 0 and rst_ttl == syn_ttl - 1


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
    suspect_resets_dropped: int = 0


class PacketEngine:
    def __init__(
        self,
        packet_filter: str,
        logger: logging.Logger,
        strategy,
        stats_interval: float = 10.0,
        dns_redirect=None,
    ) -> None:
        self.packet_filter = packet_filter
        self.logger = logger
        self.strategy = strategy
        self.stats_interval = stats_interval
        self.dns_redirect = dns_redirect
        self.stats = EngineStats()
        self._last_report = time.monotonic()
        self._syn_acks: dict[tuple[str, int], tuple[int, int, float]] = {}
        self._protected_flows: dict[tuple[str, int], float] = {}
        self.ready = threading.Event()
        self._divert = None

    def stop(self) -> None:
        divert = self._divert
        if divert is not None and getattr(divert, "is_open", True):
            try:
                divert.close()
            except OSError:
                pass

    def _report_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_report < self.stats_interval:
            return

        self.logger.info(
            "Stats: %s packets | %s bytes | TLS ClientHello: %s | SNI: %s | fragmented: %s | inbound RST: %s | dropped RST: %s | strategy output: %s | %s send errors",
            f"{self.stats.packets:,}",
            f"{self.stats.bytes:,}",
            self.stats.tls_client_hellos,
            self.stats.sni_detected,
            self.stats.fragmented_client_hellos,
            self.stats.inbound_resets,
            self.stats.suspect_resets_dropped,
            self.stats.strategy_packets,
            self.stats.send_errors,
        )
        self._last_report = now
        self._syn_acks = {key: value for key, value in self._syn_acks.items() if now - value[2] <= 30}
        self._protected_flows = {key: seen for key, seen in self._protected_flows.items() if now - seen <= 8}

    def run(self) -> EngineStats:
        self.logger.info("Opening WinDivert engine...")
        self.logger.info("Strategy: %s", self.strategy.name)

        packet_filter = self.packet_filter
        if self.dns_redirect is not None:
            packet_filter = f"({packet_filter}) or ({self.dns_redirect.config.packet_filter})"
            self.logger.info("DNS handling integrated into main WinDivert engine.")
        with pydivert.WinDivert(packet_filter) as divert:
            self._divert = divert
            self.logger.info("WinDivert engine is active.")
            self.ready.set()

            for packet in divert:
                self.stats.packets += 1
                self.stats.bytes += len(packet.raw)

                # Handle DNS in the same WinDivert capture/reinject loop as TCP.
                # This mirrors GoodbyeDPI's single-handle design and avoids
                # redirected packets being recaptured by a second handle.
                if self.dns_redirect is not None and packet.udp is not None:
                    try:
                        dns_packet = self.dns_redirect.process(packet)
                        if dns_packet is not None:
                            divert.send(dns_packet)
                            self.stats.strategy_packets += 1
                    except Exception:
                        self.logger.exception("DNS redirect failed; sending packet unchanged.")
                        try:
                            divert.send(packet)
                            self.stats.strategy_packets += 1
                        except OSError as exc:
                            self.stats.send_errors += 1
                            self.logger.error("Could not send DNS packet: %s", exc)
                    self._report_if_needed()
                    continue

                if packet.is_inbound:
                    ip_header = bytes(packet.raw)
                    ip_ttl = ip_header[8] if len(ip_header) >= 20 and ip_header[0] >> 4 == 4 else "?"
                    ip_id = int.from_bytes(ip_header[4:6], "big") if ip_ttl != "?" else "?"
                    if packet.tcp is not None and packet.tcp.syn and packet.tcp.ack:
                        flow = (str(packet.src_addr), packet.tcp.dst_port)
                        if isinstance(ip_ttl, int) and isinstance(ip_id, int):
                            self._syn_acks[flow] = (ip_ttl, ip_id, time.monotonic())
                        self.logger.info(
                            "Inbound TCP SYN-ACK | %s:%s -> local:%s | ttl=%s | ip_id=%s",
                            packet.src_addr,
                            packet.tcp.src_port,
                            packet.tcp.dst_port,
                            ip_ttl,
                            ip_id,
                        )
                    if packet.tcp is not None and packet.tcp.rst:
                        self.stats.inbound_resets += 1
                        self.logger.info(
                            "Inbound TCP RST | %s:%s -> local:%s | ttl=%s | ip_id=%s | seq=%s | ack=%s",
                            packet.src_addr,
                            packet.tcp.src_port,
                            packet.tcp.dst_port,
                            ip_ttl,
                            ip_id,
                            packet.tcp.seq_num,
                            getattr(packet.tcp, "ack_num", "?"),
                        )
                        flow = (str(packet.src_addr), packet.tcp.dst_port)
                        syn = self._syn_acks.get(flow)
                        protected_at = self._protected_flows.get(flow)
                        now = time.monotonic()
                        config = getattr(self.strategy, "config", None)
                        if (
                            getattr(config, "drop_suspect_rst", False)
                            and syn is not None
                            and protected_at is not None
                            and now - syn[2] <= 30
                            and now - protected_at <= 8
                            and isinstance(ip_ttl, int)
                            and isinstance(ip_id, int)
                            and is_suspect_rst(syn[0], syn[1], ip_ttl, ip_id)
                        ):
                            self.stats.suspect_resets_dropped += 1
                            self.logger.warning(
                                "Dropped suspected TCP RST | %s:%s -> local:%s | syn_ttl=%s | rst_ttl=%s",
                                packet.src_addr,
                                packet.tcp.src_port,
                                packet.tcp.dst_port,
                                syn[0],
                                ip_ttl,
                            )
                            self._report_if_needed()
                            continue
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
                        "TLS strategy | %s:%s | SNI=%s | strategy=%s | send=%s+%s",
                        info.destination_ip,
                        info.destination_port,
                        info.sni or "?",
                        self.strategy.name,
                        len(outgoing_packets[0].payload),
                        len(outgoing_packets[1].payload),
                    )

                sent_count = 0
                for outgoing in outgoing_packets:
                    try:
                        divert.send(outgoing)
                        self.stats.strategy_packets += 1
                        sent_count += 1
                    except OSError as exc:
                        self.stats.send_errors += 1
                        self.logger.error("Could not send packet: %s", exc)

                if info.is_tls_client_hello and sent_count == 2 and packet.tcp is not None:
                    self._protected_flows[(info.destination_ip, packet.tcp.src_port)] = time.monotonic()

                self._report_if_needed()

        return self.stats
