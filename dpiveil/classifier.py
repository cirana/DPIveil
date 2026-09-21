from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PacketInfo:
    destination_ip: str
    destination_port: int
    payload_length: int
    flags: str
    is_tls_client_hello: bool
    sni: Optional[str]
    sni_offset: Optional[int] = None


def tcp_flags(packet) -> str:
    tcp = packet.tcp
    if tcp is None:
        return "-"

    flags = []
    if tcp.syn:
        flags.append("SYN")
    if tcp.ack:
        flags.append("ACK")
    if tcp.fin:
        flags.append("FIN")
    if tcp.rst:
        flags.append("RST")
    if tcp.psh:
        flags.append("PSH")
    if tcp.urg:
        flags.append("URG")

    return ",".join(flags) if flags else "-"


def extract_sni_details(payload: bytes) -> tuple[bool, Optional[str], Optional[int]]:
    # TLS record header: type(1) + version(2) + length(2)
    if len(payload) < 5 or payload[0] != 0x16:
        return False, None, None

    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return False, None, None

    # TLS handshake header: type(1) + length(3)
    if len(payload) < 9 or payload[5] != 0x01:
        return False, None, None

    pos = 9

    # client_version(2) + random(32)
    if len(payload) < pos + 34:
        return True, None, None
    pos += 34

    if len(payload) < pos + 1:
        return True, None, None
    session_id_len = payload[pos]
    pos += 1 + session_id_len

    if len(payload) < pos + 2:
        return True, None, None
    cipher_len = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2 + cipher_len

    if len(payload) < pos + 1:
        return True, None, None
    compression_len = payload[pos]
    pos += 1 + compression_len

    if len(payload) < pos + 2:
        return True, None, None
    extensions_len = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    extensions_end = min(pos + extensions_len, len(payload))

    while pos + 4 <= extensions_end:
        ext_type = int.from_bytes(payload[pos:pos + 2], "big")
        ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
        pos += 4

        ext_end = pos + ext_len
        if ext_end > extensions_end:
            break

        if ext_type == 0x0000 and ext_len >= 5:
            data = payload[pos:ext_end]
            if len(data) < 5:
                return True, None, None

            list_len = int.from_bytes(data[0:2], "big")
            name_pos = 2
            list_end = min(2 + list_len, len(data))

            while name_pos + 3 <= list_end:
                name_type = data[name_pos]
                name_len = int.from_bytes(data[name_pos + 1:name_pos + 3], "big")
                name_pos += 3
                name_end = name_pos + name_len

                if name_end > list_end:
                    break

                if name_type == 0:
                    try:
                        name = data[name_pos:name_end].decode("ascii")
                        return True, name, pos + name_pos
                    except UnicodeDecodeError:
                        return True, None, None

                name_pos = name_end

        pos = ext_end

    return True, None, None


def extract_sni(payload: bytes) -> tuple[bool, Optional[str]]:
    is_client_hello, sni, _ = extract_sni_details(payload)
    return is_client_hello, sni


def classify_packet(packet) -> PacketInfo:
    payload = bytes(packet.payload or b"")
    is_client_hello, sni, sni_offset = extract_sni_details(payload)

    dst_addr = getattr(packet, "dst_addr", None)
    dst_port = packet.tcp.dst_port if packet.tcp else 0

    return PacketInfo(
        destination_ip=str(dst_addr or "?"),
        destination_port=int(dst_port or 0),
        payload_length=len(payload),
        flags=tcp_flags(packet),
        is_tls_client_hello=is_client_hello,
        sni=sni,
        sni_offset=sni_offset,
    )
