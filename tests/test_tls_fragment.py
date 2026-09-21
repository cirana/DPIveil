import sys
import types
import unittest
from unittest.mock import patch


class FakeTCP:
    def __init__(self, seq_num=0, dst_port=443):
        self.seq_num = seq_num
        self.dst_port = dst_port
        self.syn = self.ack = self.fin = self.rst = False
        self.psh = self.urg = False


class FakePacket:
    source = None

    def __init__(self, raw=b"packet", interface=None, direction=None, timestamp=None):
        other = self.source
        self.raw = raw
        self.interface = interface
        self.direction = direction
        self.timestamp = timestamp
        self.payload = other.payload if other else b""
        self.tcp = FakeTCP(other.tcp.seq_num if other else 0)
        self.dst_addr = "192.0.2.1"
        self.checksummed = False

    def recalculate_checksums(self):
        self.checksummed = True


with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket)}):
    from dpiveil.classifier import classify_packet, extract_sni
    from dpiveil.strategies.tls_fragment import FragmentConfig, TLSClientHelloFragmentStrategy


def client_hello(host):
    name = host.encode("ascii")
    host_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    server_names = len(host_entry).to_bytes(2, "big") + host_entry
    sni = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    body = (
        b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
        + b"\x01\x00" + len(sni).to_bytes(2, "big") + sni
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class FragmentTests(unittest.TestCase):
    def tearDown(self):
        FakePacket.source = None

    def test_sni_split_preserves_stream_and_tcp_sequence(self):
        payload = client_hello("discord.com")
        packet = FakePacket()
        packet.payload = payload
        packet.tcp.seq_num = 0xFFFFFFF0
        FakePacket.source = packet

        info = classify_packet(packet)
        self.assertEqual(extract_sni(payload), (True, "discord.com"))
        self.assertEqual(payload[info.sni_offset:info.sni_offset + 11], b"discord.com")

        first, second = TLSClientHelloFragmentStrategy().process(packet)
        self.assertEqual(first.payload + second.payload, payload)
        self.assertEqual(len(first.payload), info.sni_offset + 1)
        self.assertEqual(second.tcp.seq_num, (packet.tcp.seq_num + len(first.payload)) & 0xFFFFFFFF)
        self.assertTrue(first.checksummed and second.checksummed)
        self.assertNotIn(b"discord.com", first.payload)
        self.assertNotIn(b"discord.com", second.payload)

    def test_other_packets_pass_through_and_fixed_mode_is_available(self):
        packet = FakePacket()
        packet.payload = b"ordinary request"
        self.assertEqual(list(TLSClientHelloFragmentStrategy().process(packet)), [packet])

        packet.payload = client_hello("discord.com")
        FakePacket.source = packet
        strategy = TLSClientHelloFragmentStrategy(FragmentConfig(32, "fixed"))
        first, second = strategy.process(packet)
        self.assertEqual(len(first.payload), 32)
        self.assertEqual(first.payload + second.payload, packet.payload)

    def test_invalid_configuration_rejected(self):
        with self.assertRaises(ValueError):
            TLSClientHelloFragmentStrategy(FragmentConfig(0, "fixed"))
        with self.assertRaises(ValueError):
            TLSClientHelloFragmentStrategy(FragmentConfig(32, "unknown"))


if __name__ == "__main__":
    unittest.main()
