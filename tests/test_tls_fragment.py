import sys
import types
import unittest
import logging
from unittest.mock import patch


class FakeTCP:
    def __init__(self, seq_num=0, dst_port=443, src_port=59913):
        self.seq_num = seq_num
        self.dst_port = dst_port
        self.src_port = src_port
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
        self.src_addr = "192.0.2.1"
        self.is_inbound = False
        self.checksummed = False

    def recalculate_checksums(self):
        self.checksummed = True


with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.classifier import classify_packet, extract_sni
    from dpiveil.engine import PacketEngine, is_suspect_rst
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

    def test_reverse_order_only_for_selected_domain(self):
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.seq_num = 42000
        FakePacket.source = packet
        strategy = TLSClientHelloFragmentStrategy(
            FragmentConfig(reverse_order=True, target_domains=("discord.com",))
        )
        second, first = strategy.process(packet)
        self.assertGreater(second.tcp.seq_num, first.tcp.seq_num)
        self.assertEqual(first.payload + second.payload, packet.payload)

        packet.payload = client_hello("unrelated.example")
        self.assertEqual(list(strategy.process(packet)), [packet])

        packet.payload = client_hello("cdn.discord.com")
        self.assertEqual(len(list(strategy.process(packet))), 2)

    def test_only_matching_reset_on_protected_flow_is_dropped(self):
        self.assertTrue(is_suspect_rst(127, 0, 126, 36750))
        self.assertFalse(is_suspect_rst(127, 0, 127, 36750))

        def incoming(syn=False, rst=False, ttl=127, ip_id=0, port=59913):
            raw = bytearray(20)
            raw[0] = 0x45
            raw[8] = ttl
            raw[4:6] = ip_id.to_bytes(2, "big")
            packet = FakePacket(bytes(raw))
            packet.is_inbound = True
            packet.src_addr = "192.0.2.1"
            packet.tcp.src_port = 443
            packet.tcp.dst_port = port
            packet.tcp.syn = syn
            packet.tcp.ack = syn
            packet.tcp.rst = rst
            return packet

        synack = incoming(syn=True)
        hello = FakePacket()
        hello.payload = client_hello("discord.com")
        hello.tcp.src_port = 59913
        FakePacket.source = hello
        suspect = incoming(rst=True, ttl=126, ip_id=36750)
        normal = incoming(rst=True, ttl=127, ip_id=36750)
        unrelated = incoming(rst=True, ttl=126, ip_id=36750, port=60000)

        class FakeDivert:
            last = None

            def __init__(self, _):
                self.sent = []

            def __enter__(self):
                FakeDivert.last = self
                return self

            def __exit__(self, *_):
                return False

            def __iter__(self):
                return iter([synack, hello, suspect, normal, unrelated])

            def send(self, packet):
                self.sent.append(packet)

        with patch.object(PacketEngine.run.__globals__["pydivert"], "WinDivert", FakeDivert):
            strategy = TLSClientHelloFragmentStrategy(
                FragmentConfig(target_domains=("discord.com",), drop_suspect_rst=True)
            )
            engine = PacketEngine("test", logging.getLogger("test"), strategy)
            engine.run()
            self.assertEqual(engine.stats.suspect_resets_dropped, 1)
            self.assertEqual(engine.stats.inbound_resets, 3)
            self.assertNotIn(suspect, FakeDivert.last.sent)
            self.assertIn(normal, FakeDivert.last.sent)
            self.assertIn(unrelated, FakeDivert.last.sent)


if __name__ == "__main__":
    unittest.main()
