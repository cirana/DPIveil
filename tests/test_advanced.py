import ipaddress
import sys
import types
import unittest
from unittest.mock import patch

from test_tls_fragment import FakePacket, client_hello

with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.strategies import advanced
    from dpiveil.strategies.candidates import Candidate, CandidateStrategy


class FakeUDP:
    def __init__(self, dst_port=443):
        self.dst_port = dst_port


class RawPacket:
    def __init__(self, raw, interface=None, direction=None, timestamp=None):
        self.raw = bytes(raw)
        self.interface = interface
        self.direction = direction
        self.timestamp = timestamp
        header_len = (self.raw[0] & 0x0F) * 4 if self.raw else 0
        self.payload = self.raw[header_len:]
        self.tcp = None
        self.udp = FakeUDP(443)
        self.is_inbound = False
        self.dst_addr = "192.0.2.1"

    def recalculate_checksums(self):
        pass


class AdvancedStrategyTests(unittest.TestCase):
    def tearDown(self):
        FakePacket.source = None

    def test_fake_badseq_sends_decoy_then_original(self):
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.seq_num = 10000
        FakePacket.source = packet
        candidate = Candidate("fake+badseq", "fake+badseq", 1)
        fake, original = list(CandidateStrategy(candidate, ("discord.com",)).process(packet))
        self.assertIs(original, packet)
        self.assertEqual(fake.tcp.seq_num, (10000 - 10000) & 0xFFFFFFFF)
        self.assertNotEqual(fake.payload, packet.payload)
        self.assertTrue(fake.checksummed)

    def test_syndata_modifies_empty_syn_but_preserves_tfo(self):
        packet = FakePacket()
        packet.tcp.syn = True
        packet.tcp.ack = False
        FakePacket.source = packet
        strategy = CandidateStrategy(Candidate("syndata", "syndata", 1))
        modified = list(strategy.process(packet))
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0].payload, b"\x00" * 16)
        self.assertTrue(modified[0].checksummed)

        packet.payload = b"TFO"
        self.assertEqual(list(strategy.process(packet)), [packet])

    def test_ipfrag2_splits_ipv4_udp_at_eight_bytes(self):
        udp_payload = b"\x01\xbb\x00\x20\x00\x00\x00\x00" + b"QUIC-initial-data"
        header = bytearray(20)
        header[0] = 0x45
        header[2:4] = (len(header) + len(udp_payload)).to_bytes(2, "big")
        header[4:6] = (0x1234).to_bytes(2, "big")
        header[8] = 64
        header[9] = 17
        header[12:16] = ipaddress.ip_address("192.0.2.10").packed
        header[16:20] = ipaddress.ip_address("192.0.2.1").packed
        header[10:12] = advanced._internet_checksum(bytes(header)).to_bytes(2, "big")
        packet = RawPacket(bytes(header) + udp_payload)
        first, second = list(CandidateStrategy(
            Candidate("ipfrag2-8", "ipfrag2-8", 1, ipfrag_pos=8)
        ).process(packet))

        first_flags = int.from_bytes(first.raw[6:8], "big")
        second_flags = int.from_bytes(second.raw[6:8], "big")
        self.assertTrue(first_flags & 0x2000)
        self.assertEqual(second_flags & 0x1FFF, 1)
        self.assertEqual(int.from_bytes(first.raw[2:4], "big"), 28)
        self.assertEqual(int.from_bytes(second.raw[2:4], "big"), len(second.raw))
        self.assertEqual(first.raw[20:] + second.raw[20:], udp_payload)
        self.assertEqual(first.raw[4:6], second.raw[4:6])

    def test_existing_candidate_kinds_stay_available(self):
        for name, kind in (
            ("multisplit-2", "multisplit"),
            ("multidisorder-2", "multidisorder"),
            ("fake-ttl-1", "fake_ttl"),
        ):
            candidate = Candidate(name, kind, 1)
            self.assertEqual(candidate.transport, "tcp")
            CandidateStrategy(candidate)

    def test_legacy_candidate_wire_shapes_are_unchanged(self):
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.seq_num = 100
        FakePacket.source = packet

        first, second = list(CandidateStrategy(
            Candidate("multisplit-2", "multisplit", 1, split_pos=2),
            ("discord.com",),
        ).process(packet))
        self.assertEqual(first.payload + second.payload, packet.payload)
        self.assertEqual(second.tcp.seq_num, 102)

        second, first = list(CandidateStrategy(
            Candidate("multidisorder-2", "multidisorder", 1, split_pos=2),
            ("discord.com",),
        ).process(packet))
        self.assertEqual(first.payload + second.payload, packet.payload)
        self.assertEqual(second.tcp.seq_num, 102)

        fake, original = list(CandidateStrategy(
            Candidate("fake-ttl-1", "fake_ttl", 1, ttl=1),
            ("discord.com",),
        ).process(packet))
        self.assertEqual(fake.ip.ttl, 1)
        self.assertIs(original, packet)


if __name__ == "__main__":
    unittest.main()
