import json
import logging
import sys
import types
import unittest
from unittest.mock import patch

from test_tls_fragment import FakePacket, client_hello

with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.autoselect import AutoConfig, SessionStrategy, direct_works, resolve_verified, test_candidates
    from dpiveil.strategies.candidates import Candidate


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("auto-test")
        self.candidates = (
            Candidate("split", "multisplit", 1),
            Candidate("disorder", "multidisorder", 2),
            Candidate("fake", "fake_ttl", 3),
        )
        self.config = AutoConfig("discord.com", 2, 2, self.candidates)

    def tearDown(self):
        FakePacket.source = None

    def test_direct_success_skips_candidates(self):
        calls = []

        def probe(host, ip, path, timeout):
            calls.append(ip)
            if ip.endswith(".1"):
                raise TimeoutError("blocked")
            return 200, b""

        self.assertTrue(direct_works(self.config, ["192.0.2.1", "192.0.2.2"], self.logger, probe))
        self.assertEqual(calls, ["192.0.2.1", "192.0.2.2"])

    def test_all_candidates_probed_failed_ones_skipped_and_best_selected(self):
        session = SessionStrategy("discord.com")
        seen = []
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        def probe(host, ip, path, timeout, on_connected):
            on_connected(51234)
            self.assertEqual(session._port, 51234)
            session.process(packet)
            seen.append((session._candidate.name, ip))
            if session._candidate.name == "disorder" or (session._candidate.name == "split" and ip.endswith(".1")):
                return 403, b""
            raise ConnectionResetError("reset")

        selected, scores = test_candidates(self.config, session, self.logger,
                                            ["192.0.2.1", "192.0.2.2"], probe)
        self.assertEqual(len(seen), 6)
        self.assertEqual(scores, {"split": 1, "disorder": 2, "fake": 0})
        self.assertEqual(selected.name, "disorder")
        self.assertEqual(session.name, "disorder")

    def test_no_verified_reply_keeps_passthrough(self):
        session = SessionStrategy("discord.com")

        def fail(*args, **kwargs):
            raise ValueError("certificate invalid")

        selected, scores = test_candidates(self.config, session, self.logger,
                                            ["192.0.2.1"], fail)
        self.assertIsNone(selected)
        self.assertTrue(all(score == 0 for score in scores.values()))
        self.assertEqual(session.name, "auto")

    def test_probe_isolation_and_deterministic_tie(self):
        session = SessionStrategy("discord.com")
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        FakePacket.source = packet
        session.set_probe(self.candidates[0], 51234)
        self.assertEqual(list(session.process(packet)), [packet])
        packet.tcp.src_port = 51234
        self.assertEqual(len(list(session.process(packet))), 2)
        session.set_probe(None)
        self.assertEqual(list(session.process(packet)), [packet])

        def success(host, ip, path, timeout, on_connected):
            on_connected(51234)
            packet.tcp.src_port = 51234
            session.process(packet)
            return 200, b""

        selected, _ = test_candidates(self.config, session, self.logger,
                                       ["192.0.2.1"], success)
        self.assertEqual(selected.name, "split")
        packet.tcp.src_port = 60000
        self.assertEqual(len(list(session.process(packet))), 2)

    def test_dns_reply_requires_verified_https_and_address(self):
        calls = []

        def dns(host, ip, path, timeout, accept):
            calls.append((host, ip, accept))
            if ip == "1.1.1.1":
                raise ConnectionResetError("unavailable")
            return 200, json.dumps({"Status": 0, "Answer": [
                {"type": 1, "data": "162.159.138.232"},
                {"type": 1, "data": "162.159.128.233"},
            ]}).encode()

        self.assertEqual(resolve_verified_with(dns), ["162.159.128.233"])
        self.assertEqual(calls[0][0], "cloudflare-dns.com")
        self.assertEqual(calls[1][1], "1.0.0.1")


def resolve_verified_with(dns):
    with patch.dict(resolve_verified.__globals__, {"https_request": dns}):
        return resolve_verified("discord.com", 3, 1)


if __name__ == "__main__":
    unittest.main()
