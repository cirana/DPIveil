import json
import logging
import sys
import types
import unittest
from unittest.mock import patch

from test_tls_fragment import FakePacket, client_hello

with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.autoselect import (
        AutoConfig,
        SessionStrategy,
        direct_works,
        resolve_verified,
        test_cached_candidate,
        test_candidates,
    )
    from dpiveil.probes import https_request as probes_https_request
    from dpiveil.autoselect import https_request as autoselect_https_request
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

    def test_direct_works_checks_all_addresses(self):
        calls = []
        timeouts = []

        def probe(host, ip, path, timeout):
            calls.append(ip)
            timeouts.append(timeout)
            if ip.endswith(".1"):
                raise TimeoutError("blocked")
            return 200, b""

        self.assertTrue(direct_works(self.config, ["192.0.2.1", "192.0.2.2"], self.logger, probe))
        self.assertEqual(calls, ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(timeouts, [2.0, 2.0])

    def test_direct_works_stops_after_verified_address(self):
        calls = []

        def probe(host, ip, path, timeout):
            calls.append(ip)
            return 200, b""

        self.assertTrue(direct_works(self.config, ["192.0.2.1", "192.0.2.2"], self.logger, probe))
        self.assertEqual(calls, ["192.0.2.1"])

    def test_candidate_timeout_is_bounded_and_configurable(self):
        config = AutoConfig.from_options({
            "host": "discord.com",
            "timeout": 6,
            "max_ips": 2,
            "candidates": [{"name": "split", "kind": "multisplit", "priority": 1}],
        })
        self.assertEqual(config.candidate_timeout, 4.0)
        config = AutoConfig.from_options({
            "host": "discord.com",
            "timeout": 6,
            "candidate_timeout": 3,
            "max_ips": 2,
            "candidates": [{"name": "split", "kind": "multisplit", "priority": 1}],
        })
        self.assertEqual(config.candidate_timeout, 3.0)
        with self.assertRaises(ValueError):
            AutoConfig.from_options({
                "host": "discord.com",
                "timeout": 3,
                "candidate_timeout": 4,
                "max_ips": 2,
                "candidates": [{"name": "split", "kind": "multisplit", "priority": 1}],
            })

    def test_probe_functions_are_reexported_without_duplicate_implementations(self):
        self.assertIs(autoselect_https_request, probes_https_request)

    def test_cached_candidate_uses_verified_probe_and_activates(self):
        session = SessionStrategy("discord.com")
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        def probe(host, ip, path, timeout, on_connected, accept=None):
            on_connected(51234)
            packet.dst_addr = ip
            session.process(packet)
            return 200, b""

        selected = test_cached_candidate(
            self.config,
            session,
            self.logger,
            self.candidates[0],
            ["192.0.2.1"],
            probe,
        )
        self.assertEqual(selected.name, "split")
        self.assertEqual(session.name, "split")

    def test_failed_cached_candidate_leaves_full_scan_path_available(self):
        session = SessionStrategy("discord.com")

        def fail(*args, **kwargs):
            raise ConnectionResetError("cached strategy reset")

        selected = test_cached_candidate(
            self.config,
            session,
            self.logger,
            self.candidates[0],
            ["192.0.2.1"],
            fail,
        )
        self.assertIsNone(selected)
        self.assertEqual(session.name, "auto")

    def test_all_working_candidates_are_tested_and_priority_selects(self):
        session = SessionStrategy("discord.com")
        seen = []
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        def probe(host, ip, path, timeout, on_connected, accept=None):
            on_connected(51234)
            packet.dst_addr = ip
            session.process(packet)
            seen.append((session._candidate.name, ip))
            if session._candidate.name == "split" and ip.endswith(".1"):
                raise ConnectionResetError("reset")
            return 200, b""

        selected, details = test_candidates(
            self.config,
            session,
            self.logger,
            ["192.0.2.1", "192.0.2.2"],
            probe,
        )

        self.assertEqual(selected.name, "split")
        self.assertEqual(session.name, "split")
        self.assertEqual(
            seen,
            [
                ("split", "192.0.2.1"), ("split", "192.0.2.2"),
                ("disorder", "192.0.2.1"),
                ("fake", "192.0.2.1"),
            ],
        )
        self.assertEqual(details, {
            "split": {"web": True},
            "disorder": {"web": True},
            "fake": {"web": True},
        })

    def test_failed_candidates_fall_through_in_priority_order(self):
        session = SessionStrategy("discord.com")
        seen = []
        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        def probe(host, ip, path, timeout, on_connected, accept=None):
            on_connected(51234)
            packet.dst_addr = ip
            session.process(packet)
            seen.append(session._candidate.name)
            if session._candidate.name != "disorder":
                raise ConnectionResetError("reset")
            return 200, b""

        selected, details = test_candidates(
            self.config,
            session,
            self.logger,
            ["192.0.2.1"],
            probe,
        )

        self.assertEqual(selected.name, "disorder")
        self.assertEqual(seen, ["split", "disorder", "fake"])
        self.assertEqual(details, {
            "split": {"web": False},
            "disorder": {"web": True},
            "fake": {"web": False},
        })

    def test_no_verified_reply_keeps_passthrough(self):
        session = SessionStrategy("discord.com")

        def fail(*args, **kwargs):
            raise ValueError("certificate invalid")

        selected, details = test_candidates(
            self.config,
            session,
            self.logger,
            ["192.0.2.1"],
            fail,
        )
        self.assertIsNone(selected)
        self.assertTrue(all(not row["web"] for row in details.values()))
        self.assertEqual(session.name, "auto")

    def test_probe_isolation_and_activation(self):
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

        def success(host, ip, path, timeout, on_connected, accept=None):
            on_connected(51234)
            packet.tcp.src_port = 51234
            session.process(packet)
            return 200, b""

        selected, _ = test_candidates(
            self.config,
            session,
            self.logger,
            ["192.0.2.1"],
            success,
        )
        self.assertEqual(selected.name, "split")

        packet.tcp.src_port = 60000
        self.assertEqual(len(list(session.process(packet))), 2)

    def test_active_strategy_learns_rotated_discord_ip_from_sni(self):
        session = SessionStrategy("discord.com")
        candidate = self.candidates[0]
        session.record_dns_answer("discord.com", ["192.0.2.1"])
        session.activate(candidate)

        packet = FakePacket()
        packet.payload = client_hello("updates.discord.com")
        packet.dst_addr = "192.0.2.2"
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        output = list(session.process(packet))
        self.assertEqual(len(output), 2)
        self.assertTrue(session.protects_ip("192.0.2.2"))

    def test_active_fake_ttl_still_applies_to_known_ip(self):
        session = SessionStrategy("discord.com")
        candidate = self.candidates[2]
        session.record_dns_answer("discord.com", ["192.0.2.1"])
        session.activate(candidate)

        packet = FakePacket()
        packet.payload = client_hello("discord.com")
        packet.dst_addr = "192.0.2.1"
        packet.tcp.src_port = 51234
        FakePacket.source = packet

        fake, original = list(session.process(packet))
        self.assertEqual(fake.ip.ttl, 1)
        self.assertIs(original, packet)

    def test_dns_reply_requires_verified_https_and_address(self):
        calls = []

        def dns(host, ip, path, timeout, accept):
            calls.append((host, ip, accept))
            if ip == "1.1.1.1":
                raise ConnectionResetError("unavailable")
            return 200, json.dumps({
                "Status": 0,
                "Answer": [
                    {"type": 1, "data": "162.159.138.232"},
                    {"type": 1, "data": "162.159.128.233"},
                ],
            }).encode()

        self.assertEqual(resolve_verified_with(dns), ["162.159.128.233"])
        self.assertEqual(calls[0][0], "cloudflare-dns.com")
        self.assertEqual(calls[1][1], "1.0.0.1")


def resolve_verified_with(dns):
    with patch.dict(resolve_verified.__globals__, {"https_request": dns}):
        return resolve_verified("discord.com", 3, 1)


if __name__ == "__main__":
    unittest.main()
