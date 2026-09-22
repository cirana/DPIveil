import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_tls_fragment import FakePacket

with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.autoselect import AutoConfig
    from dpiveil.strategies.candidates import Candidate
    from dpiveil.strategy_cache import (
        CACHE_VERSION,
        StrategyCache,
        candidate_signature,
        config_signature,
        network_identity,
        network_key,
    )


class StrategyCacheTests(unittest.TestCase):
    def setUp(self):
        self.config = AutoConfig(
            "discord.com",
            2,
            2,
            (
                Candidate("multisplit-2", "multisplit", 1, split_pos=2),
                Candidate("multidisorder-2", "multidisorder", 2, split_pos=2),
            ),
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "strategy-cache.json"
        self.key = network_key("192.168.1.1@192.168.1.10")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_save_and_load_round_trip(self):
        cache = StrategyCache(self.path)
        candidate = self.config.candidates[0]

        self.assertTrue(cache.save(self.key, self.config, candidate))
        loaded = cache.load(self.key, self.config)

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.name, candidate.name)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], CACHE_VERSION)
        self.assertEqual(data["entries"][self.key]["candidate_signature"], candidate_signature(candidate))
        self.assertEqual(data["entries"][self.key]["config_signature"], config_signature(self.config))

    def test_corrupt_cache_is_ignored(self):
        self.path.write_text("{not-json", encoding="utf-8")
        cache = StrategyCache(self.path)
        self.assertIsNone(cache.load(self.key, self.config))
        self.assertFalse(cache.save(None, self.config, self.config.candidates[0]))

    def test_stale_and_changed_profiles_are_ignored(self):
        cache = StrategyCache(self.path, max_age_seconds=1)
        cache.save(self.key, self.config, self.config.candidates[0])
        with patch("dpiveil.strategy_cache.time.time", return_value=time.time() + 2):
            self.assertIsNone(cache.load(self.key, self.config))

        changed = AutoConfig(
            "discord.com",
            2,
            2,
            (Candidate("multisplit-2", "fake_ttl", 1, ttl=1),),
        )
        self.assertIsNone(StrategyCache(self.path).load(self.key, changed))

    def test_unknown_network_disables_cache_without_error(self):
        cache = StrategyCache(self.path)
        self.assertFalse(cache.save(None, self.config, self.config.candidates[0]))
        self.assertFalse(self.path.exists())

    def test_route_identity_is_hashed_and_parsed(self):
        route_output = """===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1     192.168.1.10     25
===========================================================================
"""
        result = types.SimpleNamespace(returncode=0, stdout=route_output)
        with patch("dpiveil.strategy_cache.os.name", "nt"):
            identity = network_identity(lambda *args, **kwargs: result)
        self.assertEqual(identity, "192.168.1.1@192.168.1.10")
        self.assertEqual(len(network_key(identity)), 64)


if __name__ == "__main__":
    unittest.main()
