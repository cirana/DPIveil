import json
import logging
import unittest
from unittest.mock import patch

from dpiveil.constants import DISCORD_DOMAINS
from dpiveil.dns_policy import DNSPolicyConfig, WindowsDNSPolicy


class DNSPolicyTests(unittest.TestCase):
    def test_config_defaults_to_cloudflare_doh_without_udp_fallback(self):
        config = DNSPolicyConfig.from_options({"enabled": True})
        self.assertEqual(config.resolver, "1.1.1.1")
        self.assertEqual(config.doh_template, "https://cloudflare-dns.com/dns-query")
        self.assertFalse(config.allow_fallback_to_udp)
        self.assertEqual(config.domains, DISCORD_DOMAINS)

    def test_invalid_template_is_rejected(self):
        with self.assertRaises(ValueError):
            DNSPolicyConfig.from_options({"enabled": True, "doh_template": "http://example.test/dns-query"})

    def test_start_adds_nrpt_and_stop_removes_only_created_rule(self):
        policy = WindowsDNSPolicy(DNSPolicyConfig(), logging.getLogger("dns-policy-test"))
        calls = []

        def ps(script):
            calls.append(script)
            if "Get-DnsClientDohServerAddress" in script:
                return json.dumps({
                    "ServerAddress": "1.1.1.1",
                    "DohTemplate": "https://cloudflare-dns.com/dns-query",
                    "AllowFallbackToUdp": False,
                    "AutoUpgrade": False,
                })
            if "Add-DnsClientNrptRule" in script:
                return json.dumps({
                    "Name": "{DPIveil-test-rule}",
                    "Namespace": ["discord.com", ".discord.com"],
                    "NameServers": ["1.1.1.1"],
                })
            return ""

        with patch("dpiveil.dns_policy._powershell", ps), patch("dpiveil.dns_policy.flush_dns_cache"):
            policy.start()
            self.assertEqual(policy.rule_names, ["{DPIveil-test-rule}"])
            policy.stop()

        joined = "\n".join(calls)
        self.assertIn("Set-DnsClientDohServerAddress", joined)
        self.assertIn("Add-DnsClientNrptRule", joined)
        self.assertIn("Remove-DnsClientNrptRule -Name '{DPIveil-test-rule}'", joined)
        self.assertIn("-AutoUpgrade $False", joined)


if __name__ == "__main__":
    unittest.main()
