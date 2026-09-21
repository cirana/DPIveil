import logging
import sys
import types
import unittest
from unittest.mock import patch

from test_tls_fragment import FakePacket

with patch.dict(sys.modules, {"pydivert": types.SimpleNamespace(Packet=FakePacket, WinDivert=None)}):
    from dpiveil.dns_redirect import DNSConfig, DNSRedirect, flush_dns_cache, question_key
    from dpiveil import app as app_module


def dns_message(txid=0x1234, response=False, qname=b"\x07discord\x03com\x00", qtype=1):
    flags = 0x8180 if response else 0x0100
    return (txid.to_bytes(2, "big") + flags.to_bytes(2, "big") +
            b"\x00\x01" + (b"\x00\x01" if response else b"\x00\x00") +
            b"\x00\x00\x00\x00" + qname + qtype.to_bytes(2, "big") + b"\x00\x01")


class DNSPacket:
    def __init__(self, src, dst, src_port, dst_port, payload, inbound=False):
        self.src_addr = src
        self.dst_addr = dst
        self.udp = types.SimpleNamespace(src_port=src_port, dst_port=dst_port)
        self.payload = payload
        self.is_inbound = inbound
        self.is_outbound = not inbound
        self.ip = types.SimpleNamespace(src_addr=src, dst_addr=dst)
        self.checksummed = False

    def recalculate_checksums(self):
        self.checksummed = True


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.config = DNSConfig.from_options({"enabled": True})
        self.redirect = DNSRedirect(self.config, logging.getLogger("dns-test"), clock=lambda: self.now)

    def test_ipv4_roundtrip_preserves_original_resolver_and_ports(self):
        query = DNSPacket("192.0.2.20", "192.0.2.53", 50000, 53, dns_message())
        self.assertIs(self.redirect.process(query), query)
        self.assertEqual((query.ip.dst_addr, query.udp.dst_port), ("77.88.8.8", 1253))
        self.assertTrue(query.checksummed)

        response = DNSPacket("77.88.8.8", "192.0.2.20", 1253, 50000,
                             dns_message(response=True), inbound=True)
        self.assertIs(self.redirect.process(response), response)
        self.assertEqual((response.ip.src_addr, response.udp.src_port), ("192.0.2.53", 53))
        self.assertTrue(response.checksummed)
        self.assertEqual((self.redirect.queries, self.redirect.responses), (1, 1))
        self.assertEqual(self.redirect.pending, {})

    def test_ipv6_redirect_and_reply(self):
        query = DNSPacket("2001:db8::10", "fe80::1", 50505, 53,
                          dns_message(qtype=28))
        self.redirect.process(query)
        self.assertEqual((query.ip.dst_addr, query.udp.dst_port),
                         ("2a02:6b8::feed:ff", 1253))
        response = DNSPacket("2a02:6b8::feed:0ff", "2001:db8::10", 1253, 50505,
                             dns_message(response=True, qtype=28), inbound=True)
        self.redirect.process(response)
        self.assertEqual(response.ip.src_addr, "fe80::1")

    def test_spoofed_and_mismatched_answers_are_not_delivered_as_redirected(self):
        self.redirect.process(DNSPacket("192.0.2.20", "192.0.2.53", 50000, 53,
                                        dns_message()))
        spoof = DNSPacket("192.0.2.53", "192.0.2.20", 53, 50000,
                          dns_message(response=True), inbound=True)
        self.assertIsNone(self.redirect.process(spoof))
        mismatch = DNSPacket("77.88.8.8", "192.0.2.20", 1253, 50000,
                             dns_message(txid=0x9999, response=True), inbound=True)
        self.assertIs(self.redirect.process(mismatch), mismatch)
        self.assertEqual(mismatch.ip.src_addr, "77.88.8.8")
        wrong_question = DNSPacket("192.0.2.53", "192.0.2.20", 53, 50000,
                                   dns_message(response=True, qname=b"\x05other\x03com\x00"), inbound=True)
        self.assertIsNone(self.redirect.process(wrong_question))
        malformed = DNSPacket("192.0.2.53", "192.0.2.20", 53, 50000,
                              dns_message(response=True, qname=b"\xc0\x0c"), inbound=True)
        self.assertIsNone(self.redirect.process(malformed))
        self.assertEqual(self.redirect.spoofed, 1)
        self.assertEqual(len(self.redirect.pending), 1)

    def test_parallel_queries_to_different_servers_keep_reply_mapping(self):
        first = DNSPacket("192.0.2.20", "192.0.2.53", 50000, 53, dns_message())
        second = DNSPacket("192.0.2.20", "192.0.2.54", 50000, 53, dns_message())
        self.redirect.process(first)
        self.redirect.process(second)
        self.assertEqual(first.udp.src_port, 50000)
        self.assertNotEqual(second.udp.src_port, first.udp.src_port)
        second_reply = DNSPacket("77.88.8.8", "192.0.2.20", 1253,
                                 second.udp.src_port, dns_message(response=True), inbound=True)
        self.redirect.process(second_reply)
        self.assertEqual((second_reply.ip.src_addr, second_reply.udp.dst_port),
                         ("192.0.2.54", 50000))
        first_reply = DNSPacket("77.88.8.8", "192.0.2.20", 1253, 50000,
                                dns_message(response=True), inbound=True)
        self.redirect.process(first_reply)
        self.assertEqual(first_reply.ip.src_addr, "192.0.2.53")

    def test_expiry_and_malformed_question(self):
        self.assertIsNone(question_key(dns_message(qname=b"\xc0\x0c"), False))
        self.redirect.process(DNSPacket("192.0.2.20", "192.0.2.53", 50000, 53,
                                        dns_message()))
        self.now = 120.0
        late = DNSPacket("77.88.8.8", "192.0.2.20", 1253, 50000,
                         dns_message(response=True), inbound=True)
        self.assertIs(self.redirect.process(late), late)
        self.assertEqual(self.redirect.pending, {})

    def test_config_filter_and_cache_flush(self):
        self.assertIn("udp.SrcPort == 1253", self.config.packet_filter)
        self.assertIn("udp.DstPort == 53", self.config.packet_filter)
        with self.assertRaises(ValueError):
            DNSConfig.from_options({"enabled": "true"})
        with patch.object(flush_dns_cache.__globals__["subprocess"], "run") as run:
            run.return_value.returncode = 0
            flush_dns_cache()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["ipconfig", "/flushdns"])

    def test_app_starts_dns_flushes_cache_then_probes(self):
        events = []

        class DNSStub:
            def __init__(self, *_):
                pass

            def start(self):
                events.append("dns-start")

            def stop(self):
                events.append("dns-stop")

        def flush():
            events.append("flush")

        def probe(*args):
            events.append("probe")
            return 0

        with patch.dict(app_module.run.__globals__, {
            "is_windows": lambda: True, "is_admin": lambda: True,
            "check_pydivert": lambda: True, "configure_logging": lambda: logging.getLogger("dns-test"),
            "DNSRedirect": DNSStub, "flush_dns_cache": flush, "run_auto": probe,
        }):
            self.assertEqual(app_module.run(), 0)
        self.assertEqual(events, ["dns-start", "flush", "probe", "dns-stop"])


if __name__ == "__main__":
    unittest.main()
