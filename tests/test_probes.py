import json
import ssl
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from dpiveil.probes import resolve_verified


class VerifiedDohTests(unittest.TestCase):
    def setUp(self):
        self.answer = json.dumps({
            "Status": 0,
            "Answer": [
                {"type": 1, "data": "162.159.138.232"},
                {"type": 1, "data": "162.159.128.233"},
                {"type": 28, "data": "2606:4700::6810:90"},
            ],
        }).encode("utf-8")

    def test_python_https_success_does_not_run_curl(self):
        with (
            patch("dpiveil.probes.https_request", return_value=(200, self.answer)) as python_request,
            patch("dpiveil.probes.subprocess.run") as curl_run,
        ):
            addresses = resolve_verified("discord.com", 4, 2)

        self.assertEqual(addresses, ["162.159.128.233", "162.159.138.232"])
        python_request.assert_called_once()
        self.assertEqual(python_request.call_args.args[1], "1.1.1.1")
        curl_run.assert_not_called()

    def test_certificate_error_retries_same_doh_query_with_curl(self):
        curl_result = subprocess.CompletedProcess(
            args=["curl.exe"],
            returncode=0,
            stdout=self.answer + b"\n200",
            stderr=b"",
        )
        with (
            patch(
                "dpiveil.probes.https_request",
                side_effect=ssl.SSLCertVerificationError("missing issuer"),
            ) as python_request,
            patch("dpiveil.probes.subprocess.run", return_value=curl_result) as curl_run,
            self.assertLogs("dpiveil.probes", level="INFO") as logs,
        ):
            addresses = resolve_verified("discord.com", 4, 2)

        self.assertEqual(addresses, ["162.159.128.233", "162.159.138.232"])
        python_request.assert_called_once()
        command = curl_run.call_args.args[0]
        self.assertEqual(Path(command[0]).name.lower(), "curl.exe")
        self.assertEqual(command[1], "--disable")
        self.assertIn("--resolve", command)
        self.assertIn("cloudflare-dns.com:443:1.1.1.1", command)
        self.assertIn("https://cloudflare-dns.com/dns-query?name=discord.com&type=A", command)
        self.assertIn("Accept: application/dns-json", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("-k", command)
        self.assertTrue(any("certificate verification failed" in row for row in logs.output))
        self.assertTrue(any("verified DNS answer" in row for row in logs.output))

    def test_python_certificate_and_curl_failures_keep_verified_dns_error(self):
        failed_curl = subprocess.CompletedProcess(
            args=["curl.exe"],
            returncode=60,
            stdout=b"",
            stderr=b"certificate verify failed",
        )
        with (
            patch(
                "dpiveil.probes.https_request",
                side_effect=ssl.SSLCertVerificationError("Python missing issuer"),
            ) as python_request,
            patch("dpiveil.probes.subprocess.run", return_value=failed_curl) as curl_run,
            self.assertLogs("dpiveil.probes", level="WARNING") as logs,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Verified DNS unavailable:.*Python TLS certificate verification failed.*curl.exe fallback failed",
            ):
                resolve_verified("discord.com", 4, 2)

        self.assertEqual(python_request.call_count, 2)
        self.assertEqual(curl_run.call_count, 2)
        self.assertTrue(any("curl.exe fallback failed" in row for row in logs.output))

    def test_curl_fallback_rejects_unsuccessful_dns_status(self):
        unsuccessful_answer = json.dumps({
            "Status": 3,
            "Answer": [{"type": 1, "data": "192.0.2.1"}],
        }).encode("utf-8")
        curl_result = subprocess.CompletedProcess(
            args=["curl.exe"],
            returncode=0,
            stdout=unsuccessful_answer + b"\n200",
            stderr=b"",
        )
        with (
            patch(
                "dpiveil.probes.https_request",
                side_effect=ssl.SSLCertVerificationError("missing issuer"),
            ),
            patch("dpiveil.probes.subprocess.run", return_value=curl_result),
        ):
            with self.assertRaisesRegex(RuntimeError, "Verified DNS unavailable"):
                resolve_verified("discord.com", 4, 2)

    def test_non_certificate_network_error_does_not_run_curl(self):
        with (
            patch("dpiveil.probes.https_request", side_effect=TimeoutError("network timeout")) as python_request,
            patch("dpiveil.probes.subprocess.run") as curl_run,
        ):
            with self.assertRaisesRegex(RuntimeError, "Verified DNS unavailable"):
                resolve_verified("discord.com", 4, 2)

        self.assertEqual(python_request.call_count, 2)
        curl_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
