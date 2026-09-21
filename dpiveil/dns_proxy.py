"""Local DNS proxy and temporary Windows adapter DNS configuration."""
from __future__ import annotations

import json
import logging
import socket
import socketserver
import subprocess
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class DNSProxyConfig:
    enabled: bool = True
    listen_host: str = "127.0.0.1"
    listen_port: int = 53
    upstream_ipv4: str = "1.1.1.1"
    upstream_port: int = 53
    timeout: float = 4.0

    @classmethod
    def from_options(cls, options):
        if not isinstance(options, dict):
            raise ValueError("dns_proxy must be an object")
        config = cls(**options)
        if type(config.enabled) is not bool:
            raise ValueError("dns_proxy.enabled must be boolean")
        if not 1 <= int(config.listen_port) <= 65535 or not 1 <= int(config.upstream_port) <= 65535:
            raise ValueError("DNS proxy ports must be between 1 and 65535")
        return config


def _powershell(script: str) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "PowerShell command failed").strip())
    return result.stdout.strip()


def flush_dns_cache():
    result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10, check=False)
    if result.returncode != 0:
        raise OSError("ipconfig /flushdns failed; Windows DNS cache was not cleared")


def _read_dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    next_offset = offset
    seen = set()

    while offset < len(message):
        if offset in seen:
            raise ValueError("DNS compression loop")
        seen.add(offset)
        length = message[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("Truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break
        if offset + length > len(message):
            raise ValueError("Truncated DNS label")
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length
        if not jumped:
            next_offset = offset

    return ".".join(labels).lower(), next_offset


def parse_dns_addresses(message: bytes) -> tuple[str | None, tuple[str, ...]]:
    """Return the first queried hostname and all A/AAAA answers in a DNS reply."""
    if len(message) < 12:
        return None, ()

    qdcount = int.from_bytes(message[4:6], "big")
    ancount = int.from_bytes(message[6:8], "big")
    offset = 12
    query_name = None

    try:
        for index in range(qdcount):
            name, offset = _read_dns_name(message, offset)
            if index == 0:
                query_name = name
            if offset + 4 > len(message):
                return query_name, ()
            offset += 4

        addresses = []
        for _ in range(ancount):
            _, offset = _read_dns_name(message, offset)
            if offset + 10 > len(message):
                break
            rtype = int.from_bytes(message[offset:offset + 2], "big")
            rclass = int.from_bytes(message[offset + 2:offset + 4], "big")
            rdlength = int.from_bytes(message[offset + 8:offset + 10], "big")
            offset += 10
            if offset + rdlength > len(message):
                break
            rdata = message[offset:offset + rdlength]
            offset += rdlength

            if rclass != 1:
                continue
            if rtype == 1 and rdlength == 4:
                addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == 28 and rdlength == 16:
                addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))

        return query_name, tuple(dict.fromkeys(addresses))
    except (UnicodeDecodeError, ValueError, OSError):
        return query_name, ()


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, client = self.request
        proxy = self.server.proxy
        if not data:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(proxy.config.timeout)
                upstream.sendto(data, (proxy.config.upstream_ipv4, proxy.config.upstream_port))
                reply, _ = upstream.recvfrom(65535)
            proxy.observe_reply(reply)
            client.sendto(reply, self.client_address)
            proxy.queries += 1
            proxy.replies += 1
        except OSError as exc:
            proxy.failures += 1
            proxy.logger.warning("Local DNS UDP proxy failed: %s", exc)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        proxy = self.server.proxy
        try:
            header = self.request.recv(2)
            if len(header) != 2:
                return
            size = int.from_bytes(header, "big")
            payload = b""
            while len(payload) < size:
                chunk = self.request.recv(size - len(payload))
                if not chunk:
                    return
                payload += chunk
            with socket.create_connection(
                (proxy.config.upstream_ipv4, proxy.config.upstream_port),
                timeout=proxy.config.timeout,
            ) as upstream:
                upstream.sendall(header + payload)
                reply_header = upstream.recv(2)
                if len(reply_header) != 2:
                    return
                reply_size = int.from_bytes(reply_header, "big")
                reply = b""
                while len(reply) < reply_size:
                    chunk = upstream.recv(reply_size - len(reply))
                    if not chunk:
                        return
                    reply += chunk
            proxy.observe_reply(reply)
            self.request.sendall(reply_header + reply)
            proxy.queries += 1
            proxy.replies += 1
        except OSError as exc:
            proxy.failures += 1
            proxy.logger.warning("Local DNS TCP proxy failed: %s", exc)


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LocalDNSProxy:
    def __init__(self, config: DNSProxyConfig, logger: logging.Logger, answer_callback=None):
        self.config = config
        self.logger = logger
        self.answer_callback = answer_callback
        self.queries = 0
        self.replies = 0
        self.failures = 0
        self._udp = None
        self._tcp = None
        self._threads = []
        self._snapshot = []

    def observe_reply(self, reply: bytes):
        if self.answer_callback is None:
            return
        host, addresses = parse_dns_addresses(reply)
        if host and addresses:
            try:
                self.answer_callback(host, addresses)
            except Exception as exc:
                self.logger.debug("DNS answer callback failed: %s", exc)

    def _active_adapters(self):
        script = r"""
$items = Get-NetIPConfiguration | Where-Object {
  $_.NetAdapter.Status -eq 'Up' -and ($null -ne $_.IPv4DefaultGateway -or $null -ne $_.IPv6DefaultGateway)
} | ForEach-Object {
  $idx = $_.InterfaceIndex
  $servers = @(Get-DnsClientServerAddress -InterfaceIndex $idx | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
  [pscustomobject]@{ InterfaceIndex=$idx; InterfaceAlias=$_.InterfaceAlias; ServerAddresses=$servers }
}
$items | ConvertTo-Json -Compress
"""
        raw = _powershell(script)
        if not raw:
            return []
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]

    def _set_dns(self, interface_index: int, addresses):
        quoted = ",".join("'" + str(x).replace("'", "''") + "'" for x in addresses)
        if addresses:
            _powershell(
                f"Set-DnsClientServerAddress -InterfaceIndex {int(interface_index)} "
                f"-ServerAddresses @({quoted})"
            )
        else:
            _powershell(
                f"Set-DnsClientServerAddress -InterfaceIndex {int(interface_index)} -ResetServerAddresses"
            )

    def start(self):
        if not self.config.enabled:
            return
        self._udp = _ThreadingUDPServer((self.config.listen_host, self.config.listen_port), _UDPHandler)
        self._tcp = _ThreadingTCPServer((self.config.listen_host, self.config.listen_port), _TCPHandler)
        self._udp.proxy = self
        self._tcp.proxy = self
        for server, name in ((self._udp, "dpiveil-dns-udp"), (self._tcp, "dpiveil-dns-tcp")):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

        self._snapshot = self._active_adapters()
        if not self._snapshot:
            self.stop()
            raise RuntimeError("No active Windows network adapter with a default gateway was found")

        changed = []
        try:
            for adapter in self._snapshot:
                idx = int(adapter["InterfaceIndex"])
                self._set_dns(idx, [self.config.listen_host])
                changed.append(idx)
                self.logger.info(
                    "Windows DNS -> local proxy | adapter=%s (%s) | previous=%s",
                    adapter.get("InterfaceAlias", "?"),
                    idx,
                    ", ".join(adapter.get("ServerAddresses") or []) or "automatic",
                )
            flush_dns_cache()
        except Exception:
            for adapter in self._snapshot:
                if int(adapter["InterfaceIndex"]) in changed:
                    try:
                        self._set_dns(int(adapter["InterfaceIndex"]), adapter.get("ServerAddresses") or [])
                    except OSError:
                        pass
            self.stop()
            raise

        self.logger.info(
            "Local DNS proxy active | %s:%s -> %s:%s",
            self.config.listen_host,
            self.config.listen_port,
            self.config.upstream_ipv4,
            self.config.upstream_port,
        )

    def stop(self):
        for server in (self._udp, self._tcp):
            if server is not None:
                try:
                    server.shutdown()
                    server.server_close()
                except OSError:
                    pass
        self._udp = self._tcp = None

        if self._snapshot:
            for adapter in self._snapshot:
                try:
                    self._set_dns(int(adapter["InterfaceIndex"]), adapter.get("ServerAddresses") or [])
                    self.logger.info(
                        "Windows DNS restored | adapter=%s (%s)",
                        adapter.get("InterfaceAlias", "?"),
                        adapter.get("InterfaceIndex", "?"),
                    )
                except OSError as exc:
                    self.logger.error("Could not restore Windows DNS settings: %s", exc)
            try:
                flush_dns_cache()
            except OSError as exc:
                self.logger.warning("Could not flush DNS cache after restore: %s", exc)
            self._snapshot = []

        self.logger.info(
            "Local DNS proxy: %s queries, %s replies, %s failures",
            self.queries, self.replies, self.failures,
        )
