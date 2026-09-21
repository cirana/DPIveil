"""Temporary Windows NRPT + native DoH policy for Discord namespaces."""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass


def _powershell(script: str) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "PowerShell command failed").strip())
    return result.stdout.strip()


def flush_dns_cache():
    result = subprocess.run(
        ["ipconfig", "/flushdns"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise OSError("ipconfig /flushdns failed; Windows DNS cache was not cleared")


@dataclass(frozen=True)
class DNSPolicyConfig:
    enabled: bool = True
    resolver: str = "1.1.1.1"
    doh_template: str = "https://cloudflare-dns.com/dns-query"
    allow_fallback_to_udp: bool = False
    domains: tuple[str, ...] = (
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "discord.media",
        "discordcdn.com",
        "discord.dev",
        "discord.new",
        "discord.gift",
        "discordstatus.com",
        "dis.gd",
        "discord.co",
        "discord-attachments-uploads-prd.storage.googleapis.com",
    )

    @classmethod
    def from_options(cls, options):
        if not isinstance(options, dict):
            raise ValueError("dns_policy must be an object")
        data = dict(options)
        domains = data.pop("domains", None)
        config = cls(**data)
        if type(config.enabled) is not bool:
            raise ValueError("dns_policy.enabled must be boolean")
        if type(config.allow_fallback_to_udp) is not bool:
            raise ValueError("dns_policy.allow_fallback_to_udp must be boolean")
        if not isinstance(config.resolver, str) or not config.resolver:
            raise ValueError("dns_policy.resolver must be a non-empty IP address")
        if not isinstance(config.doh_template, str) or not config.doh_template.startswith("https://"):
            raise ValueError("dns_policy.doh_template must be an HTTPS URL")
        if domains is not None:
            if not isinstance(domains, list) or not domains or any(
                not isinstance(domain, str) or not domain.strip() for domain in domains
            ):
                raise ValueError("dns_policy.domains must be a non-empty list of hostnames")
            config = cls(
                enabled=config.enabled,
                resolver=config.resolver,
                doh_template=config.doh_template,
                allow_fallback_to_udp=config.allow_fallback_to_udp,
                domains=tuple(domain.lower().rstrip(".") for domain in domains),
            )
        return config


class WindowsDNSPolicy:
    MARKER = "DPIveil temporary Discord DNS policy"

    def __init__(self, config: DNSPolicyConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.rule_names: list[str] = []
        self.original_doh = None
        self.doh_was_present = False
        self.started = False

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _snapshot_doh(self):
        resolver = self._ps_quote(self.config.resolver)
        script = (
            f"$x = Get-DnsClientDohServerAddress -ServerAddress {resolver} "
            "-ErrorAction SilentlyContinue; "
            "if ($null -ne $x) { "
            "$x | Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade "
            "| ConvertTo-Json -Compress }"
        )
        raw = _powershell(script)
        if not raw:
            self.doh_was_present = False
            self.original_doh = None
            return
        data = json.loads(raw)
        if isinstance(data, list):
            data = data[0] if data else None
        self.doh_was_present = bool(data)
        self.original_doh = data

    def _configure_doh(self):
        resolver = self._ps_quote(self.config.resolver)
        template = self._ps_quote(self.config.doh_template)
        fallback = "$True" if self.config.allow_fallback_to_udp else "$False"
        if self.doh_was_present:
            script = (
                f"Set-DnsClientDohServerAddress -ServerAddress {resolver} "
                f"-DohTemplate {template} -AllowFallbackToUdp {fallback} "
                "-AutoUpgrade $True -Confirm:$False | Out-Null"
            )
        else:
            script = (
                f"Add-DnsClientDohServerAddress -ServerAddress {resolver} "
                f"-DohTemplate {template} -AllowFallbackToUdp {fallback} "
                "-AutoUpgrade $True -Confirm:$False | Out-Null"
            )
        _powershell(script)

    def _cleanup_stale_rules(self):
        marker = self._ps_quote(self.MARKER)
        _powershell(
            f"Get-DnsClientNrptRule -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.Comment -eq {marker} }} | "
            "ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }"
        )

    def _add_rule(self):
        namespaces = []
        for domain in self.config.domains:
            namespaces.extend((domain, "." + domain))
        namespaces = tuple(dict.fromkeys(namespaces))
        namespace_ps = "@(" + ",".join(self._ps_quote(item) for item in namespaces) + ")"
        resolver = self._ps_quote(self.config.resolver)
        marker = self._ps_quote(self.MARKER)
        display = self._ps_quote("DPIveil Discord DoH")
        raw = _powershell(
            f"$r = Add-DnsClientNrptRule -Namespace {namespace_ps} "
            f"-NameServers {resolver} -DisplayName {display} -Comment {marker} -PassThru; "
            "$r | Select-Object Name,Namespace,NameServers | ConvertTo-Json -Compress"
        )
        data = json.loads(raw)
        rows = data if isinstance(data, list) else [data]
        self.rule_names = [str(row["Name"]) for row in rows if row and row.get("Name")]
        if not self.rule_names:
            raise RuntimeError("Windows did not return an NRPT rule identifier")

    def start(self):
        if not self.config.enabled:
            return
        self._snapshot_doh()
        self._cleanup_stale_rules()
        try:
            self._configure_doh()
            self._add_rule()
            flush_dns_cache()
        except Exception:
            self.stop()
            raise
        self.started = True
        self.logger.info(
            "Windows DNS policy active | Discord -> %s via DoH | fallback UDP=%s",
            self.config.resolver,
            "allowed" if self.config.allow_fallback_to_udp else "disabled",
        )

    def _restore_doh(self):
        resolver = self._ps_quote(self.config.resolver)
        if self.doh_was_present and self.original_doh:
            template = self._ps_quote(str(self.original_doh.get("DohTemplate") or self.config.doh_template))
            fallback = "$True" if bool(self.original_doh.get("AllowFallbackToUdp")) else "$False"
            auto = "$True" if bool(self.original_doh.get("AutoUpgrade")) else "$False"
            _powershell(
                f"Set-DnsClientDohServerAddress -ServerAddress {resolver} "
                f"-DohTemplate {template} -AllowFallbackToUdp {fallback} "
                f"-AutoUpgrade {auto} -Confirm:$False | Out-Null"
            )
        elif not self.doh_was_present:
            # 1.1.1.1 is normally built into Windows' known DoH list. If it was
            # not present before DPIveil, remove only the entry we added.
            _powershell(
                f"Remove-DnsClientDohServerAddress -ServerAddress {resolver} "
                "-Confirm:$False -ErrorAction SilentlyContinue"
            )

    def stop(self):
        errors = []
        for name in list(self.rule_names):
            try:
                _powershell(
                    f"Remove-DnsClientNrptRule -Name {self._ps_quote(name)} "
                    "-Force -ErrorAction SilentlyContinue"
                )
            except OSError as exc:
                errors.append(exc)
        self.rule_names = []

        if self.original_doh is not None or not self.doh_was_present:
            try:
                self._restore_doh()
            except OSError as exc:
                errors.append(exc)

        try:
            flush_dns_cache()
        except OSError as exc:
            errors.append(exc)

        if self.started:
            if errors:
                self.logger.warning("DNS policy cleanup completed with %s error(s)", len(errors))
            else:
                self.logger.info("Windows DNS policy removed; previous DoH settings restored.")
        self.started = False
