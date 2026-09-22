"""Independent, extensible strategy definitions for automatic selection."""
from __future__ import annotations

from dataclasses import dataclass

from dpiveil.strategies.advanced import (
    FakeBadSeqConfig,
    FakeBadSeqStrategy,
    IPFragment2Config,
    IPFragment2Strategy,
    SynDataStrategy,
)
from dpiveil.strategies.zapret_compat import ZapretCompatConfig, ZapretCompatStrategy


LEGACY_KINDS = frozenset({"multisplit", "multidisorder", "fake_ttl"})
ADVANCED_KINDS = frozenset({"fake+badseq", "fake_badseq", "syndata", "ipfrag2", "ipfrag2-8"})
SUPPORTED_KINDS = LEGACY_KINDS | ADVANCED_KINDS


def _canonical_kind(kind: str) -> str:
    return {
        "fake+badseq": "fake_badseq",
        "ipfrag2-8": "ipfrag2",
    }.get(kind, kind)


@dataclass(frozen=True)
class Candidate:
    name: str
    kind: str
    priority: int
    split_pos: int = 2
    ttl: int = 1
    badseq_increment: int = -10000
    badack_increment: int = -66000
    ipfrag_pos: int = 8
    transport: str = "auto"
    # ``protocol`` is accepted as a readable configuration alias for callers
    # that use the terminology from the blockcheck output.
    protocol: str | None = None

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Candidate name must not be empty")
        if self.kind not in SUPPORTED_KINDS:
            raise ValueError(f"Unknown candidate kind: {self.kind}")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise ValueError("Candidate priority must be an integer")
        if not 0 < self.split_pos < 65536 or not 0 < self.ttl <= 255:
            raise ValueError("Invalid split position or TTL")
        if not isinstance(self.badseq_increment, int) or not isinstance(self.badack_increment, int):
            raise ValueError("Bad sequence increments must be integers")
        ipfrag_pos = self.ipfrag_pos
        # Some blockcheck exports call the fragment point ``split_pos``.
        if _canonical_kind(self.kind) == "ipfrag2" and ipfrag_pos == 8 and self.split_pos != 2:
            ipfrag_pos = self.split_pos
            object.__setattr__(self, "ipfrag_pos", ipfrag_pos)
        if ipfrag_pos < 8 or ipfrag_pos % 8:
            raise ValueError("ipfrag_pos must be a multiple of 8 and at least 8")
        transport = self.protocol if self.protocol is not None else self.transport
        if transport == "quic":
            transport = "udp"
        if transport == "auto":
            transport = "udp" if _canonical_kind(self.kind) == "ipfrag2" else "tcp"
        if transport not in {"tcp", "udp"}:
            raise ValueError("Candidate transport must be tcp, udp, or auto")
        if _canonical_kind(self.kind) == "ipfrag2" and transport != "udp":
            raise ValueError("ipfrag2 candidates must use UDP")
        if _canonical_kind(self.kind) != "ipfrag2" and transport != "tcp":
            raise ValueError("TCP candidates cannot use UDP")
        object.__setattr__(self, "transport", transport)

    @property
    def canonical_kind(self) -> str:
        return _canonical_kind(self.kind)


class CandidateStrategy:
    """Build one strategy from a data-only candidate definition."""

    def __init__(self, candidate: Candidate, domains=("discord.com",)):
        self.candidate = candidate
        if isinstance(domains, str):
            domains = (domains,)
        self.domains = tuple(domain.lower() for domain in domains)
        self.name = candidate.name

        if candidate.canonical_kind in LEGACY_KINDS:
            self._strategy = ZapretCompatStrategy(ZapretCompatConfig(
                mode=candidate.canonical_kind,
                split_pos=candidate.split_pos,
                fake_ttl=candidate.ttl,
                target_domains=self.domains,
            ))
        elif candidate.canonical_kind == "fake_badseq":
            self._strategy = FakeBadSeqStrategy(FakeBadSeqConfig(
                target_domains=self.domains,
                badseq_increment=candidate.badseq_increment,
                badack_increment=candidate.badack_increment,
            ))
        elif candidate.canonical_kind == "syndata":
            self._strategy = SynDataStrategy()
        elif candidate.canonical_kind == "ipfrag2":
            self._strategy = IPFragment2Strategy(IPFragment2Config(candidate.ipfrag_pos))
        else:  # guarded by Candidate.__post_init__
            raise ValueError(f"Unknown candidate kind: {candidate.kind}")

    def process(self, packet, force_ip=False):
        if force_ip and hasattr(self._strategy, "process_forced"):
            return self._strategy.process_forced(packet)
        return self._strategy.process(packet)
