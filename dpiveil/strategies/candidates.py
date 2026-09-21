"""Independent, configurable ClientHello strategies for the HTTPS probe."""
from __future__ import annotations

from dataclasses import dataclass

from dpiveil.strategies.zapret_compat import ZapretCompatConfig, ZapretCompatStrategy


@dataclass(frozen=True)
class Candidate:
    name: str
    kind: str
    priority: int
    split_pos: int = 2
    ttl: int = 1

    def __post_init__(self):
        if self.kind not in {"multisplit", "multidisorder", "fake_ttl"}:
            raise ValueError(f"Unknown candidate kind: {self.kind}")
        if not 0 < self.split_pos < 65536 or not 0 < self.ttl <= 255:
            raise ValueError("Invalid split position or TTL")



class CandidateStrategy:
    def __init__(self, candidate: Candidate, domain: str = "discord.com"):
        self.candidate = candidate
        self.domain = domain
        self.name = candidate.name
        self._strategy = ZapretCompatStrategy(ZapretCompatConfig(
            mode=candidate.kind, split_pos=candidate.split_pos,
            fake_ttl=candidate.ttl, target_domains=(domain,),
        ))

    def process(self, packet):
        return self._strategy.process(packet)
