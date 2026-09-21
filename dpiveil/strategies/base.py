from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable


class PacketStrategy(ABC):
    name = "base"

    @abstractmethod
    def process(self, packet) -> Iterable:
        """Return one or more packets to send."""
        raise NotImplementedError
