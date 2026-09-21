from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    filter: str
    strategy: str
    strategy_options: dict[str, object]
    dns_policy: dict[str, object] = field(default_factory=dict)


def load_profile(path: Path) -> Profile:
    data = json.loads(path.read_text(encoding="utf-8"))

    return Profile(
        name=str(data["name"]),
        description=str(data.get("description", "")),
        filter=str(data["filter"]),
        strategy=str(data.get("strategy", "passthrough")),
        strategy_options=dict(data.get("strategy_options", {})),
        dns_policy=dict(data.get("dns_policy", {})),
    )
