from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    filter: str


def load_profile(path: Path) -> Profile:
    data = json.loads(path.read_text(encoding="utf-8"))

    return Profile(
        name=str(data["name"]),
        description=str(data.get("description", "")),
        filter=str(data["filter"]),
    )
