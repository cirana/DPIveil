"""Safe local cache for verified automatic DPI strategy selections."""
from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path

from dpiveil.runtime import log_dir


CACHE_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_ENTRIES = 32


def default_cache_path() -> Path:
    return log_dir() / "strategy-cache.json"


def network_identity(runner=subprocess.run) -> str | None:
    """Return a stable, non-sensitive identity for the active IPv4 route.

    The route's gateway and interface are enough to distinguish common home,
    hotspot, VPN, and office networks without persisting an SSID or account
    identifier. If Windows cannot provide a default route, caching is simply
    disabled for this run.
    """
    if os.name != "nt":
        return None
    try:
        result = runner(
            ["route.exe", "print", "-4", "0.0.0.0"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, TypeError):
        return None
    if getattr(result, "returncode", 1) != 0:
        return None

    routes = []
    for line in (getattr(result, "stdout", "") or "").splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "0.0.0.0" or fields[1] != "0.0.0.0":
            continue
        gateway, interface = fields[2], fields[3]
        if gateway in {"0.0.0.0", "On-link", "on-link"}:
            continue
        routes.append((gateway, interface))
    if not routes:
        return None
    return "|".join(f"{gateway}@{interface}" for gateway, interface in sorted(set(routes)))


def network_key(identity: str | None = None) -> str | None:
    identity = network_identity() if identity is None else identity
    if not isinstance(identity, str) or not identity.strip():
        return None
    return hashlib.sha256(identity.strip().encode("utf-8")).hexdigest()


def _candidate_payload(candidate) -> dict[str, object]:
    if is_dataclass(candidate):
        return asdict(candidate)
    return {
        key: getattr(candidate, key)
        for key in (
            "name",
            "kind",
            "priority",
            "split_pos",
            "ttl",
            "badseq_increment",
            "badack_increment",
            "ipfrag_pos",
            "transport",
            "protocol",
        )
        if hasattr(candidate, key)
    }


def candidate_signature(candidate) -> str:
    encoded = json.dumps(
        _candidate_payload(candidate),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def config_signature(config) -> str:
    payload = {
        "host": str(config.host).lower(),
        "candidates": [
            _candidate_payload(candidate)
            for candidate in config.candidates
        ],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class StrategyCache:
    """Best-effort persistent cache; cache errors never stop DPIveil."""

    def __init__(self, path: str | Path | None = None, max_age_seconds=DEFAULT_MAX_AGE_SECONDS, logger=None):
        self.path = Path(path) if path is not None else default_cache_path()
        self.max_age_seconds = float(max_age_seconds)
        self.logger = logger

    def _warn(self, message, *args):
        if self.logger is not None:
            self.logger.warning(message, *args)

    def _read(self) -> dict[str, object]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            self._warn("Strategy cache ignored: %s", exc)
            return {}
        if not isinstance(raw, dict):
            self._warn("Strategy cache ignored: root is not an object")
            return {}
        return raw

    def load(self, key: str | None, config):
        """Return the configured candidate cached for a network key, if valid."""
        if not key:
            return None
        data = self._read()
        if data.get("version") != CACHE_VERSION:
            return None
        entries = data.get("entries")
        if not isinstance(entries, dict):
            return None
        entry = entries.get(key)
        if not isinstance(entry, dict):
            return None
        try:
            saved_at = float(entry["saved_at"])
        except (KeyError, TypeError, ValueError):
            return None
        now = time.time()
        if (
            not math.isfinite(saved_at)
            or saved_at > now + 300
            or now - saved_at > self.max_age_seconds
        ):
            return None
        if (
            entry.get("host") != str(config.host).lower()
            or entry.get("config_signature") != config_signature(config)
        ):
            return None
        name = entry.get("strategy")
        signature = entry.get("candidate_signature")
        if not isinstance(name, str) or not isinstance(signature, str):
            return None
        for candidate in config.candidates:
            if candidate.name == name and candidate_signature(candidate) == signature:
                return candidate
        return None

    def save(self, key: str | None, config, candidate) -> bool:
        """Persist a verified selection without making cache writes mandatory."""
        if not key:
            return False
        try:
            data = self._read()
            entries = data.get("entries")
            if not isinstance(entries, dict):
                entries = {}
            entries[key] = {
                "host": str(config.host).lower(),
                "strategy": candidate.name,
                "candidate_signature": candidate_signature(candidate),
                "config_signature": config_signature(config),
                "saved_at": time.time(),
            }
            valid_entries = {
                entry_key: entry
                for entry_key, entry in entries.items()
                if isinstance(entry_key, str) and isinstance(entry, dict)
            }
            def saved_time(item):
                try:
                    return float(item[1].get("saved_at", 0) or 0)
                except (TypeError, ValueError):
                    return 0.0
            valid_entries = dict(
                sorted(valid_entries.items(), key=saved_time, reverse=True)[:MAX_ENTRIES]
            )
            payload = {
                "version": CACHE_VERSION,
                "entries": valid_entries,
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(
                json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
            return True
        except (OSError, UnicodeError, TypeError, ValueError) as exc:
            self._warn("Could not save strategy cache: %s", exc)
            return False

