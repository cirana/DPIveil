"""Runtime paths and frozen-build helpers."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_root() -> Path:
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def log_dir() -> Path:
    if not is_frozen():
        return app_dir() / "logs"

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "DPIveil" / "logs"
    return app_dir() / "logs"


def configure_pydivert() -> tuple[bool, str | None]:
    """Prepare PyDivert and point frozen builds at external WinDivert files."""
    try:
        import pydivert  # noqa: F401
    except ImportError:
        return False, "PyDivert is not installed."

    if not is_frozen():
        return True, None

    dll_path = app_dir() / "WinDivert64.dll"
    driver_path = app_dir() / "WinDivert64.sys"
    missing = [path.name for path in (dll_path, driver_path) if not path.is_file()]
    if missing:
        return False, (
            "Required WinDivert file(s) are missing next to DPIveil.exe: "
            + ", ".join(missing)
        )

    try:
        from pydivert import windivert_dll
        windivert_dll.DLL_PATH = str(dll_path)
    except (ImportError, AttributeError) as exc:
        return False, f"Could not configure external WinDivert runtime: {exc}"

    return True, None
