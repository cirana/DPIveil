from __future__ import annotations

import ctypes
import os
import platform


def is_windows() -> bool:
    return os.name == "nt" and platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False
