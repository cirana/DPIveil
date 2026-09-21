from __future__ import annotations

import logging
import sys
from pathlib import Path

from dpiveil import __version__
from dpiveil.engine import PassthroughEngine
from dpiveil.profiles import load_profile
from dpiveil.system import is_admin, is_windows

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
DEFAULT_PROFILE = ROOT / "profiles" / "default.json"


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("dpiveil")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    file_handler = logging.FileHandler(LOG_DIR / "dpiveil.log", encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


def check_pydivert() -> bool:
    try:
        import pydivert  # noqa: F401
    except ImportError:
        return False
    return True


def run() -> int:
    logger = configure_logging()

    print()
    print("DPIveil")
    print(f"v{__version__}")
    print("-" * 42)

    if not is_windows():
        logger.error("DPIveil currently supports Windows only.")
        return 1

    if not is_admin():
        logger.error("Administrator privileges are required.")
        logger.info("Open CMD/PowerShell as administrator and run the program again.")
        return 1

    if not check_pydivert():
        logger.error("PyDivert is not installed.")
        logger.info("Run: pip install -r requirements.txt")
        return 1

    try:
        profile = load_profile(DEFAULT_PROFILE)
    except (OSError, KeyError, ValueError) as exc:
        logger.error("Could not load default profile: %s", exc)
        return 1

    logger.info("DPIveil started.")
    logger.info("Profile: %s", profile.name)
    logger.info("Filter: %s", profile.filter)
    logger.info("Mode: passthrough (packets are not modified)")
    logger.info("Press Ctrl+C to stop.")

    engine = PassthroughEngine(profile.filter, logger)

    try:
        engine.run()
    except KeyboardInterrupt:
        print()
        logger.info("Stopping DPIveil...")
    except OSError as exc:
        logger.error("WinDivert error: %s", exc)
        return 1
    finally:
        logger.info(
            "Final stats: %s packets | %s bytes | %s send errors",
            f"{engine.stats.packets:,}",
            f"{engine.stats.bytes:,}",
            engine.stats.send_errors,
        )
        logger.info("DPIveil stopped cleanly.")

    return 0


if __name__ == "__main__":
    sys.exit(run())
