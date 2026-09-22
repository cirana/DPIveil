from __future__ import annotations

import json
import logging
import sys
import threading

from dpiveil import __version__
from dpiveil.autoselect import (
    AutoConfig,
    SessionStrategy,
    diagnose_desktop_endpoints,
    direct_works,
    resolve_system,
    resolve_verified,
    test_candidates,
)
from dpiveil.dns_policy import DNSPolicyConfig, WindowsDNSPolicy
from dpiveil.engine import PacketEngine
from dpiveil.profiles import load_profile
from dpiveil.strategies.tls_fragment import FragmentConfig, TLSClientHelloFragmentStrategy
from dpiveil.strategies.zapret_compat import ZapretCompatConfig, ZapretCompatStrategy
from dpiveil.runtime import configure_pydivert, log_dir, resource_root
from dpiveil.system import is_admin, is_windows, register_console_close_handler

LOG_DIR = log_dir()
DEFAULT_PROFILE = resource_root() / "profiles" / "default.json"


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


def check_pydivert() -> tuple[bool, str | None]:
    return configure_pydivert()


def _target_domains(options) -> tuple[str, ...]:
    target_domains = options.get("target_domains", [])
    if not isinstance(target_domains, list) or any(
        not isinstance(domain, str) for domain in target_domains
    ):
        raise ValueError("target_domains must be a list of hostnames")
    return tuple(domain.lower() for domain in target_domains)


def build_strategy(profile):
    if profile.strategy == "auto":
        config = AutoConfig.from_options(profile.strategy_options)
        return SessionStrategy(config.host)
    if profile.strategy == "tls_client_hello_fragment":
        chunk_size = int(profile.strategy_options.get("first_chunk_size", 32))
        split_mode = str(profile.strategy_options.get("split_mode", "sni"))
        reverse_order = profile.strategy_options.get("reverse_order", False)
        drop_suspect_rst = profile.strategy_options.get("drop_suspect_rst", False)
        if not isinstance(reverse_order, bool):
            raise ValueError("reverse_order must be a boolean")
        if not isinstance(drop_suspect_rst, bool):
            raise ValueError("drop_suspect_rst must be a boolean")
        return TLSClientHelloFragmentStrategy(
            FragmentConfig(
                first_chunk_size=chunk_size,
                split_mode=split_mode,
                reverse_order=reverse_order,
                target_domains=_target_domains(profile.strategy_options),
                drop_suspect_rst=drop_suspect_rst,
            )
        )

    if profile.strategy == "zapret_compat":
        return ZapretCompatStrategy(
            ZapretCompatConfig(
                mode=str(profile.strategy_options.get("mode", "multisplit")),
                split_pos=int(profile.strategy_options.get("split_pos", 2)),
                fake_ttl=int(profile.strategy_options.get("fake_ttl", 1)),
                target_domains=_target_domains(profile.strategy_options),
            )
        )

    raise ValueError(f"Unknown strategy: {profile.strategy}")


def _seed_discord_ips(session, logger):
    record = getattr(session, "record_dns_answer", None)
    domains = getattr(session, "active_domains", ())
    if not callable(record):
        return
    total = 0
    for host in domains:
        try:
            addresses = resolve_system(host, 4)
        except OSError:
            continue
        if addresses:
            record(host, addresses)
            total += len(addresses)
    logger.info("DNS policy seed: %s Discord address(es) recorded for session protection.", total)


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

    pydivert_ok, pydivert_error = check_pydivert()
    if not pydivert_ok:
        logger.error("%s", pydivert_error or "PyDivert is unavailable.")
        if not getattr(sys, "frozen", False):
            logger.info("Run: pip install -r requirements.txt")
        return 1

    try:
        profile = load_profile(DEFAULT_PROFILE)
        strategy = build_strategy(profile)
        dns_policy_config = DNSPolicyConfig.from_options(profile.dns_policy)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        logger.error("Could not load default profile or strategy: %s", exc)
        return 1

    logger.info("DPIveil started.")
    logger.info("Profile: %s", profile.name)
    logger.info("Filter: %s", profile.filter)
    logger.info("Strategy: %s", strategy.name)
    logger.info("Press Ctrl+C to stop.")

    dns_policy = WindowsDNSPolicy(dns_policy_config, logger) if dns_policy_config.enabled else None
    unregister_close_handler = lambda: None
    if dns_policy is not None:
        try:
            dns_policy.start()
            unregister_close_handler = register_console_close_handler(
                lambda _event: dns_policy.stop()
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            logger.error("Windows DNS policy startup failed: %s", exc)
            return 1

    try:
        if profile.strategy == "auto":
            _seed_discord_ips(strategy, logger)
            return run_auto(profile, strategy, logger)
        return run_manual(profile, strategy, logger)
    finally:
        try:
            if dns_policy is not None:
                dns_policy.stop()
        finally:
            unregister_close_handler()


def run_manual(profile, strategy, logger) -> int:
    engine = PacketEngine(profile.filter, logger, strategy)

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
            "Final stats: %s packets | %s bytes | %s TLS splits | %s UDP fragments | %s inbound RST | %s dropped RST | %s send errors",
            f"{engine.stats.packets:,}",
            f"{engine.stats.bytes:,}",
            engine.stats.fragmented_client_hellos,
            engine.stats.fragmented_udp_packets,
            engine.stats.inbound_resets,
            engine.stats.suspect_resets_dropped,
            engine.stats.send_errors,
        )
        logger.info("DPIveil stopped cleanly.")

    return 0


def run_auto(profile, session, logger) -> int:
    config = AutoConfig.from_options(profile.strategy_options)
    engine = PacketEngine(profile.filter, logger, session)
    errors = []

    def worker():
        try:
            engine.run()
        except Exception as exc:
            errors.append(exc)
            engine.ready.set()

    thread = threading.Thread(target=worker, name="dpiveil-divert", daemon=True)
    thread.start()
    try:
        if not engine.ready.wait(timeout=5) or errors or not thread.is_alive():
            logger.error("Could not start WinDivert engine: %s", errors or "engine not ready")
            return 1

        # Check the normal, system-resolved HTTPS path first.  A valid TLS
        # response means packet manipulation is unnecessary for this session.
        try:
            system_addresses = resolve_system(config.host, config.max_ips)
        except OSError as exc:
            system_addresses = []
            logger.info("System DNS probe unavailable: %s", exc)
        if system_addresses and direct_works(config, system_addresses, logger):
            logger.info("Direct verified HTTPS works; no DPI strategy selected.")
            while thread.is_alive():
                thread.join(timeout=0.5)
            if errors:
                logger.error("WinDivert engine stopped: %s", errors[0])
                return 1
            logger.error("WinDivert engine stopped unexpectedly.")
            return 1

        addresses = resolve_verified(config.host, config.timeout, config.max_ips)
        session.record_dns_answer(config.host, addresses)
        logger.info("Verified target addresses | %s | %s", config.host, ", ".join(addresses))
        selected, _ = test_candidates(config, session, logger, addresses)
        if selected is None:
            return 2
        logger.info("Active strategy for this session: %s", selected.name)

        desktop_details = diagnose_desktop_endpoints(config, logger)
        if desktop_details:
            logger.info(
                "Desktop Discord diagnostics: %s",
                ", ".join(f"{name}={'OK' if ok else 'FAIL'}" for name, ok in desktop_details.items()),
            )

        while thread.is_alive():
            thread.join(timeout=0.5)
        if errors:
            logger.error("WinDivert engine stopped: %s", errors[0])
            return 1
        logger.error("WinDivert engine stopped unexpectedly.")
        return 1
    except KeyboardInterrupt:
        logger.info("Stopping DPIveil...")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("Auto selection failed: %s", exc)
        return 1
    finally:
        engine.stop()
        thread.join(timeout=5)
        logger.info(
            "Final stats: %s packets | %s bytes | %s TLS splits | %s UDP fragments | %s send errors",
            f"{engine.stats.packets:,}",
            f"{engine.stats.bytes:,}",
            engine.stats.fragmented_client_hellos,
            engine.stats.fragmented_udp_packets,
            engine.stats.send_errors,
        )


if __name__ == "__main__":
    sys.exit(run())
